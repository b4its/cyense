"""Route & endpoint discovery — comprehensive routing enumeration.

Adaptation of Kiterunner / js-link-finder / gau concepts: enumerate the
entire route surface of a website from multiple read-only sources:

  * ``/robots.txt`` — Disallow/Allow entries (often hidden admin paths)
  * ``/sitemap.xml`` (+ ``.gz`` variant) — <loc> URLs
  * ``/openapi.json``, ``/swagger.json``, ``/api-docs`` — API path specs
  * crawled HTML links (supplied by the caller)
  * JavaScript API-call paths (extract_js_urls)
  * Wayback Machine corpus (optional, supplied by the caller)

Routes are deduplicated, normalized, and classified (api vs page vs
sensitive) so the scanner can report the full attack surface.
"""

from __future__ import annotations

import gzip
import re
from typing import Any
from urllib.parse import urljoin, urlparse

# robots.txt directive lines.
_ROBOTS_LINE_RE = re.compile(r"^\s*(?:Disallow|Allow)\s*:\s*(\S+)", re.I | re.M)

# sitemap <loc> entries.
_SITEMAP_LOC_RE = re.compile(r"<loc>\s*([^<]+)\s*</loc>", re.I)

# Sitemap entry points to probe.
_SITEMAP_PATHS = ["/sitemap.xml", "/sitemap.xml.gz"]

# OpenAPI spec entry points to probe.
_OPENAPI_PATHS = [
    "/openapi.json", "/openapi.yaml", "/swagger.json", "/swagger.yaml",
    "/api/openapi.json", "/v1/openapi.json", "/api-docs", "/api/docs",
    "/swagger-ui.html", "/docs", "/redoc",
]

# Sensitive-looking route prefixes (elevate classification).
_SENSITIVE_PREFIXES = (
    "admin", "internal", "private", "secret", "debug", "backup",
    "config", "manage", "panel", "console", "graphql", "actuator",
)

# API-looking route patterns.
_API_PATTERNS = (
    r"^/api", r"^/v\d", r"^/rest", r"^/graphql", r"/api/",
)


def parse_robots_paths(body: str) -> list[str]:
    """Extract Disallow/Allow paths from a robots.txt body.

    Pure wildcard patterns (``*``, ``/*.pdf$``) are skipped — they are
    patterns, not routes.
    """
    if not body:
        return []
    paths: list[str] = []
    for m in _ROBOTS_LINE_RE.finditer(body):
        path = m.group(1).strip()
        if not path or path == "/":
            continue
        if "*" in path:
            continue  # wildcard pattern, not a concrete route
        # RFC: "admin" means "/admin"
        if not path.startswith("/"):
            path = "/" + path
        paths.append(path)
    return paths


def parse_sitemap_urls(body: str) -> list[str]:
    """Extract <loc> URLs from a sitemap XML body."""
    if not body:
        return []
    urls: list[str] = []
    for m in _SITEMAP_LOC_RE.finditer(body):
        url = m.group(1).strip()
        if url:
            urls.append(url)
    return urls


def extract_paths_from_urls(urls: list[str], base_domain: str | None = None) -> list[str]:
    """Normalize a list of URLs into unique path strings (same domain only)."""
    paths: list[str] = []
    for url in urls:
        try:
            parsed = urlparse(url if "://" in url else f"http://{url}")
        except ValueError:
            continue
        if base_domain and parsed.hostname and (
            parsed.hostname != base_domain
            and not parsed.hostname.endswith("." + base_domain)
        ):
            continue  # off-domain
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"
        paths.append(path)
    return list(dict.fromkeys(paths))


def classify_route(path: str) -> str:
    """Classify a route: 'sensitive', 'api', or 'page'."""
    lowered = path.lower()
    if any(prefix in lowered for prefix in _SENSITIVE_PREFIXES):
        return "sensitive"
    for pattern in _API_PATTERNS:
        if re.match(pattern, lowered):
            return "api"
    return "page"


async def discover_routes(
    base_url: str,
    get_body,
    *,
    extra_paths: list[str] | None = None,
) -> dict[str, Any]:
    """Enumerate routes from robots.txt, sitemap, and OpenAPI specs.

    ``get_body`` is an async callable ``(url) -> (status, body)``. Returns:
      {routes: [{path, source, classification}], sources: {...}}
    """
    routes: dict[str, dict[str, str]] = {}

    def add(path: str, source: str, classification: str | None = None) -> None:
        path = path.strip()
        if not path or path == "/":
            return
        # Normalize to an absolute path form (robots "admin" → "/admin").
        if not path.startswith(("/", "http://", "https://")):
            path = "/" + path
        if path in routes:
            return
        routes[path] = {
            "path": path,
            "source": source,
            "classification": classification or classify_route(path),
        }

    for extra in extra_paths or []:
        add(extra, "crawl")

    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    # 1. robots.txt
    try:
        status, body = await get_body(urljoin(origin + "/", "robots.txt"))
        if 200 <= status < 300:
            for p in parse_robots_paths(body):
                add(p, "robots.txt")
    except Exception:  # noqa: BLE001
        pass

    # 2. sitemap.xml (+ gz)
    for sp in _SITEMAP_PATHS:
        try:
            status, body = await get_body(urljoin(origin + "/", sp.lstrip("/")))
            if not (200 <= status < 300):
                continue
            if sp.endswith(".gz"):
                try:
                    import httpx
                    parsed0 = urlparse(base_url)
                    gz_url = f"{parsed0.scheme}://{parsed0.netloc}{sp}"
                    async with httpx.AsyncClient(
                        timeout=8.0, follow_redirects=True,
                    ) as c:
                        raw = (await c.get(gz_url)).content
                    body = gzip.decompress(raw).decode("utf-8", errors="replace")
                except (OSError, ValueError, httpx.HTTPError, ImportError):
                    continue
            for url in parse_sitemap_urls(body):
                for p in extract_paths_from_urls([url], parsed.hostname):
                    add(p, sp)
        except Exception:  # noqa: BLE001
            continue

    # 3. OpenAPI specs — parse path keys from the spec
    for op in _OPENAPI_PATHS:
        try:
            status, body = await get_body(urljoin(origin + "/", op.lstrip("/")))
            if not (200 <= status < 300):
                continue
            for p in _paths_from_openapi(body, op):
                add(p, op)
        except Exception:  # noqa: BLE001
            continue

    route_list = list(routes.values())
    # Sort: sensitive first, then api, then page.
    order = {"sensitive": 0, "api": 1, "page": 2}
    route_list.sort(key=lambda r: (order.get(r["classification"], 9), r["path"]))
    return {
        "routes": route_list,
        "count": len(route_list),
    }


def _paths_from_openapi(body: str, source: str) -> list[str]:
    """Extract API path keys from an OpenAPI/Swagger JSON/YAML body."""
    import json

    import yaml

    try:
        spec = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        try:
            spec = yaml.safe_load(body)
        except Exception:  # noqa: BLE001
            return []
    if not isinstance(spec, dict):
        return []
    paths = spec.get("paths")
    if not isinstance(paths, dict):
        return []
    return list(paths.keys())
