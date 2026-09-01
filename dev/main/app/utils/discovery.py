"""Content & passive discovery — adaptation of HackerOne 104 tools.

Implements the read-only core of several classic recon tools:
  * **Nikto / Dirsearch / Ffuf** — common sensitive file/path checks
  * **Jsluice / js-link-finder** — URL & path extraction from JavaScript
  * **Arjun** — hidden HTTP parameter discovery
  * **Virtual-host-discovery** — Host-header fuzzing for vhosts
  * **Waybackurls / gau** — passive URL discovery via Wayback Machine CDX

All checks are deterministic, rate-limited by the caller, and read-only.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin, urlparse

# (path, description, severity) — classic sensitive-file checks.
SENSITIVE_PATHS: list[tuple[str, str, str]] = [
    ("/.git/config", "Git repository config ter-expose (bocor remote URL).", "high"),
    ("/.git/HEAD", "Direktori .git dapat diakses.", "critical"),
    ("/.env", "File .env ter-expose (kredensial aplikasi).", "critical"),
    ("/env", "File env ter-expose.", "high"),
    ("/.htaccess", "File .htaccess dapat diakses.", "medium"),
    ("/.htpasswd", "File .htpasswd dapat diakses.", "critical"),
    ("/backup.zip", "File backup.zip dapat diunduh.", "high"),
    ("/backup.tar.gz", "File backup.tar.gz dapat diunduh.", "high"),
    ("/www.zip", "Arsip source code www.zip ter-expose.", "critical"),
    ("/config.php.bak", "Backup config.php ter-expose.", "critical"),
    ("/wp-config.php.bak", "Backup wp-config.php ter-expose.", "critical"),
    ("/phpinfo.php", "phpinfo() ter-expose (bocor konfigurasi).", "medium"),
    ("/server-status", "Apache server-status ter-expose.", "medium"),
    ("/server-info", "Apache server-info ter-expose.", "medium"),
    ("/.DS_Store", "File .DS_Store ter-expose (struktur direktori).", "low"),
    ("/web.config", "File web.config ter-expose.", "medium"),
    ("/crossdomain.xml", "crossdomain.xml permisif.", "low"),
    ("/trace.axd", "ASP.NET trace.axd ter-expose.", "medium"),
    ("/elmah.axd", "ELMAH error log ter-expose.", "high"),
    ("/actuator/env", "Spring Boot actuator /env ter-expose.", "critical"),
    ("/actuator/health", "Spring Boot actuator ter-expose.", "medium"),
    ("/actuator", "Spring Boot actuator endpoints ter-expose.", "high"),
    ("/graphql", "Endpoint GraphQL ter-expose (cek introspeksi).", "medium"),
    ("/swagger-ui.html", "Swagger UI ter-expose.", "low"),
    ("/api/docs", "Dokumentasi API ter-expose.", "low"),
    ("/debug", "Endpoint debug ter-expose.", "medium"),
    ("/console", "Konsol debug (Werkzeug dll) ter-expose.", "high"),
    ("/wp-login.php", "WordPress login ter-expose.", "info"),
    ("/xmlrpc.php", "WordPress XML-RPC aktif (brute force/SSRF).", "medium"),
    ("/wp-json/wp/v2/users", "WordPress REST user enumeration.", "medium"),
]

# Common parameter names for hidden-param discovery (Arjun-style).
COMMON_PARAM_NAMES: list[str] = [
    "id", "page", "search", "q", "query", "user", "username", "admin",
    "debug", "file", "path", "url", "redirect", "next", "callback",
    "jsonp", "token", "key", "lang", "locale", "theme", "action",
    "cmd", "exec", "view", "show", "format", "type", "sort", "order",
]

# Common virtual-host names (virtual-host-discovery).
COMMON_VHOSTS: list[str] = [
    "admin", "api", "app", "blog", "cdn", "dev", "docs", "git", "mail",
    "old", "portal", "stage", "staging", "static", "test", "www",
]

# JS URL-ish patterns (Jsluice/js-link-finder adaptation).
_JS_URL_RE = re.compile(
    r"[\"']((?:https?://|/)[^\"'\s]{2,200})[\"']", re.I
)
_JS_API_PATH_RE = re.compile(
    r"(?:fetch|axios|get|post|put|delete)\s*\(\s*['\"]([^'\"]+)['\"]", re.I
)


def extract_js_urls(content: str) -> list[str]:
    """Extract URLs/paths from JavaScript source (Jsluice-style).

    Combines absolute URLs and API-call string literals; deduped.
    """
    if not content:
        return []
    found: list[str] = []
    for m in _JS_URL_RE.finditer(content):
        found.append(m.group(1))
    for m in _JS_API_PATH_RE.finditer(content):
        found.append(m.group(1))
    return list(dict.fromkeys(found))


def wayback_cdx_url(domain: str) -> str:
    """Build the Wayback Machine CDX API URL for a domain (waybackurls)."""
    return (
        f"https://web.archive.org/cdx/search/cdx"
        f"?url={domain}/*&output=json&fl=original&collapse=urlkey"
        f"&limit=200&filter=statuscode:200"
    )


async def fetch_wayback_urls(domain: str, timeout: float = 10.0) -> list[str]:
    """Fetch known URLs for a domain from the Wayback Machine (graceful)."""
    import httpx

    url = wayback_cdx_url(domain)
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as c:
            resp = await c.get(url)
            resp.raise_for_status()
            data = resp.json()
    except (httpx.HTTPError, ValueError):
        return []
    # data: [[headers], [row], ...] — first row is the header.
    out: list[str] = []
    for row in data[1:]:
        if row and isinstance(row, list) and row[0]:
            out.append(str(row[0]))
    return out


async def check_sensitive_paths(
    base_url: str,
    get_body,
    paths: list[tuple[str, str, str]] | None = None,
) -> list[dict[str, Any]]:
    """Probe common sensitive paths; report those that return 2xx.

    ``get_body`` is an async callable ``(url) -> (status, body)`` so the
    caller can reuse its rate-limited HTTP client.
    """
    findings: list[dict[str, Any]] = []
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    for path, description, severity in (paths or SENSITIVE_PATHS):
        url = urljoin(origin + "/", path.lstrip("/"))
        try:
            status, body = await get_body(url)
        except Exception:  # noqa: BLE001 — best-effort per path
            continue
        if 200 <= status < 300:
            snippet = (body or "")[:160]
            findings.append({
                "path": path,
                "status": status,
                "description": description,
                "severity": severity,
                "snippet": snippet,
                "url": url,
            })
    return findings


async def discover_hidden_params(
    page_url: str,
    get_body,
    params: list[str] | None = None,
) -> list[str]:
    """Arjun-style: append common params and detect response changes.

    Returns param names whose presence changes the response (size diff).
    """
    import urllib.parse as up

    found: list[str] = []
    parsed = urlparse(page_url)
    base_qs = up.parse_qs(parsed.query)
    try:
        _, base_body = await get_body(page_url)
    except Exception:  # noqa: BLE001
        return []
    base_len = len(base_body or "")

    for param in (params or COMMON_PARAM_NAMES):
        qs = dict(base_qs)
        qs[param] = ["1"]
        probe_url = parsed._replace(query=up.urlencode(qs, doseq=True)).geturl()
        try:
            status, body = await get_body(probe_url)
        except Exception:  # noqa: BLE001
            continue
        if 200 <= status < 300 and abs(len(body or "") - base_len) > 50:
            found.append(param)
    return found


async def discover_vhosts(
    host: str,
    base_url: str,
    get_body,
    vhosts: list[str] | None = None,
) -> list[str]:
    """Virtual-host-discovery: probe common vhost names via Host header."""
    found: list[str] = []
    parsed = urlparse(base_url)
    port_part = f":{parsed.port}" if parsed.port else ""
    try:
        _, base_body = await get_body(base_url)
    except Exception:  # noqa: BLE001
        return []
    base_len = len(base_body or "")

    for vhost in (vhosts or COMMON_VHOSTS):
        candidate = f"{vhost}.{host}"
        # Use a URL whose host we override via get_body? Caller must support
        # custom headers; we signal vhost via the URL scheme.
        try:
            status, body = await get_body(
                base_url, extra_headers={"Host": f"{candidate}{port_part}"}
            )
        except TypeError:
            return []  # caller does not support headers — skip
        except Exception:  # noqa: BLE001
            continue
        if 200 <= status < 300 and abs(len(body or "") - base_len) > 100:
            found.append(candidate)
    return found


# ---------------------------------------------------------------------------
# Extended tool adaptations (full HackerOne 104 coverage)
# ---------------------------------------------------------------------------

# Subdomain prefixes (Subfinder/Shuffledns/Dnscan-style active enumeration).
COMMON_SUBDOMAINS: list[str] = [
    "www", "api", "admin", "dev", "staging", "stage", "test", "mail",
    "blog", "docs", "app", "web", "portal", "git", "ci", "cdn", "static",
    "assets", "status", "help", "support", "shop", "store", "auth",
    "login", "vpn", "old", "new", "beta", "demo", "uat", "qa",
]

# API endpoint candidates (Kiterunner-style route discovery).
API_PATHS: list[str] = [
    "/api", "/api/v1", "/api/v2", "/api/v3", "/v1", "/v2", "/v3",
    "/health", "/healthz", "/status", "/version", "/metrics", "/ping",
    "/info", "/debug", "/internal", "/private", "/graphql", "/rest",
    "/rest/v1", "/oauth", "/oauth/token", "/swagger", "/openapi.json",
    "/docs", "/redoc", "/actuator", "/actuator/health",
]

# Admin panel / management interfaces (Nuclei-style exposure checks).
ADMIN_PATHS: list[tuple[str, str, str]] = [
    ("/admin", "Admin panel ter-expose.", "high"),
    ("/administrator", "Admin panel (Joomla-style) ter-expose.", "high"),
    ("/manage", "Management interface ter-expose.", "high"),
    ("/cpanel", "cPanel login ter-expose.", "medium"),
    ("/webmail", "Webmail ter-expose.", "medium"),
    ("/phpmyadmin", "phpMyAdmin ter-expose.", "critical"),
    ("/jenkins", "Jenkins ter-expose.", "critical"),
    ("/jenkins/script", "Jenkins script console ter-expose.", "critical"),
    ("/grafana", "Grafana ter-expose.", "high"),
    ("/kibana", "Kibana ter-expose.", "high"),
    ("/solr", "Apache Solr ter-expose.", "critical"),
    ("/_cat/indices", "Elasticsearch indices ter-expose.", "critical"),
    ("/actuator/env", "Spring Boot env ter-expose.", "critical"),
]

# WordPress-specific checks (Wpscan-style).
WP_PATHS: list[tuple[str, str, str]] = [
    ("/wp-json/wp/v2/users", "WordPress user enumeration via REST.", "medium"),
    ("/wp-json", "WordPress REST API ter-expose.", "low"),
    ("/readme.html", "WordPress readme.html membocorkan versi.", "low"),
    ("/wp-content/plugins", "Daftar plugin WordPress ter-expose.", "medium"),
    ("/wp-content/uploads", "Direktori upload ter-list.", "low"),
]

# Parameters likely used as SSRF sinks (SSRFTest-style passive detection).
SSRF_PARAM_NAMES: list[str] = [
    "url", "uri", "link", "redirect", "redirect_uri", "callback",
    "target", "host", "domain", "proxy", "next", "dest", "destination",
    "image", "img", "avatar", "file", "path", "fetch", "load", "remote",
    "webhook", "endpoint", "source", "origin", "ref",
]

# Common directories (Ffuf/Wfuzz/Dirsearch-style wordlist fuzzing).
COMMON_DIR_PATHS: list[str] = [
    "/login", "/admin", "/uploads", "/upload", "/images", "/img",
    "/assets", "/static", "/js", "/css", "/fonts", "/download",
    "/downloads", "/files", "/media", "/content", "/data", "/backup",
    "/backups", "/config", "/conf", "/database", "/db", "/dump",
    "/logs", "/log", "/temp", "/tmp", "/cache", "/old", "/new",
    "/test", "/tests", "/dev", "/development", "/staging", "/vendor",
    "/node_modules", "/.git", "/.svn", "/.hg",
]

# GraphQL introspection query (Altair-style, read-only POST).
GRAPHQL_INTROSPECTION_QUERY = (
    "{\"query\": \"query { __schema { queryType { name } } }\"}"
)
GRAPHQL_INTROSPECTION_HEADERS = {"Content-Type": "application/json"}


def extract_subdomains_from_urls(urls: list[str], base_domain: str) -> list[str]:
    """Extract subdomains belonging to base_domain from a list of URLs
    (passive subdomain discovery, Subfinder-style)."""
    subdomains: set[str] = set()
    for url in urls:
        try:
            host = urlparse(url if "://" in url else f"http://{url}").hostname or ""
        except ValueError:
            continue
        if host.endswith("." + base_domain) and host != base_domain:
            subdomains.add(host)
    return sorted(subdomains)


async def discover_subdomains(domain: str, prefixes: list[str] | None = None) -> list[str]:
    """Active DNS enumeration of common subdomain prefixes.

    Uses getaddrinfo (non-intrusive, no zone transfer). Returns resolvable
    subdomains. Best-effort — DNS failures yield fewer results, never raise.
    """
    import asyncio

    found: list[str] = []

    async def _resolve(sub: str) -> str | None:
        try:
            await asyncio.get_event_loop().getaddrinfo(sub, None)
            return sub
        except OSError:
            return None

    results = await asyncio.gather(
        *(_resolve(f"{p}.{domain}") for p in (prefixes or COMMON_SUBDOMAINS)),
        return_exceptions=True,
    )
    for r in results:
        if isinstance(r, str):
            found.append(r)
    return sorted(found)


async def check_api_endpoints(
    base_url: str, get_body, paths: list[str] | None = None,
) -> list[str]:
    """Probe common API paths (Kiterunner-style); return those that answer
    with a non-404 status."""
    found: list[str] = []
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    for path in (paths or API_PATHS):
        url = urljoin(origin + "/", path.lstrip("/"))
        try:
            status, _ = await get_body(url)
        except Exception:  # noqa: BLE001
            continue
        if status not in (404, 0):
            found.append(path)
    return found


def detect_ssrf_params(page_url: str, body: str | None = None) -> list[str]:
    """Passive SSRF-sink detection: query/body params with sink-like names."""
    import urllib.parse as up

    found: set[str] = set()
    parsed = urlparse(page_url)
    for key in up.parse_qs(parsed.query).keys():
        if key.lower() in SSRF_PARAM_NAMES:
            found.add(key)
    # Form field names in the body
    if body:
        for m in re.finditer(r'name=["\']([^"\']+)["\']', body, re.I):
            if m.group(1).lower() in SSRF_PARAM_NAMES:
                found.add(m.group(1))
    return sorted(found)


async def check_graphql_introspection(base_url: str) -> bool:
    """POST a GraphQL introspection query; return True if introspection
    is enabled (schema returned). Read-only — no mutation."""
    import httpx

    url = urljoin(base_url.rstrip("/") + "/", "graphql")
    try:
        async with httpx.AsyncClient(timeout=8.0, follow_redirects=True) as c:
            resp = await c.post(
                url,
                content=GRAPHQL_INTROSPECTION_QUERY,
                headers=GRAPHQL_INTROSPECTION_HEADERS,
            )
            if resp.status_code != 200:
                return False
            data = resp.json()
    except (httpx.HTTPError, ValueError):
        return False
    return isinstance(data, dict) and "__schema" in data.get("data", {})
