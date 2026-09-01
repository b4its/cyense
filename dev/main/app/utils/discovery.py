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
