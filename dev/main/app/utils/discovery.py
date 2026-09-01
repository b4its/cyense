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


# ---------------------------------------------------------------------------
# Harvester — passive OSINT gathering from public sources
# ---------------------------------------------------------------------------

_HARVEST_EMAIL_RE = re.compile(
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"
)
_IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)


async def harvest_subdomains_crtsh(
    domain: str, timeout: float = 15.0,
) -> list[str]:
    """Query crt.sh for subdomains belonging to *domain* (Harvester-style).

    Returns unique subdomain list. Best-effort — any failure yields fewer
    results, never raises.
    """
    import httpx

    try:
        async with httpx.AsyncClient(timeout=timeout) as c:
            resp = await c.get(
                "https://crt.sh/",
                params={"q": f"%25.{domain}", "output": "json"},
            )
            resp.raise_for_status()
            data = resp.json()
    except (httpx.HTTPError, ValueError):
        return []
    subs: set[str] = set()
    for entry in data:
        name = entry.get("name_value", "")
        for line in name.split("\n"):
            line = line.strip().lower().lstrip(".")
            if line.endswith("." + domain) and line != domain:
                subs.add(line)
    return sorted(subs)


async def harvest_subdomains_wayback(
    domain: str, timeout: float = 15.0,
) -> list[str]:
    """Parse Wayback Machine CDX for subdomains (Harvester-style)."""
    import httpx

    try:
        async with httpx.AsyncClient(timeout=timeout) as c:
            resp = await c.get(
                "https://web.archive.org/cdx/search/cdx",
                params={
                    "url": f"*.{domain}/*",
                    "output": "json",
                    "fl": "original",
                    "collapse": "urlkey",
                    "limit": 500,
                },
            )
            resp.raise_for_status()
            data = resp.json()
    except (httpx.HTTPError, ValueError):
        return []
    subs: set[str] = set()
    for row in data[1:]:
        if row and isinstance(row, list) and row[0]:
            try:
                host = urlparse(row[0]).hostname or ""
            except ValueError:
                continue
            if host.endswith("." + domain) and host != domain:
                subs.add(host)
    return sorted(subs)


def harvest_emails(body: str) -> list[str]:
    """Extract email addresses from content (Harvester-style)."""
    if not body:
        return []
    return list(dict.fromkeys(_HARVEST_EMAIL_RE.findall(body)))


def harvest_ips(body: str) -> list[str]:
    """Extract IP addresses from content (Harvester-style)."""
    if not body:
        return []
    return list(dict.fromkeys(_IP_RE.findall(body)))


def harvest_tech_from_headers(headers: dict[str, str]) -> list[dict[str, Any]]:
    """Extract technology fingerprints from response headers
    (Harvester-style)."""
    results: list[dict[str, Any]] = []
    header_map = {k.lower(): v for k, v in headers.items()}

    _HEADER_SPECS: list[tuple[str, str, str, str, float, str | None]] = [
        ("SERVER-NGINX",  "server", r"^nginx(?:/([\d\.]+))?",
         "server:nginx", 0.95, r"nginx/([\d\.]+)"),
        ("SERVER-APACHE", "server", r"^Apache(?:/([\d\.\-_ ]+))?",
         "server:apache", 0.95, r"Apache/([\d\.]+)"),
        ("STACK-EXPRESS", "x-powered-by", r"^Express$",
         "stack:express", 0.9, None),
        ("STACK-DJANGO",  "x-powered-by", r"^Django$",
         "stack:django", 0.9, None),
        ("STACK-FLASK",   "x-powered-by", r"^Flask$",
         "stack:flask", 0.9, None),
        ("STACK-RUBY",    "x-powered-by", r"^Ruby$",
         "stack:ruby", 0.85, None),
        ("SERVER-IIS",    "server", r"^Microsoft-IIS",
         "server:iis", 0.95, None),
        ("SERVER-TOMCAT", "server", r"^Apache/Tomcat",
         "server:tomcat", 0.9, None),
        ("SERVER-OPENBSD","server", r"^OpenBSD",
         "server:openbsd", 0.9, None),
    ]
    for rule_id, hdr, pattern, category, confidence, ver_re in _HEADER_SPECS:
        val = header_map.get(hdr, "")
        m = re.match(pattern, val, re.I)
        if m:
            version = None
            if ver_re:
                vm = re.search(ver_re, val)
                if vm:
                    version = vm.group(1)
            results.append({
                "rule": rule_id,
                "category": category,
                "value": val,
                "version": version,
                "confidence": confidence,
            })
    return results


def harvest_tech_fingerprints(body: str) -> list[dict[str, Any]]:
    """Extract technology fingerprints from HTML body (Harvester-style)."""
    results: list[dict[str, Any]] = []
    if not body:
        return results

    # Meta generator tag.
    gen_m = re.search(
        r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']([^\"']+)[\"']",
        body, re.I,
    )
    if gen_m:
        results.append({
            "rule": "TECH-META-GENERATOR",
            "category": "stack",
            "value": gen_m.group(1).strip(),
            "confidence": 0.85,
        })

    # X-Powered-By meta.
    xp_m = re.search(
        r"<meta[^>]+http-equiv=[\"']X-Powered-By[\"'][^>]+content=[\"']([^\"']+)[\"']",
        body, re.I,
    )
    if xp_m:
        results.append({
            "rule": "TECH-X-POWERED-BY",
            "category": "stack",
            "value": xp_m.group(1).strip(),
            "confidence": 0.8,
        })

    # JavaScript library markers.
    _JS_LIB_PATTERNS: list[tuple[str, str, str]] = [
        (r"jquery[\.\-]?\d", "stack:jquery", 0.9),
        (r"prototype[^\"']*\d", "stack:prototype", 0.85),
        (r"dojo[^\"']*\d", "stack:dojo", 0.85),
        (r"yui[^\"']*\d", "stack:yui", 0.85),
        (r"modernizr[^\"']*\d", "stack:modernizr", 0.8),
        (r"bootstrap[^\"']*\d", "stack:bootstrap", 0.85),
        (r"react[^\"']*\d", "stack:react", 0.8),
        (r"angular[^\"']*\d", "stack:angular", 0.8),
        (r"vue[^\"']*\d", "stack:vue", 0.8),
        (r"backbone[^\"']*\d", "stack:backbone", 0.8),
        (r"underscore[^\"']*\d", "stack:underscore", 0.8),
        (r"sizzle[^\"']*\d", "stack:sizzle", 0.8),
        (r"moment[^\"']*\d", "stack:moment", 0.8),
        (r"lodash[^\"']*\d", "stack:lodash", 0.8),
    ]
    for pattern, rule_id, confidence in _JS_LIB_PATTERNS:
        if re.search(pattern, body, re.I):
            results.append({
                "rule": rule_id,
                "category": "stack",
                "value": rule_id.split(":")[1],
                "confidence": confidence,
            })

    # Framework-specific HTML patterns.
    _FRAMEWORK_PATTERNS: list[tuple[str, str, str]] = [
        (r"<link[^>]+csrf[^>]+>", "stack:django-csrf", 0.9),
        (r"__VIEWSTATE", "stack:aspnet", 0.9),
        (r"__RequestVerificationToken", "stack:aspnet", 0.9),
        (r"<input[^>]+_token[^>]+>", "stack:laravel", 0.85),
        (r"<meta[^>]+csrf-token", "stack:laravel", 0.85),
        (r"<!-- wp-", "stack:wordpress", 0.9),
        (r"wp-content", "stack:wordpress", 0.85),
        (r"/wp-json/", "stack:wordpress", 0.85),
    ]
    for pattern, rule_id, confidence in _FRAMEWORK_PATTERNS:
        if re.search(pattern, body, re.I):
            results.append({
                "rule": rule_id,
                "category": "stack",
                "value": rule_id.split(":")[1],
                "confidence": confidence,
            })

    # Form action patterns hinting at backend.
    if re.search(r"action=[\"']/api/", body, re.I):
        results.append({
            "rule": "TECH-API-FORM",
            "category": "api",
            "value": "API form endpoint",
            "confidence": 0.6,
        })

    return results


# ---------------------------------------------------------------------------
# Nikto — comprehensive web server security checks
# ---------------------------------------------------------------------------

_DANGEROUS_HEADERS = frozenset([
    "x-powered-by", "x-aspnet-version", "x-aspnet-queue",
    "x-aspNet-Version", "x-generated-by", "x-backend",
    "x-runtime", "x-request-id", "x-debug-token",
])

_MISSING_SECURITY_HEADERS = [
    ("strict-transport-security", "Strict-Transport-Security", "HSTS"),
    ("x-content-type-options", "X-Content-Type-Options", "X-Content-Type-Options"),
    ("x-frame-options", "X-Frame-Options", "X-Frame-Options"),
    ("content-security-policy", "Content-Security-Policy", "CSP"),
    ("referrer-policy", "Referrer-Policy", "Referrer-Policy"),
    ("permissions-policy", "Permissions-Policy", "Permissions-Policy"),
]


def nikto_check_server_headers(
    headers: dict[str, str],
) -> list[dict[str, Any]]:
    """Check server response headers for dangerous/missing headers
    (Nikto-style)."""
    findings: list[dict[str, Any]] = []
    header_map = {k.lower(): v for k, v in headers.items()}

    # Check for dangerous server-information headers.
    for hdr in _DANGEROUS_HEADERS:
        if hdr in header_map and header_map[hdr]:
            findings.append({
                "rule": "NIKTO-DANGEROUS-HEADER",
                "severity": "low",
                "confidence": 0.9,
                "cwe": "CWE-200",
                "title": f"Header informasi server ter-expose: {hdr}",
                "description": (
                    f"Header {hdr!r} mengungkapkan informasi server: "
                    f"{header_map[hdr][:80]}"
                ),
                "evidence": {"header": hdr, "value": header_map[hdr]},
                "remediation": (
                    "Hapus atau sembunyikan header server-information "
                    "dari respons HTTP."
                ),
                "location": "server-headers",
            })

    # Check for missing security headers.
    for param, hdr, label in _MISSING_SECURITY_HEADERS:
        if param not in header_map or not header_map.get(param):
            findings.append({
                "rule": "NIKTO-MISSING-HEADER",
                "severity": "medium",
                "confidence": 0.85,
                "cwe": "CWE-693",
                "title": f"Header keamanan hilang: {label}",
                "description": (
                    f"Header {hdr!r} tidak ada di respons HTTP — "
                    f"memungkinkan serangan seperti clickjacking, "
                    f"MIME-sniffing, dan CSP bypass."
                ),
                "evidence": {"missing_header": hdr, "location": "server-headers"},
                "remediation": (
                    f"Tambahkan header {hdr!r} ke konfigurasi web server."
                ),
                "location": "server-headers",
            })

    # Check for overly verbose Server header.
    server_val = header_map.get("server", "")
    if server_val and "/" in server_val:
        findings.append({
            "rule": "NIKTO-SERVER-HEADER",
            "severity": "low",
            "confidence": 0.95,
            "cwe": "CWE-200",
            "title": f"Server header mengungkap versi: {server_val}",
            "description": (
                f"Header Server mengungkapkan vendor dan versi: "
                f"{server_val} — attacker dapat menargetkan "
                f"kerentanan yang diketahui."
            ),
            "evidence": {"header": "Server", "value": server_val},
            "remediation": (
                "Sembunyikan atau ubah versi pada header Server; "
                "gunakan server header yang lebih ringkas."
            ),
            "location": "server-headers",
        })

    return findings


def _version_in_range(version: str, low: str, high: str) -> bool:
    """Check if *version* falls within [low, high] using tuple comparison."""
    def _parse(v: str) -> tuple:
        return tuple(int(p) for p in v.split(".")[:4])
    try:
        v = _parse(version)
        l = _parse(low)
        h = _parse(high)
        return l <= v <= h
    except (ValueError, IndexError):
        return True


def nikto_check_outdated_software(
    tech_findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Flag outdated software versions based on known vulnerable ranges
    (Nikto-style)."""
    findings: list[dict[str, Any]] = []

    _VULNERABLE_VERSIONS: dict[str, list[tuple[str, str]]] = {
        "nginx": [
            ("1.0", "1.14.0"), ("1.0", "1.13.2"),
        ],
        "apache": [
            ("2.2", "2.2.34"), ("2.4.0", "2.4.25"),
        ],
        "tomcat": [
            ("7.0", "7.0.93"), ("8.0", "8.5.61"),
            ("9.0", "9.0.27"),
        ],
        "iis": [
            ("6.0", "6.0"), ("7.0", "7.0"), ("7.5", "7.5"),
        ],
        "wordpress": [
            ("4.0", "5.2.4"), ("5.0", "5.2.4"),
        ],
        "php": [
            ("5.0", "5.6.40"), ("7.0", "7.0.33"),
            ("7.1", "7.1.33"), ("7.2", "7.2.34"),
        ],
    }

    for tech in tech_findings:
        value = tech.get("value", "")
        version = tech.get("version")
        if not version and not value:
            continue
        for product, ranges in _VULNERABLE_VERSIONS.items():
            if product.lower() in value.lower():
                for low, high in ranges:
                    if version and not _version_in_range(version, low, high):
                        continue
                    findings.append({
                        "rule": "NIKTO-OUTDATED-SOFTWARE",
                        "severity": "high",
                        "confidence": 0.7,
                        "cwe": "CWE-1104",
                        "title": (
                            f"Perangkat lunak usang terdeteksi: "
                            f"{value}"
                        ),
                        "description": (
                            f"{value} mungkin berada dalam rentang "
                            f"versi rentan ({low}–{high}). "
                            f"Perbarui ke versi terbaru."
                        ),
                        "evidence": {
                            "product": product,
                            "version": version,
                            "value": value,
                        },
                        "remediation": (
                            f"Update {product} ke versi terbaru "
                            f"(≥ {high})."
                        ),
                        "location": "technology-detection",
                    })
                break

    return findings


def nikto_check_sql_errors(body: str) -> list[dict[str, Any]]:
    """Detect SQL error messages leaked in response body (Nikto-style)."""
    if not body:
        return []

    _SQL_ERROR_PATTERNS: list[tuple[str, str]] = [
        (r"SQL syntax.*MySQL", "MySQL error"),
        (r"Warning.*mysql_", "MySQL warning"),
        (r"PG::Error|ERROR:.*syntax", "PostgreSQL error"),
        (r"ORA-[0-9]{5}", "Oracle error"),
        (r"SQLiteException|SQLite:", "SQLite error"),
        (r"Microsoft SQL Server|ODBC|SQL Server", "MSSQL error"),
        (r"DB2 SQL|SQL0[0-9]{4}", "DB2 error"),
        (r"\[Microsoft\]\[ODBC|\[Macromedia\]\[SQLServer\]", "ODBC error"),
        (r"Unclosed quotation mark|Convert failed", "SQL syntax error"),
        (r"quoted string not properly terminated", "SQL string error"),
        (r"mysql_fetch|mysql_num_rows", "MySQL function leak"),
        (r"pg_query|pg_fetch", "PostgreSQL function leak"),
        (r"mssql_query|mssql_fetch", "MSSQL function leak"),
        (r"ORA-[0-9]|oci_", "Oracle function leak"),
    ]

    findings: list[dict[str, Any]] = []
    seen = set()
    for pattern, label in _SQL_ERROR_PATTERNS:
        if re.search(pattern, body, re.I):
            if label in seen:
                continue
            seen.add(label)
            findings.append({
                "rule": "NIKTO-SQL-ERROR",
                "severity": "critical",
                "confidence": 0.9,
                "cwe": "CWE-89",
                "title": f"Kebocoran error SQL terdeteksi: {label}",
                "description": (
                    f"Respons mengandung pesan error {label}. "
                    f"Ini menunjukkan aplikasi mengekspos error "
                    f"database ke client."
                ),
                "evidence": {"error_type": label},
                "remediation": (
                    "Nonaktifkan display error di production; "
                    "gunakan custom error pages."
                ),
                "location": "response-body",
            })
    return findings


def nikto_check_directory_listing(body: str, url: str = "") -> list[dict[str, Any]]:
    """Detect directory listing exposure (Nikto-style)."""
    if not body:
        return []

    patterns = [
        r"(?i)<title>.*index of.*</title>",
        r"(?i)Directory listing for",
        r"(?i)<h1>.*Index of.*</h1>",
        r"(?i)Parent Directory",
        r"(?i)<a href=.*[\"']\.\.[\"']",
    ]
    for pattern in patterns:
        if re.search(pattern, body):
            return [{
                "rule": "NIKTO-DIR-LISTING",
                "severity": "high",
                "confidence": 0.95,
                "cwe": "CWE-548",
                "title": "Directory listing aktif",
                "description": (
                    "Server menampilkan daftar direktori — "
                    "file dan folder ter-expose ke publik."
                ),
                "evidence": {"url": url or "unknown"},
                "remediation": (
                    "Nonaktifkan directory listing di konfigurasi "
                    "web server (Options -Indexes)."
                ),
                "location": url or "response-body",
            }]
    return []


def nikto_check_info_disclosure(body: str) -> list[dict[str, Any]]:
    """Detect information disclosure patterns in response body (Nikto-style)."""
    if not body:
        return []

    _DISCLOSURE_PATTERNS: list[tuple[str, str, str]] = [
        (r"(?i)Warning:.*(mysql|mysqli|pg_|sqlite|oci)", "Database error leak"),
        (r"(?i)Fatal error:", "PHP fatal error"),
        (r"(?i)Parse error:", "PHP parse error"),
        (r"(?i)Call Stack:.*/var/www/", "PHP call stack leak"),
        (r"(?i)Exception trace.*#0 ", "Stack trace leak"),
        (r"(?i)<pre>.*\(.*\):\s*file\s", "File path disclosure"),
        (r"(?i)Environment.*\(\)", "Environment dump"),
        (r"(?i)\b(DB_|PASSWORD|SECRET|API_KEY)\s*=", "Credential in source"),
        (r"(?i)phpinfo\(\)", "phpinfo page detected"),
        (r"(?i)Server version|Server API", "Server info dump"),
    ]

    findings: list[dict[str, Any]] = []
    seen = set()
    for pattern, label in _DISCLOSURE_PATTERNS:
        if re.search(pattern, body) and label not in seen:
            seen.add(label)
            findings.append({
                "rule": "NIKTO-INFO-DISCLOSURE",
                "severity": "high",
                "confidence": 0.85,
                "cwe": "CWE-200",
                "title": f"Information disclosure: {label}",
                "description": (
                    f"Respons mengungkapkan informasi sensitif: {label}. "
                    f"Information disclosure membantu attacker "
                    f"memetakan target."
                ),
                "evidence": {"disclosure_type": label},
                "remediation": (
                    "Nonaktifkan debugging dan error display di "
                    "production environment."
                ),
                "location": "response-body",
            })
    return findings


# ---------------------------------------------------------------------------
# Nuclei — template-based vulnerability scanning
# ---------------------------------------------------------------------------

_NUCLEUS_CORS_RE = re.compile(
    r"(access-control-allow-origin\s*:\s*(?:\*|https?://[^,\s]+))"
    r"|access-control-allow-credentials\s*:\s*true",
    re.I,
)

_NUCLEUS_XSS_RE = re.compile(
    r"<script[^>]*>.*document\.cookie|"
    r"window\.location\s*=|alert\s*\(\s*['\"]",
    re.I,
)

_NUCLEUS_SENSITIVE_RE = re.compile(
    r"(password|secret|token|api[_-]?key|private[_-]?key|credential"
    r"|authorization)\s*[=:]\s*['\"][^'\"]{8,}['\"]",
    re.I,
)

_NUCLEUS_SSTI_RE = re.compile(
    r"\{\{.*\}\}|<%.*%>",
)

_NUCLEUS_SSRF_RE = re.compile(
    r"(http://127\.0\.0\.1|http://localhost|http://169\.254\.169\.254"
    r"|http://169\.254\.169\.254/latest"
    r"|file:///etc/passwd)",
)

_NUCLEUS_SHELLEXEC_RE = re.compile(
    r"(system\s*\(|exec\s*\(|shell_exec\s*\(|passthru\s*\(|`.*`)",
)


def nuclei_check_cors_misconfig(headers: dict[str, str]) -> list[dict[str, Any]]:
    """Check for CORS misconfiguration (Nuclei cors-misconfig templates)."""
    findings: list[dict[str, Any]] = []
    header_map = {k.lower(): v for k, v in headers.items()}

    acao = header_map.get("access-control-allow-origin", "")
    if acao == "*":
        findings.append({
            "rule": "NUCLEUS-CORS-WILDCARD",
            "severity": "medium",
            "confidence": 0.9,
            "cwe": "CWE-359",
            "title": "CORS wildcard origin (*) ditemukan",
            "description": (
                "Header Access-Control-Allow-Origin menggunakan wildcard (*). "
                "Setiap origin dapat mengakses sumber daya — potensi "
                "cross-origin data theft."
            ),
            "evidence": {"header": "Access-Control-Allow-Origin", "value": acao},
            "remediation": (
                "Tetapkan origin spesifik bukan wildcard; validasi origin "
                "secara server-side."
            ),
            "location": "server-headers",
        })
    elif acao and acao != "null":
        # Check if credentials are allowed with specific origin.
        acac = header_map.get("access-control-allow-credentials", "")
        if acac.lower() == "true":
            findings.append({
                "rule": "NUCLEUS-CORS-CREDENTIALS",
                "severity": "medium",
                "confidence": 0.85,
                "cwe": "CWE-359",
                "title": "CORS credentials enabled dengan origin spesifik",
                "description": (
                    "Access-Control-Allow-Credentials: true dikombinasikan "
                    "dengan Access-Control-Allow-Origin. "
                    "Pastikan origin yang diizinkan tidak dapat di-spoof."
                ),
                "evidence": {
                    "origin": acao,
                    "credentials": acac,
                },
                "remediation": (
                    "Pastikan origin yang diizinkan tidak bisa di-spoof; "
                    "jangan izinkan credentials dengan wildcard origin."
                ),
                "location": "server-headers",
            })

    return findings


def nuclei_check_xss_protection(headers: dict[str, str]) -> list[dict[str, Any]]:
    """Check for XSS protection configuration (Nuclei xss templates)."""
    findings: list[dict[str, Any]] = []
    header_map = {k.lower(): v for k, v in headers.items()}

    # Check for legacy X-XSS-Protection enabled.
    xss = header_map.get("x-xss-protection", "")
    if xss and "0" in xss:
        findings.append({
            "rule": "NUCLEUS-XSS-PROTECTION-DISABLED",
            "severity": "low",
            "confidence": 0.8,
            "cwe": "CWE-79",
            "title": "X-XSS-Protection dinonaktifkan",
            "description": (
                "Header X-XSS-Protection di-set ke 0. "
                "Meski sudah usang (digantikan CSP), ketiadaan proteksi "
                "ini bisa menjadi sinyal."
            ),
            "evidence": {"header": "X-XSS-Protection", "value": xss},
            "remediation": (
                "Gunakan Content-Security-Policy alih-alih "
                "X-XSS-Protection."
            ),
            "location": "server-headers",
        })

    # Check for Reflected-XSS body pattern (XSS in response).
    return findings


def nuclei_check_security_headers(headers: dict[str, str]) -> list[dict[str, Any]]:
    """Check for missing security headers (Nuclei security-headers template)."""
    return nikto_check_server_headers(headers)


def nuclei_check_sensitive_files(body: str, url: str = "") -> list[dict[str, Any]]:
    """Check for sensitive content exposure (Nuclei sensitive-files template)."""
    findings: list[dict[str, Any]] = []
    if not body:
        return findings

    # Check for credential patterns.
    cred_matches = _NUCLEUS_SENSITIVE_RE.findall(body)
    if cred_matches:
        findings.append({
            "rule": "NUCLEUS-SENSITIVE-DATA",
            "severity": "critical",
            "confidence": 0.9,
            "cwe": "CWE-798",
            "title": "Data sensitif terdeteksi di response",
            "description": (
                "Pattern credential/secret ditemukan di body response: "
                + ", ".join(list(dict.fromkeys(cred_matches))[:5])
            ),
            "evidence": {"pattern_count": len(cred_matches)},
            "remediation": (
                "Hapus data sensitif dari response; gunakan secret manager."
            ),
            "location": url or "response-body",
        })

    return findings


def nuclei_check_template_matches(body: str, url: str = "") -> list[dict[str, Any]]:
    """Match against Nuclei-style template vulnerability patterns."""
    findings: list[dict[str, Any]] = []
    if not body:
        return findings

    # SSTI (Server-Side Template Injection) detection.
    if re.search(_NUCLEUS_SSTI_RE, body):
        findings.append({
            "rule": "NUCLEUS-SSTI",
            "severity": "critical",
            "confidence": 0.8,
            "cwe": "CWE-1336",
            "title": "Potensi Server-Side Template Injection",
            "description": (
                "Pola template injection terdeteksi di response "
                "({{ }} atau <% %> syntax). Pastikan bukan false positive."
            ),
            "evidence": {"url": url or "unknown"},
            "remediation": (
                "Validasi dan escape semua input template; "
                "gunakan sandbox untuk template rendering."
            ),
            "location": url or "response-body",
        })

    # SSRF sink detection.
    ssrf_matches = _NUCLEUS_SSRF_RE.findall(body)
    if ssrf_matches:
        findings.append({
            "rule": "NUCLEUS-SSRF-SINK",
            "severity": "high",
            "confidence": 0.75,
            "cwe": "CWE-918",
            "title": "Potensi SSRF sink terdeteksi",
            "description": (
                "Pattern URL internal ditemukan di body response "
                f"(seperti: {', '.join(ssrf_matches[:3])}). "
                "Server mungkin rentan SSRF."
            ),
            "evidence": {"matches": ssrf_matches[:5]},
            "remediation": (
                "Validasi dan blokir URL internal; gunakan allowlist "
                "untuk outbound request."
            ),
            "location": url or "response-body",
        })

    # Shell execution patterns.
    if re.search(_NUCLEUS_SHELLEXEC_RE, body):
        findings.append({
            "rule": "NUCLEUS-SHELL-EXEC",
            "severity": "critical",
            "confidence": 0.75,
            "cwe": "CWE-78",
            "title": "Potensi code injection (shell execution)",
            "description": (
                "Pattern eksekusi shell ditemukan di response body."
            ),
            "evidence": {"url": url or "unknown"},
            "remediation": (
                "Validasi dan sanitize semua input user; "
                "hindari dynamic code execution."
            ),
            "location": url or "response-body",
        })

    return findings


def nuclei_check_crlf_injection(headers: dict[str, str]) -> list[dict[str, Any]]:
    """Check for CRLF injection in headers (Nuclei crlf templates)."""
    findings: list[dict[str, Any]] = []
    for hdr, val in headers.items():
        if "\r" in val or "\n" in val:
            findings.append({
                "rule": "NUCLEUS-CRLF-INJECTION",
                "severity": "high",
                "confidence": 0.85,
                "cwe": "CWE-113",
                "title": f"CRLF injection ditemukan pada header: {hdr}",
                "description": (
                    f"Header {hdr} mengandung karakter carriage-return "
                    f"atau newline — potensi HTTP response splitting."
                ),
                "evidence": {"header": hdr, "value": val[:80]},
                "remediation": (
                    "Sanitasi semua header values; "
                    "reject karakter CR/LF."
                ),
                "location": f"header:{hdr}",
            })
    return findings
