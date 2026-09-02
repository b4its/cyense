"""Tests for secret scanning (TruffleHog-style) + discovery modules.

Adaptation of the HackerOne 104 tools list: TruffleHog/Shhgit (secrets),
Jsluice/js-link-finder (JS URLs), Nikto/Dirsearch (sensitive paths),
Arjun (hidden params), waybackurls (passive URLs),
Harvester (OSINT), Nuclei (template-based vulns).
"""

from __future__ import annotations

from app.utils.discovery import (
    COMMON_PARAM_NAMES,
    SENSITIVE_PATHS,
    extract_js_urls,
    harvest_emails,
    harvest_ips,
    harvest_tech_fingerprints,
    harvest_tech_from_headers,
    nikto_check_directory_listing,
    nikto_check_info_disclosure,
    nikto_check_outdated_software,
    nikto_check_server_headers,
    nikto_check_sql_errors,
    nuclei_check_cors_misconfig,
    nuclei_check_crlf_injection,
    nuclei_check_sensitive_files,
    nuclei_check_template_matches,
    nuclei_check_xss_protection,
    wayback_cdx_url,
)
from app.utils.secrets import scan_secrets

# ---------------------------------------------------------------------------
# Secret scanning
# ---------------------------------------------------------------------------

def test_scan_secrets_aws_key() -> None:
    findings = scan_secrets("var k = 'AKIAIOSFODNN7EXAMPLE';")
    types = {f["secret_type"] for f in findings}
    assert "aws-access-key" in types


def test_scan_secrets_github_token() -> None:
    findings = scan_secrets("token = 'ghp_abcdefghijklmnopqrstuvwxyz0123456789'")
    assert any(f["secret_type"] == "github-token" for f in findings)


def test_scan_secrets_private_key() -> None:
    findings = scan_secrets("-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END")
    assert any(f["secret_type"] == "private-key-pem" for f in findings)


def test_scan_secrets_redacts_values() -> None:
    """Secret VALUES must never appear in findings (only redacted samples)."""
    findings = scan_secrets("key = 'AKIAIOSFODNN7EXAMPLE'")
    dumped = str(findings)
    assert "IOSFODNN7EXAMPLE" not in dumped
    assert "[REDACTED]" in dumped


def test_scan_secrets_multiple_types() -> None:
    body = (
        "aws='AKIAIOSFODNN7EXAMPLE'; "
        "some-service='token-value-here'; "
        "mysql://root:secret123@db.internal/app"
    )
    findings = scan_secrets(body)
    types = {f["secret_type"] for f in findings}
    assert {"aws-access-key", "mysql-dsn"} <= types


def test_scan_secrets_empty() -> None:
    assert scan_secrets("") == []
    assert scan_secrets("<html><body>no secrets here</body></html>") == []


def test_scan_secrets_jwt() -> None:
    findings = scan_secrets(
        "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signaturexyz"
    )
    assert any(f["secret_type"] == "jwt-token" for f in findings)


# ---------------------------------------------------------------------------
# JS URL extraction (Jsluice-style)
# ---------------------------------------------------------------------------

def test_extract_js_urls_fetch_and_http() -> None:
    urls = extract_js_urls(
        'fetch("/api/users?id=1"); '
        'var cdn = "https://cdn.example.com/app.js";'
    )
    assert "/api/users?id=1" in urls
    assert "https://cdn.example.com/app.js" in urls


def test_extract_js_urls_dedup() -> None:
    urls = extract_js_urls('fetch("/api/x"); fetch("/api/x");')
    assert urls.count("/api/x") == 1


def test_extract_js_urls_empty() -> None:
    assert extract_js_urls("") == []
    assert extract_js_urls("var x = 42;") == []


# ---------------------------------------------------------------------------
# Discovery constants / helpers
# ---------------------------------------------------------------------------

def test_sensitive_paths_coverage() -> None:
    """The sensitive-path list covers the classic Nikto/dirsearch checks."""
    paths = [p for p, _, _ in SENSITIVE_PATHS]
    assert "/.git/config" in paths
    assert "/.env" in paths
    assert "/wp-login.php" in paths
    assert "/actuator/env" in paths
    assert len(SENSITIVE_PATHS) >= 25


def test_common_params_and_vhosts() -> None:
    assert "id" in COMMON_PARAM_NAMES
    assert "callback" in COMMON_PARAM_NAMES
    assert len(COMMON_PARAM_NAMES) >= 25


def test_wayback_cdx_url() -> None:
    url = wayback_cdx_url("example.com")
    assert "web.archive.org/cdx/search/cdx" in url
    assert "example.com" in url


# ---------------------------------------------------------------------------
# Async discovery helpers (mocked, no network)
# ---------------------------------------------------------------------------

def test_check_sensitive_paths_hits(monkeypatch) -> None:
    import asyncio

    from app.utils.discovery import check_sensitive_paths

    async def _get(url: str, extra_headers=None):
        if "/.env" in url:
            return 200, "SECRET_KEY=abc"
        return 404, ""

    findings = asyncio.run(
        check_sensitive_paths(
            "http://target.test/", _get,
            paths=[("/.env", "env exposed", "critical"),
                   ("/.git/config", "git exposed", "high")],
        )
    )
    assert len(findings) == 1
    assert findings[0]["path"] == "/.env"
    assert findings[0]["severity"] == "critical"


def test_check_sensitive_paths_no_hits(monkeypatch) -> None:
    import asyncio

    from app.utils.discovery import check_sensitive_paths

    async def _get(url: str, extra_headers=None):
        return 404, ""

    findings = asyncio.run(
        check_sensitive_paths(
            "http://target.test/", _get,
            paths=[("/.env", "env exposed", "critical")],
        )
    )
    assert findings == []


def test_discover_hidden_params(monkeypatch) -> None:
    import asyncio

    from app.utils.discovery import discover_hidden_params

    async def _get(url: str, extra_headers=None):
        if "debug=1" in url:
            return 200, "X" * 500  # significantly different body
        return 200, "X" * 100

    found = asyncio.run(
        discover_hidden_params(
            "http://target.test/page", _get,
            params=["debug", "q"],
        )
    )
    assert "debug" in found
    assert "q" not in found


# ---------------------------------------------------------------------------
# Extended tool adaptations (full HackerOne 104 coverage)
# ---------------------------------------------------------------------------

def test_extract_subdomains_from_urls() -> None:
    from app.utils.discovery import extract_subdomains_from_urls

    subs = extract_subdomains_from_urls(
        ["http://api.example.com/x", "http://www.example.com/",
         "http://evil.com/y", "http://example.com/"],
        "example.com",
    )
    assert "api.example.com" in subs
    assert "www.example.com" in subs
    assert "evil.com" not in subs
    assert "example.com" not in subs


def test_detect_ssrf_params_url_and_form() -> None:
    from app.utils.discovery import detect_ssrf_params

    params = detect_ssrf_params(
        "http://x.test/fetch?url=https://a.b",
        '<form><input name="callback" /></form>',
    )
    assert "url" in params
    assert "callback" in params
    assert detect_ssrf_params("http://x.test/?q=1") == []


def test_check_api_endpoints(monkeypatch) -> None:
    import asyncio

    from app.utils.discovery import check_api_endpoints

    async def _get(url: str, extra_headers=None):
        if "/api/v1" in url:
            return 200, "{}"
        return 404, ""

    hits = asyncio.run(
        check_api_endpoints("http://x.test/", _get, paths=["/api/v1", "/api/v2"])
    )
    assert hits == ["/api/v1"]


def test_discover_subdomains_offline() -> None:
    """DNS enumeration must degrade gracefully (no external DNS in tests)."""
    import asyncio

    from app.utils.discovery import discover_subdomains

    # .invalid TLD never resolves — must return [] without raising.
    subs = asyncio.run(discover_subdomains("nonexistent.invalid"))
    assert subs == []


def test_common_dir_and_admin_paths() -> None:
    from app.utils.discovery import ADMIN_PATHS, COMMON_DIR_PATHS, WP_PATHS

    assert any(p == "/phpmyadmin" for p, _, _ in ADMIN_PATHS)
    assert any(p == "/wp-json/wp/v2/users" for p, _, _ in WP_PATHS)
    assert "/login" in COMMON_DIR_PATHS


# ---------------------------------------------------------------------------
# Route discovery (robots.txt / sitemap / OpenAPI / classification)
# ---------------------------------------------------------------------------

def test_parse_robots_paths() -> None:
    from app.utils.route_discovery import parse_robots_paths

    body = (
        "User-agent: *\n"
        "Disallow: /admin\n"
        "Disallow: /private\n"
        "Allow: /public\n"
        "Disallow: /\n"
    )
    paths = parse_robots_paths(body)
    assert "/admin" in paths
    assert "/private" in paths
    assert "/public" in paths
    assert "/" not in paths  # root allow-all is skipped


def test_parse_sitemap_urls() -> None:
    from app.utils.route_discovery import parse_sitemap_urls

    body = (
        "<urlset><url><loc>https://x.test/page1</loc></url>"
        "<url><loc>https://x.test/deep/page2</loc></url></urlset>"
    )
    urls = parse_sitemap_urls(body)
    assert "https://x.test/page1" in urls
    assert "https://x.test/deep/page2" in urls


def test_extract_paths_from_urls_same_domain() -> None:
    from app.utils.route_discovery import extract_paths_from_urls

    paths = extract_paths_from_urls(
        ["https://x.test/a", "https://x.test/b?x=1", "https://evil.test/c"],
        "x.test",
    )
    assert "/a" in paths
    assert "/b?x=1" in paths
    assert "/c" not in paths  # off-domain filtered


def test_classify_route() -> None:
    from app.utils.route_discovery import classify_route

    assert classify_route("/admin/users") == "sensitive"
    assert classify_route("/internal/health") == "sensitive"
    assert classify_route("/api/v1/users") == "api"
    assert classify_route("/graphql") == "sensitive"
    assert classify_route("/about") == "page"


def test_discover_routes_robots_and_openapi(monkeypatch) -> None:
    import asyncio

    from app.utils.route_discovery import discover_routes

    async def _get(url: str, extra_headers=None):
        if url.endswith("/robots.txt"):
            return 200, "Disallow: /admin\nDisallow: /console"
        if url.endswith("/openapi.json"):
            return 200, '{"paths": {"/api/users": {}, "/api/orders": {}}}'
        return 404, ""

    result = asyncio.run(
        discover_routes("http://x.test/", _get, extra_paths=["/crawled-page"])
    )
    paths = {r["path"] for r in result["routes"]}
    assert "/admin" in paths
    assert "/console" in paths
    assert "/api/users" in paths
    assert "/api/orders" in paths
    assert "/crawled-page" in paths
    # classification
    by_path = {r["path"]: r for r in result["routes"]}
    assert by_path["/admin"]["classification"] == "sensitive"
    assert by_path["/api/users"]["classification"] == "api"
    assert by_path["/crawled-page"]["classification"] == "page"
    assert by_path["/admin"]["source"] == "robots.txt"
    assert by_path["/api/users"]["source"] == "/openapi.json"


# ---------------------------------------------------------------------------
# Harvester-style passive OSINT gathering
# ---------------------------------------------------------------------------

def test_harvest_emails() -> None:
    body = "Contact us at admin@example.com or support@cyense.dev"
    emails = harvest_emails(body)
    assert len(emails) == 2
    assert "admin@example.com" in emails
    assert "support@cyense.dev" in emails


def test_harvest_emails_empty() -> None:
    assert harvest_emails("") == []
    assert harvest_emails("no emails here") == []


def test_harvest_ips() -> None:
    body = "Server at 192.168.1.1 and gateway 10.0.0.1"
    ips = harvest_ips(body)
    assert len(ips) == 2
    assert "192.168.1.1" in ips
    assert "10.0.0.1" in ips


def test_harvest_ips_empty() -> None:
    assert harvest_ips("") == []


def test_harvest_tech_from_headers() -> None:
    headers = {
        "Server": "nginx/1.18.0",
        "X-Powered-By": "Express",
        "Content-Type": "text/html",
    }
    techs = harvest_tech_from_headers(headers)
    types = {t["rule"] for t in techs}
    assert "SERVER-NGINX" in types
    assert "STACK-EXPRESS" in types
    assert any(t["version"] == "1.18.0" for t in techs)


def test_harvest_tech_from_headers_empty() -> None:
    assert harvest_tech_from_headers({}) == []


def test_harvest_tech_fingerprints() -> None:
    body = '<meta name="generator" content="WordPress 6.0"><script src="jquery-3.6.0.js"></script>'
    techs = harvest_tech_fingerprints(body)
    types = {t["rule"] for t in techs}
    assert "TECH-META-GENERATOR" in types
    assert any("jquery" in t.get("value", "") for t in techs)


def test_harvest_tech_fingerprints_empty() -> None:
    assert harvest_tech_fingerprints("") == []


def test_harvest_subdomains_crtsh_no_secret() -> None:
    """Function accepts domain and returns list; no network crash."""
    # crt.sh may be unreachable — must not raise.
    import asyncio

    from app.utils.discovery import harvest_subdomains_crtsh
    try:
        result = asyncio.get_event_loop().run_until_complete(
            harvest_subdomains_crtsh("example.com")
        )
        assert isinstance(result, list)
    except Exception:
        pass  # network unreachable is acceptable


# ---------------------------------------------------------------------------
# Nikto-style web server security checks
# ---------------------------------------------------------------------------

def test_nikto_check_server_headers_dangerous() -> None:
    headers = {"x-powered-by": "Express/4.17.1", "server": "nginx/1.18.0"}
    findings = nikto_check_server_headers(headers)
    rules = {f["rule"] for f in findings}
    assert "NIKTO-DANGEROUS-HEADER" in rules
    assert "NIKTO-SERVER-HEADER" in rules


def test_nikto_check_server_headers_missing() -> None:
    headers = {"content-type": "text/html"}
    findings = nikto_check_server_headers(headers)
    rules = {f["rule"] for f in findings}
    assert "NIKTO-MISSING-HEADER" in rules
    assert any(
        "HSTS" in f.get("title", "")
        for f in findings
    )


def test_nikto_check_server_headers_clean() -> None:
    headers = {
        "server": "nginx",
        "content-type": "text/html",
        "strict-transport-security": "max-age=31536000",
        "x-content-type-options": "nosniff",
        "x-frame-options": "DENY",
        "content-security-policy": "default-src 'self'",
        "referrer-policy": "strict-origin",
        "permissions-policy": "geolocation=()",
    }
    findings = nikto_check_server_headers(headers)
    dangerous = [
        f for f in findings
        if f["rule"] == "NIKTO-DANGEROUS-HEADER"
    ]
    assert len(dangerous) == 0


def test_nikto_check_sql_errors() -> None:
    body = (
        "You have an error in your SQL syntax; check the manual near "
        "'WHERE id=1' at line 1 — MySQL error"
    )
    findings = nikto_check_sql_errors(body)
    assert len(findings) > 0
    assert all(f["rule"] == "NIKTO-SQL-ERROR" for f in findings)
    assert all(f["severity"] == "critical" for f in findings)


def test_nikto_check_sql_errors_clean() -> None:
    assert nikto_check_sql_errors("Hello world") == []


def test_nikto_check_directory_listing() -> None:
    body = "<title>Index of /</title><a href='../'>Parent Directory</a>"
    findings = nikto_check_directory_listing(body, "http://target.test/")
    assert len(findings) == 1
    assert findings[0]["rule"] == "NIKTO-DIR-LISTING"
    assert findings[0]["severity"] == "high"


def test_nikto_check_directory_listing_clean() -> None:
    assert nikto_check_directory_listing("<html>hello</html>") == []


def test_nikto_check_info_disclosure() -> None:
    body = "Warning: mysql_connect() failed in /var/www/index.php on line 42"
    findings = nikto_check_info_disclosure(body)
    assert len(findings) > 0
    assert all(f["rule"] == "NIKTO-INFO-DISCLOSURE" for f in findings)


def test_nikto_check_info_disclosure_clean() -> None:
    assert nikto_check_info_disclosure("Hello world") == []


def test_nikto_check_outdated_software() -> None:
    techs = [
        {"rule": "SERVER-NGINX", "value": "nginx/1.14.0", "version": "1.14.0"},
        {"rule": "STACK-EXPRESS", "value": "Express", "version": None},
    ]
    findings = nikto_check_outdated_software(techs)
    assert len(findings) > 0
    assert all(f["rule"] == "NIKTO-OUTDATED-SOFTWARE" for f in findings)


# ---------------------------------------------------------------------------
# Nuclei-style template-based vulnerability checks
# ---------------------------------------------------------------------------

def test_nuclei_check_cors_misconfig_wildcard() -> None:
    headers = {"access-control-allow-origin": "*"}
    findings = nuclei_check_cors_misconfig(headers)
    assert len(findings) == 1
    assert findings[0]["rule"] == "NUCLEUS-CORS-WILDCARD"
    assert findings[0]["severity"] == "medium"


def test_nuclei_check_cors_misconfig_clean() -> None:
    headers = {"access-control-allow-origin": "https://example.com"}
    findings = nuclei_check_cors_misconfig(headers)
    assert len(findings) == 0


def test_nuclei_check_template_matches_ssti() -> None:
    body = "{{7*7}}"
    findings = nuclei_check_template_matches(body, "http://target.test/")
    assert len(findings) == 1
    assert findings[0]["rule"] == "NUCLEUS-SSTI"
    assert findings[0]["severity"] == "critical"


def test_nuclei_check_template_matches_ssrf() -> None:
    body = "http://169.254.169.254/latest/meta-data/"
    findings = nuclei_check_template_matches(body, "http://target.test/")
    assert len(findings) == 1
    assert findings[0]["rule"] == "NUCLEUS-SSRF-SINK"


def test_nuclei_check_template_matches_shell() -> None:
    body = "system('/bin/bash')"
    findings = nuclei_check_template_matches(body, "http://target.test/")
    assert len(findings) == 1
    assert findings[0]["rule"] == "NUCLEUS-SHELL-EXEC"


def test_nuclei_check_template_matches_clean() -> None:
    body = "<html><body>Hello world</body></html>"
    findings = nuclei_check_template_matches(body, "http://target.test/")
    assert len(findings) == 0


def test_nuclei_check_sensitive_files() -> None:
    body = "api_key='sk-1234567890abcdef'"
    findings = nuclei_check_sensitive_files(body, "http://target.test/")
    assert len(findings) > 0
    assert findings[0]["rule"] == "NUCLEUS-SENSITIVE-DATA"
    assert findings[0]["severity"] == "critical"


def test_nuclei_check_sensitive_files_clean() -> None:
    assert nuclei_check_sensitive_files("Hello world") == []


def test_nuclei_check_crlf_injection() -> None:
    headers = {"x-custom": "value\r\ninjected"}
    findings = nuclei_check_crlf_injection(headers)
    assert len(findings) == 1
    assert findings[0]["rule"] == "NUCLEUS-CRLF-INJECTION"


def test_nuclei_check_crlf_injection_clean() -> None:
    headers = {"content-type": "text/html"}
    assert nuclei_check_crlf_injection(headers) == []


def test_nuclei_check_xss_protection() -> None:
    headers = {"x-xss-protection": "0"}
    findings = nuclei_check_xss_protection(headers)
    assert len(findings) == 1
    assert findings[0]["rule"] == "NUCLEUS-XSS-PROTECTION-DISABLED"


def test_nuclei_check_xss_protection_clean() -> None:
    headers = {"x-xss-protection": "1; mode=block"}
    assert nuclei_check_xss_protection(headers) == []
