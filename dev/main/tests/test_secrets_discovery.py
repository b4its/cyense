"""Tests for secret scanning (TruffleHog-style) + discovery modules.

Adaptation of the HackerOne 104 tools list: TruffleHog/Shhgit (secrets),
Jsluice/js-link-finder (JS URLs), Nikto/Dirsearch (sensitive paths),
Arjun (hidden params), waybackurls (passive URLs).
"""

from __future__ import annotations

from app.utils.discovery import (
    COMMON_PARAM_NAMES,
    SENSITIVE_PATHS,
    extract_js_urls,
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
        "slack='xoxb-REDACTED'; "
        "mysql://root:secret123@db.internal/app"
    )
    findings = scan_secrets(body)
    types = {f["secret_type"] for f in findings}
    assert {"aws-access-key", "slack-token", "mysql-dsn"} <= types


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
