"""Tests for live OWASP Top 10 posture analysis (app/engines/live_owasp.py).

Covers: sensitive-data exposure over plaintext HTTP, session-cookie attributes
(HttpOnly / Secure / SameSite), login-form detection, CSRF token + cross-origin
action posture, insecure-deserialization markers, header disclosure, directory
listing, debug-endpoint exposure, verbose internal-error disclosure, the 2xx /
text-only rules, and the active sensitive-endpoint probe.
"""

from __future__ import annotations

import pytest

from app.engines.live_owasp import (
    analyze_page_owasp,
    probe_auth_surfaces,
    probe_http_methods,
    probe_owasp_endpoints,
)


def _page(
    *,
    url: str = "http://app/",
    status: int = 200,
    body: str = "<html><body>ok</body></html>",
    content_type: str = "text/html; charset=utf-8",
    headers: dict[str, str] | None = None,
) -> dict:
    return {
        "url": url,
        "status": status,
        "body": body,
        "content_type": content_type,
        "headers": headers or {},
    }


def _rules(findings) -> set[str]:
    return {f["rule"] for f in findings}


# ---------------------------------------------------------------------------
# Guard rules: only 2xx HTML pages are analyzed
# ---------------------------------------------------------------------------

def test_non_2xx_skipped() -> None:
    assert _rules(analyze_page_owasp(_page(status=500))) == set()


def test_non_html_content_skipped() -> None:
    page = _page(content_type="application/json", body='{"a":1}')
    assert _rules(analyze_page_owasp(page)) == set()


# ---------------------------------------------------------------------------
# A02 sensitive data exposure
# ---------------------------------------------------------------------------

def test_plaintext_http_reported() -> None:
    findings = analyze_page_owasp(_page(url="http://app/"))
    assert "OWASP-SENSITIVE-001" in _rules(findings)


def test_https_not_flagged_as_plaintext() -> None:
    findings = analyze_page_owasp(_page(url="https://app/"))
    assert "OWASP-SENSITIVE-001" not in _rules(findings)


# ---------------------------------------------------------------------------
# A07 session-cookie attributes
# ---------------------------------------------------------------------------

def test_cookie_without_httponly_reported() -> None:
    findings = analyze_page_owasp(_page(headers={"Set-Cookie": "session=abc; Path=/"}))
    assert "OWASP-AUTH-001" in _rules(findings)


def test_cookie_secure_only_flagged_over_https() -> None:
    # Over HTTPS an insecure (no Secure flag) cookie is flagged.
    https_rules = _rules(analyze_page_owasp(_page(
        url="https://app/", headers={"Set-Cookie": "session=abc; Path=/"},
    )))
    assert "OWASP-AUTH-002" in https_rules

    # Over HTTP the Secure flag is meaningless -> not flagged.
    http_rules = _rules(analyze_page_owasp(_page(
        url="http://app/", headers={"Set-Cookie": "session=abc; Path=/"},
    )))
    assert "OWASP-AUTH-002" not in http_rules


def test_samesite_none_without_secure_reported() -> None:
    findings = analyze_page_owasp(_page(headers={"Set-Cookie": "sid=1; SameSite=None"}))
    assert "OWASP-CSRF-004" in _rules(findings)


def test_session_cookie_missing_samesite_reported() -> None:
    findings = analyze_page_owasp(_page(headers={"Set-Cookie": "session=abc; Path=/; HttpOnly"}))
    assert "OWASP-CSRF-003" in _rules(findings)


# ---------------------------------------------------------------------------
# A07 login form detection
# ---------------------------------------------------------------------------

def test_password_form_detected() -> None:
    body = '<form action="/login"><input type="password" name="pw"></form>'
    findings = analyze_page_owasp(_page(body=body))
    assert "OWASP-AUTH-003" in _rules(findings)


# ---------------------------------------------------------------------------
# A04 CSRF posture
# ---------------------------------------------------------------------------

def test_post_form_without_token_reported() -> None:
    body = '<form method="post" action="/change"><input name="email"></form>'
    findings = analyze_page_owasp(_page(body=body))
    assert "OWASP-CSRF-001" in _rules(findings)


def test_post_form_with_page_token_not_flagged() -> None:
    body = (
        '<head><meta name="csrf-token" content="t"></head>'
        '<form method="post" action="/change"><input name="email"></form>'
    )
    findings = analyze_page_owasp(_page(body=body))
    assert "OWASP-CSRF-001" not in _rules(findings)


def test_cross_origin_form_action_reported() -> None:
    body = '<form method="post" action="https://evil.example/log"><input name="x"></form>'
    findings = analyze_page_owasp(_page(body=body))
    assert "OWASP-CSRF-002" in _rules(findings)


# ---------------------------------------------------------------------------
# A08 insecure deserialization markers
# ---------------------------------------------------------------------------

def test_deserialization_marker_reported() -> None:
    findings = analyze_page_owasp(_page(body='data: rO0ABXNyABN...'))
    assert "OWASP-DESER-001" in _rules(findings)


# ---------------------------------------------------------------------------
# A05 security misconfiguration
# ---------------------------------------------------------------------------

def test_server_header_disclosure_reported() -> None:
    findings = analyze_page_owasp(_page(headers={"Server": "nginx/1.18.0"}))
    assert "OWASP-CONF-001" in _rules(findings)


def test_x_powered_by_disclosure_reported() -> None:
    findings = analyze_page_owasp(_page(headers={"X-Powered-By": "Express"}))
    assert "OWASP-CONF-002" in _rules(findings)


def test_directory_listing_reported() -> None:
    findings = analyze_page_owasp(_page(body="<title>Index of /var/www</title>"))
    assert "OWASP-CONF-004" in _rules(findings)


def test_debug_endpoint_url_reported() -> None:
    findings = analyze_page_owasp(_page(url="https://app/wp-admin/"))
    assert "OWASP-CONF-003" in _rules(findings)


# ---------------------------------------------------------------------------
# A09 verbose internal error disclosure
# ---------------------------------------------------------------------------

def test_internal_error_disclosed() -> None:
    body = "<html>Traceback (most recent call last):\nFile app.py line 3</html>"
    findings = analyze_page_owasp(_page(body=body))
    assert "OWASP-MONITOR-001" in _rules(findings)


# ---------------------------------------------------------------------------
# Active sensitive-endpoint probe (read-only GET)
# ---------------------------------------------------------------------------

class _Response:
    def __init__(self, status: int) -> None:
        self.status = status


class _Client:
    def __init__(self, status: int = 200, exc: bool = False) -> None:
        self.status = status
        self.exc = exc
        self.calls: list[str] = []

    async def get(self, url: str) -> _Response:
        self.calls.append(url)
        if self.exc:
            raise ConnectionError("boom")
        return _Response(self.status)


@pytest.mark.asyncio
async def test_probe_flags_publicly_reachable() -> None:
    client = _Client(status=200)
    findings = await probe_owasp_endpoints(client, "http://app")
    assert client.calls  # actually probed
    assert all(f["rule"] == "OWASP-CONF-003" for f in findings)
    assert all(f["severity"] == "high" for f in findings)


@pytest.mark.asyncio
async def test_probe_gated_endpoint_is_info() -> None:
    client = _Client(status=403)
    findings = await probe_owasp_endpoints(client, "http://app")
    assert findings
    assert all(f["severity"] == "info" for f in findings)


@pytest.mark.asyncio
async def test_probe_ignores_connection_errors() -> None:
    client = _Client(exc=True)
    findings = await probe_owasp_endpoints(client, "http://app")
    assert findings == []


# ---------------------------------------------------------------------------
# HTTP-method audit (A05 security misconfiguration)
# ---------------------------------------------------------------------------

class _MethodClient:
    """Stub that returns configurable responses per HTTP method."""

    def __init__(
        self,
        options: _Response | None,
        trace: _Response | None,
        *,
        get_status: int = 404,
        exc: bool = False,
    ) -> None:
        self.options = options
        self.trace = trace
        self.get_status = get_status
        self.exc = exc
        self.method_calls: list[str] = []

    async def request(self, method: str, url: str) -> _Response:
        self.method_calls.append(method)
        if self.exc:
            raise ConnectionError("boom")
        if method == "OPTIONS":
            return self.options
        if method == "TRACE":
            return self.trace
        return _Response(405)

    async def get(self, url: str) -> _Response:
        self.method_calls.append("GET")
        if self.exc:
            raise ConnectionError("boom")
        return _Response(self.get_status)


@pytest.mark.asyncio
async def test_method_audit_flags_unsafe_verbs() -> None:
    # OPTIONS advertises DELETE/PATCH via Allow.
    opts = _Response(200)
    opts.headers = {"allow": "GET, HEAD, POST, PUT, DELETE, OPTIONS"}
    client = _MethodClient(options=opts, trace=_Response(405))
    findings = await probe_http_methods(client, "http://app")
    rules = {f["rule"] for f in findings}
    assert "OWASP-CONF-005" in rules
    assert "PUT" in findings[0]["evidence"]["methods"]
    # No TRACE finding (405).
    assert "OWASP-CONF-006" not in rules


@pytest.mark.asyncio
async def test_method_audit_flags_trace_enabled() -> None:
    opts = _Response(200)
    opts.headers = {"allow": "GET, HEAD, OPTIONS"}
    # TRACE reflects the request back (status 200) → XST risk.
    trace = _Response(200)
    trace.body = "TRACE / HTTP/1.1\r\nHost: app"
    client = _MethodClient(options=opts, trace=trace)
    findings = await probe_http_methods(client, "http://app")
    rules = {f["rule"] for f in findings}
    assert "OWASP-CONF-006" in rules
    assert "OWASP-CONF-005" not in rules


@pytest.mark.asyncio
async def test_method_audit_cors_allow_methods_counted() -> None:
    # Methods advertised via Access-Control-Allow-Methods are also audited.
    opts = _Response(204)
    opts.headers = {"access-control-allow-methods": "GET, PATCH, OPTIONS"}
    client = _MethodClient(options=opts, trace=_Response(405))
    findings = await probe_http_methods(client, "http://app")
    assert any("PATCH" in f["evidence"]["methods"] for f in findings)


@pytest.mark.asyncio
async def test_method_audit_resilient_to_errors() -> None:
    client = _MethodClient(options=_Response(200), trace=_Response(200), exc=True)
    findings = await probe_http_methods(client, "http://app")
    assert findings == []


# ---------------------------------------------------------------------------
# Admin / login auth-surface probe (A01 / A07)
# ---------------------------------------------------------------------------

class _SurfaceClient:
    def __init__(self, *, admin_status: int, login_status: int, exc: bool = False) -> None:
        self.admin_status = admin_status
        self.login_status = login_status
        self.exc = exc
        self.calls: list[str] = []

    async def get(self, url: str) -> _Response:
        self.calls.append(url)
        if self.exc:
            raise ConnectionError("boom")
        if "/login" in url or "/signin" in url or "/auth" in url:
            return _Response(self.login_status)
        if "wp-login" in url:
            return _Response(self.login_status)
        return _Response(self.admin_status)


@pytest.mark.asyncio
async def test_auth_surface_flags_public_admin_panel() -> None:
    client = _SurfaceClient(admin_status=200, login_status=200)
    findings = await probe_auth_surfaces(client, "http://app")
    assert client.calls
    auth = [f for f in findings if f["rule"] == "OWASP-AUTH-004"]
    assert any(f["severity"] == "high" for f in auth)
    # Login surface flagged as low info.
    login = [f for f in findings if f["rule"] == "OWASP-AUTH-005"]
    assert any(f["severity"] == "low" for f in login)


@pytest.mark.asyncio
async def test_auth_surface_gated_admin_is_info() -> None:
    client = _SurfaceClient(admin_status=403, login_status=404)
    findings = await probe_auth_surfaces(client, "http://app")
    auth = [f for f in findings if f["rule"] == "OWASP-AUTH-004"]
    assert auth and all(f["severity"] == "info" for f in auth)


@pytest.mark.asyncio
async def test_auth_surface_resilient_to_errors() -> None:
    client = _SurfaceClient(admin_status=200, login_status=200, exc=True)
    findings = await probe_auth_surfaces(client, "http://app")
    assert findings == []
