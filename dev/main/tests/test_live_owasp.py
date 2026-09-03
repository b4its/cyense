"""Tests for live OWASP Top 10 posture analysis (app/engines/live_owasp.py).

Covers: sensitive-data exposure over plaintext HTTP, session-cookie attributes
(HttpOnly / Secure / SameSite), login-form detection, CSRF token + cross-origin
action posture, insecure-deserialization markers, header disclosure, directory
listing, debug-endpoint exposure, verbose internal-error disclosure, the 2xx /
text-only rules, and the active sensitive-endpoint probe.
"""

from __future__ import annotations

import pytest

from app.engines.live_owasp import analyze_page_owasp, probe_owasp_endpoints


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
