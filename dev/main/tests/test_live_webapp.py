"""Tests for live OWASP Top 10 classic web-application posture checks
(app/engines/live_webapp.py).

Covers: open redirect, sensitive-URL parameters, frame injection,
clear-text sensitive echoes, browser caching of sensitive inputs,
session fixation via URL, session cookie missing timeout, directory
traversal active probe, and TLS key-size / protocol checks.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.engines.live_webapp import (
    analyze_webapp,
    probe_webapp_directory_traversal,
    probe_webapp_tls,
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


def _rules(findings: list[dict]) -> set[str]:
    return {f["rule"] for f in findings}


# ---------------------------------------------------------------------------
# Guard rules
# ---------------------------------------------------------------------------

def test_non_2xx_skipped() -> None:
    assert _rules(analyze_webapp(_page(status=500))) == set()


def test_non_html_content_skipped() -> None:
    page = _page(content_type="application/json", body='{"a":1}')
    assert _rules(analyze_webapp(page)) == set()


# ---------------------------------------------------------------------------
# OWASP-CONF-007  Open Redirect / URL Redirection
# ---------------------------------------------------------------------------

def test_open_redirect_param_reported() -> None:
    findings = analyze_webapp(_page(url="http://app/?redirect=https://evil.com"))
    assert "OWASP-CONF-007" in _rules(findings)


def test_open_redirect_not_reflected_lower_confidence() -> None:
    findings = analyze_webapp(
        _page(url="http://app/?redirect=https://evil.com", body="<html>ok</html>")
    )
    f = next(f for f in findings if f["rule"] == "OWASP-CONF-007")
    assert f["confidence"] == 0.50


def test_open_redirect_reflected_higher_confidence() -> None:
    findings = analyze_webapp(
        _page(
            url="http://app/?redirect=go",
            body='<html>redirect=go</html>',
        )
    )
    f = next(f for f in findings if f["rule"] == "OWASP-CONF-007")
    assert f["confidence"] == 0.60


def test_no_redirect_param() -> None:
    assert _rules(analyze_webapp(_page())) == set()


# ---------------------------------------------------------------------------
# OWASP-SENSITIVE-002  Sensitive Info in GET Parameter
# ---------------------------------------------------------------------------

def test_sensitive_url_param_token_reported() -> None:
    findings = analyze_webapp(_page(url="http://app/?api_key=secret123"))
    assert "OWASP-SENSITIVE-002" in _rules(findings)


def test_no_sensitive_url_param() -> None:
    assert _rules(analyze_webapp(_page(url="http://app/?q=hello"))) == set()


# ---------------------------------------------------------------------------
# OWASP-CONF-008  Frame Injection / Clickjacking
# ---------------------------------------------------------------------------

def test_frame_injection_javascript_src() -> None:
    findings = analyze_webapp(
        _page(body='<iframe src="javascript:alert(1)"></iframe>')
    )
    assert "OWASP-CONF-008" in _rules(findings)


def test_frame_injection_empty_src() -> None:
    findings = analyze_webapp(
        _page(body='<iframe src=""></iframe>')
    )
    assert "OWASP-CONF-008" in _rules(findings)


def test_frame_injection_clickjacking_missing_headers() -> None:
    findings = analyze_webapp(
        _page(
            body='<iframe src="javascript:alert(1)"></iframe>',
            headers={"X-Frame-Options": ""},
        )
    )
    assert "OWASP-CONF-008" in _rules(findings)
    f = next(f for f in findings if f["rule"] == "OWASP-CONF-008")
    assert f["evidence"]["clickjacking"] is True


def test_no_frame_tag() -> None:
    assert _rules(analyze_webapp(_page())) == set()


# ---------------------------------------------------------------------------
# OWASP-SENSITIVE-003  Sensitive Data in Clear Text
# ---------------------------------------------------------------------------

def test_credit_card_pattern_reported() -> None:
    findings = analyze_webapp(
        _page(body="Card 1234-5678-9012-3456")
    )
    assert "OWASP-SENSITIVE-003" in _rules(findings)


def test_ssn_pattern_reported() -> None:
    findings = analyze_webapp(
        _page(body="SSN 123-45-6789")
    )
    assert "OWASP-SENSITIVE-003" in _rules(findings)


def test_no_clear_text_pattern() -> None:
    assert _rules(analyze_webapp(_page())) == set()


# ---------------------------------------------------------------------------
# OWASP-SENSITIVE-004  Sensitive Info Cached
# ---------------------------------------------------------------------------

def test_password_form_without_no_store() -> None:
    findings = analyze_webapp(
        _page(
            body='<input type="password" name="p">',
            headers={"Cache-Control": "max-age=3600"},
        )
    )
    assert "OWASP-SENSITIVE-004" in _rules(findings)


def test_password_form_with_no_store_not_flagged() -> None:
    findings = analyze_webapp(
        _page(
            body='<input type="password" name="p">',
            headers={"Cache-Control": "no-store, no-cache", "Pragma": "no-cache"},
        )
    )
    assert "OWASP-SENSITIVE-004" not in _rules(findings)


def test_no_password_form_not_flagged() -> None:
    assert _rules(analyze_webapp(_page())) == set()


# ---------------------------------------------------------------------------
# OWASP-AUTH-007  Session Fixation via URL
# ---------------------------------------------------------------------------

def test_session_id_in_url_reported() -> None:
    findings = analyze_webapp(
        _page(url="http://app/?jsessionid=abc123")
    )
    assert "OWASP-AUTH-007" in _rules(findings)


def test_no_session_id_url() -> None:
    assert _rules(analyze_webapp(_page())) == set()


# ---------------------------------------------------------------------------
# OWASP-AUTH-006  Session Cookie Missing Timeout
# ---------------------------------------------------------------------------

def test_session_cookie_without_maxage() -> None:
    findings = analyze_webapp(
        _page(headers={"Set-Cookie": ["sessionid=abc; Path=/"]})
    )
    assert "OWASP-AUTH-006" in _rules(findings)


def test_session_cookie_with_maxage_not_flagged() -> None:
    findings = analyze_webapp(
        _page(headers={"Set-Cookie": ["sessionid=abc; Path=/; Max-Age=3600"]})
    )
    assert "OWASP-AUTH-006" not in _rules(findings)


def test_non_session_cookie_not_flagged() -> None:
    findings = analyze_webapp(
        _page(headers={"Set-Cookie": ["theme=dark; Path=/; Max-Age=3600"]})
    )
    assert "OWASP-AUTH-006" not in _rules(findings)


# ---------------------------------------------------------------------------
# probe_webapp_directory_traversal  (active)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_directory_traversal_finds_file_read() -> None:
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.body = "root:x:0:0"
    client = AsyncMock()
    client.get = AsyncMock(return_value=mock_resp)
    findings = await probe_webapp_directory_traversal(client, "http://app")
    assert any(f["rule"] == "OWASP-CONF-009" for f in findings)


@pytest.mark.asyncio
async def test_directory_traversal_clean() -> None:
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.body = "<html>ok</html>"
    client = AsyncMock()
    client.get = AsyncMock(return_value=mock_resp)
    findings = await probe_webapp_directory_traversal(client, "http://app")
    assert not any(f["rule"] == "OWASP-CONF-009" for f in findings)


@pytest.mark.asyncio
async def test_directory_traversal_swallows_exceptions() -> None:
    client = AsyncMock()
    client.get = AsyncMock(side_effect=Exception("boom"))
    findings = await probe_webapp_directory_traversal(client, "http://app")
    assert findings == []


# ---------------------------------------------------------------------------
# probe_webapp_tls  (active)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_tls_weak_key_reported() -> None:
    with patch(
        "app.engines.live_webapp._tls_info",
        return_value={"bits": 1024, "protocol": "TLSv1.2", "not_after": None},
    ):
        findings = await probe_webapp_tls("https://app")
        rules = {f["rule"] for f in findings}
        assert "OWASP-SENSITIVE-005" in rules
        assert any(
            "key size" in f["description"].lower() for f in findings
        )


@pytest.mark.asyncio
async def test_tls_deprecated_protocol_reported() -> None:
    with patch(
        "app.engines.live_webapp._tls_info",
        return_value={"bits": 2048, "protocol": "TLSv1", "not_after": None},
    ):
        findings = await probe_webapp_tls("https://app")
        assert any(f["rule"] == "OWASP-SENSITIVE-005" for f in findings)


@pytest.mark.asyncio
async def test_tls_expired_cert_reported() -> None:
    with patch(
        "app.engines.live_webapp._tls_info",
        return_value={
            "bits": 4096,
            "protocol": "TLSv1.3",
            "not_after": "Jan  1 00:00:00 2020 GMT",
        },
    ):
        findings = await probe_webapp_tls("https://app")
        assert any(
            "expired" in f["description"].lower() for f in findings
        )


@pytest.mark.asyncio
async def test_tls_connect_failure_swallowed() -> None:
    with patch(
        "app.engines.live_webapp._tls_info", return_value=None
    ):
        findings = await probe_webapp_tls("https://app")
        assert findings == []
