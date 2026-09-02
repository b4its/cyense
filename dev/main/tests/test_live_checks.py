"""Tests for the live HTTP-observable checks (app/utils/live_checks.py)."""

from __future__ import annotations

from app.utils.live_checks import (
    check_allow_methods,
    check_cookie_security,
    check_follina,
    check_platform_exposure,
    check_tls_certificate,
    check_transport_security,
    check_verbose_errors,
    check_x_powered_by,
)


def _rules(findings: list) -> set:
    return {f["rule"] for f in findings}


def test_verbose_and_unhandled_error_detection() -> None:
    body = "<html><body>Traceback (most recent call last): ... ValueError: x</body></html>"
    assert "VERBOSE-ERROR" in _rules(check_verbose_errors(body, "http://x"))
    assert "UNHANDLED-ERROR" in _rules(
        check_verbose_errors("You have an error in your SQL syntax", "http://x")
    )


def test_clean_body_no_error() -> None:
    assert _rules(check_verbose_errors("<html>Login page</html>", "http://x")) == set()


def test_cookie_flags_detected() -> None:
    f = check_cookie_security({"Set-Cookie": "sid=abc123; path=/"})
    assert {"COOKIE-NO-HTTPONLY", "COOKIE-NO-SECURE", "COOKIE-NO-SAMESITE"} <= _rules(f)


def test_cookie_flags_good() -> None:
    hdr = "sid=abc123; HttpOnly; Secure; SameSite=Lax; path=/"
    assert _rules(check_cookie_security({"Set-Cookie": hdr})) == set()


def test_transport_http_and_hsts() -> None:
    assert "INSECURE-TRANSPORT" in _rules(
        check_transport_security("http://example.com", {})
    )
    assert "HSTS-MISSING" in _rules(
        check_transport_security("https://example.com", {})
    )
    assert _rules(check_transport_security(
        "https://example.com",
        {"Strict-Transport-Security": "max-age=31536000"},
    )) == set()


def test_trace_and_x_powered_by() -> None:
    assert "TRACE-ENABLED" in _rules(check_allow_methods({"Allow": "GET, POST, TRACE"}))
    assert _rules(check_allow_methods({"Allow": "GET, POST"})) == set()
    assert "INFO-X-POWERED-BY" in _rules(check_x_powered_by({"X-Powered-By": "Express"}))


def test_platform_exposure() -> None:
    assert "PLATFORM-DOTNET" in _rules(
        check_platform_exposure({"X-AspNet-Version": "4.0.30319"}, "")
    )
    assert "PLATFORM-JAVA" in _rules(
        check_platform_exposure({"Set-Cookie": "JSESSIONID=abc"}, "")
    )
    assert "PLATFORM-PHP" in _rules(
        check_platform_exposure({"X-Powered-By": "PHP/8.1"}, "")
    )
    assert _rules(check_platform_exposure({"Server": "nginx"}, "<html>hi</html>")) == set()


def test_follina_signature() -> None:
    assert "FOLLINA" in _rules(
        check_follina("word/_rels/document.xml.rels http://evil/shell.html ms-msdt:")
    )
    assert _rules(check_follina("<html>login</html>")) == set()


async def test_tls_cert_expiry(monkeypatch) -> None:
    # Simulate an expired certificate without touching the network.
    import app.utils.live_checks as lc
    monkeypatch.setattr(
        lc, "_read_cert_not_after",
        lambda *a, **k: ("Dec 31 23:59:59 2020 GMT", "example.com"),
    )
    res = await check_tls_certificate("https://example.com")
    assert "TLS-CERT-EXPIRED" in _rules(res)
    assert any(f["severity"] == "critical" for f in res)


async def test_tls_cert_valid_no_finding(monkeypatch) -> None:
    import app.utils.live_checks as lc
    monkeypatch.setattr(
        lc, "_read_cert_not_after",
        lambda *a, **k: ("Dec 31 23:59:59 2099 GMT", "example.com"),
    )
    assert _rules(await check_tls_certificate("https://example.com")) == set()
