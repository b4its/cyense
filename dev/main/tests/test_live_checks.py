"""Tests for the live HTTP-observable checks (app/utils/live_checks.py)."""

from __future__ import annotations

from app.utils.live_checks import (
    check_allow_methods,
    check_cookie_security,
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
