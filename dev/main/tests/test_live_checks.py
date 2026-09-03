"""Tests for the live HTTP-observable checks (app/utils/live_checks.py)."""

from __future__ import annotations

from app.utils.live_checks import (
    check_allow_methods,
    check_cookie_security,
    check_csv_exposure,
    check_follina,
    check_platform_exposure,
    check_sensitive_query_params,
    check_serialized_endpoint,
    check_tls_certificate,
    check_transport_security,
    check_upload_form,
    check_verbose_errors,
    check_x_powered_by,
    check_xml_endpoint,
    classify_injection_reflection,
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


def test_cookie_flags_expires_date_commas_no_phantom() -> None:
    """A Set-Cookie with an Expires date (which contains commas) must not be
    split into phantom pseudo-cookies nor mask the real cookie's flags."""
    hdr = (
        "session=abc123; Path=/; HttpOnly; Secure; SameSite=Lax, "
        "prefs=dark; Path=/; Expires=Wed, 21 Oct 2026 07:28:00 GMT; SameSite=Lax, "
        "sid=xyz; Path=/; HttpOnly; Secure"
    )
    f = check_cookie_security({"Set-Cookie": hdr})
    # `session` is fully hardened (HttpOnly+Secure+SameSite) → never reported.
    # `prefs` is weak (no HttpOnly/Secure) → reported. `sid` has HttpOnly+Secure
    # but no SameSite → reported only for SameSite. No phantom cookie like
    # "21 Oct 2026" may appear.
    names = {x["title"].split("'")[1] if "'" in x["title"] else "" for x in f}
    assert "session" not in names
    assert "prefs" in names
    assert "sid" in names
    assert not any("Oct" in n or "GMT" in n for n in names), f"phantom cookie: {names}"
    # The HttpOnly/Secure flags of `sid` must be honoured.
    assert "COOKIE-NO-HTTPONLY" not in {x["rule"] for x in f if "sid" in x["title"]}
    assert "COOKIE-NO-SECURE" not in {x["rule"] for x in f if "sid" in x["title"]}


def test_verbose_no_false_positive_on_js_debug() -> None:
    """`const DEBUG = true` in ordinary client-side JS is not an error page."""
    body = "<script>const DEBUG = true; const os = 'x';</script><h1>Hi</h1>"
    assert _rules(check_verbose_errors(body, "http://x")) == set()


def test_verbose_os_error_requires_code() -> None:
    """'os error' as prose must not flag; 'OS error 123' (a real code) does."""
    assert _rules(check_verbose_errors("there was an os error in the build log")) == set()
    assert "VERBOSE-ERROR" in _rules(check_verbose_errors("OS error 123"))


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


def test_sensitive_query_params() -> None:
    assert "INFO-QUERY-SECRET" in _rules(
        check_sensitive_query_params("https://x/auth?user=bob&authz_token=1234&expire=1")
    )
    assert _rules(check_sensitive_query_params("https://x/?q=search&page=2")) == set()


def test_csv_and_upload_and_xml_surfaces() -> None:
    assert "CSV-DOWNLOAD" in _rules(check_csv_exposure({"Content-Type": "text/csv; charset=utf-8"}, "https://x/report"))
    assert _rules(check_csv_exposure({"Content-Type": "text/html"}, "https://x")) == set()
    body = (
        '<form action="/upload" enctype="multipart/form-data">'
        '<input type="file" name="f"></form>'
    )
    assert "UPLOAD-FORM" in _rules(check_upload_form(body, "https://x/upload"))
    assert "XML-ENDPOINT" in _rules(check_xml_endpoint({"Content-Type": "application/xml"}, "https://x/api"))
    assert "DESERIALIZE-ENDPOINT" in _rules(
        check_serialized_endpoint({"Content-Type": "application/x-java-serialized-object"}, "https://x/rpc")
    )


def test_injection_reflection_classifier() -> None:
    # Evaluated SSTI/EL: engine returned the arithmetic result.
    assert classify_injection_reflection("total = 54444439", "${7*7777777}") == "INJ-LIVE-SSTI"
    assert classify_injection_reflection("<b>54444439</b>", "{{7*7777777}}") == "INJ-LIVE-SSTI"
    # Not evaluated (marker still present raw) → no finding.
    assert classify_injection_reflection("<b>${7*7777777}</b>", "${7*7777777}") is None
    # A page that merely contains the digits is NOT SSTI.
    assert classify_injection_reflection("the 49ers won 2013", "{{7*7777777}}") is None
    # CRLF with a reflected newline + injected header marker.
    assert classify_injection_reflection(
        "a\r\nX-Injected-CRLF: 1", "\r\nX-Injected-CRLF: 1",
    ) == "INJ-LIVE-CRLF"
