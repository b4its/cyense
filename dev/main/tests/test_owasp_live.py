"""Tests for OWASP community-vulnerability live checks (app/utils/owasp_live.py).

Each check is deterministic and passive (works on headers/body already fetched),
mapping specific OWASP www-community/vulnerabilities articles onto rule ids.
"""

from __future__ import annotations

from app.utils.owasp_live import (
    check_dispatcher_params,
    check_get_login_form,
    check_mixed_content_and_sri,
    check_password_autocomplete,
    check_serialization_magic,
    check_session_id_entropy,
    run_owasp_passive_checks,
)


def _rules(findings: list) -> set:
    return {f["rule"] for f in findings}


def test_get_login_form_detected() -> None:
    body = '<form method="get" action="/login"><input type="password" name="p"></form>'
    f = check_get_login_form(body, "https://x/login")
    assert "OWASP-LOGIN-GET" in _rules(f)


def test_post_login_not_flagged() -> None:
    body = '<form method="post" action="/login"><input type="password" name="p"></form>'
    assert _rules(check_get_login_form(body)) == set()


def test_mixed_content_on_https() -> None:
    body = '<script src="http://cdn.example.com/x.js"></script>'
    f = check_mixed_content_and_sri(body, "https://x/")
    assert "OWASP-MIXED-CONTENT" in _rules(f)


def test_no_mixed_content_on_http_page() -> None:
    body = '<script src="http://cdn.example.com/x.js"></script>'
    # On a plain HTTP page the http:// subresource is not "mixed" (page itself
    # is insecure) — no OWASP-MIXED-CONTENT.
    f = check_mixed_content_and_sri(body, "http://x/")
    assert "OWASP-MIXED-CONTENT" not in _rules(f)


def test_third_party_without_sri_flagged() -> None:
    body = '<script src="https://cdn.thirdparty.com/x.js"></script>'
    f = check_mixed_content_and_sri(body, "https://x/")
    assert "OWASP-EXTERNAL-NOSRI" in _rules(f)


def test_third_party_with_sri_ok() -> None:
    body = '<script src="https://cdn.thirdparty.com/x.js" integrity="sha384-abc"></script>'
    f = check_mixed_content_and_sri(body, "https://x/")
    assert "OWASP-EXTERNAL-NOSRI" not in _rules(f)


def test_same_origin_without_sri_ok() -> None:
    # Same-site resource (first-party) is not a third-party-access issue.
    body = '<script src="https://x/static/app.js"></script>'
    f = check_mixed_content_and_sri(body, "https://x/")
    assert "OWASP-EXTERNAL-NOSRI" not in _rules(f)


def test_serialization_java_magic() -> None:
    body = 'session=rO0ABXVyABJbTEphdmEubGFuZy5PYmplY3Q'
    assert "OWASP-DESER-MAGIC" in _rules(check_serialization_magic(body))


def test_serialization_php_magic() -> None:
    body = 'a:2:{s:4:"name";s:3:"bob";}'
    assert "OWASP-DESER-MAGIC" in _rules(check_serialization_magic(body))


def test_no_serialization_clean() -> None:
    body = "<html>normal content</html>"
    assert _rules(check_serialization_magic(body)) == set()


def test_session_short_hex_flagged() -> None:
    f = check_session_id_entropy({"Set-Cookie": "PHPSESSID=ab12cd34ef56; path=/"})
    assert "OWASP-SESSION-ENTROPY" in _rules(f)


def test_session_long_random_ok() -> None:
    long_id = "0" * 64  # hex, 256 bits-worth of characters (64 chars >= 128 bits)
    f = check_session_id_entropy({
        "Set-Cookie": f"sid={long_id}; HttpOnly; Secure; SameSite=Lax",
    })
    assert "OWASP-SESSION-ENTROPY" not in _rules(f)


def test_session_entropy_handles_expires_commas() -> None:
    """Set-Cookie containing an Expires date (with commas) must not create a
    phantom low-entropy cookie."""
    hdr = (
        "session=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef; "
        "Path=/; HttpOnly; Secure; Expires=Wed, 21 Oct 2026 07:28:00 GMT"
    )
    f = check_session_id_entropy({"Set-Cookie": hdr})
    assert _rules(f) == set()


def test_password_autocomplete_flagged() -> None:
    assert "OWASP-PW-AUTOFILL" in _rules(
        check_password_autocomplete('<input type="password" name="p">')
    )


def test_password_autocomplete_off_ok() -> None:
    assert _rules(
        check_password_autocomplete('<input type="password" name="p" autocomplete="off">')
    ) == set()


def test_run_owasp_passive_checks_aggregates() -> None:
    body = (
        '<form method="get" action="/login"><input type="password" name="p"></form>'
        '<script src="https://cdn.thirdparty.com/x.js"></script>'
    )
    findings = run_owasp_passive_checks({"Set-Cookie": "sid=ab12cd34ef56; path=/"}, body, "https://x/")
    rules = _rules(findings)
    assert "OWASP-LOGIN-GET" in rules
    assert "OWASP-EXTERNAL-NOSRI" in rules
    assert "OWASP-PW-AUTOFILL" in rules
    assert "OWASP-SESSION-ENTROPY" in rules


def test_dispatcher_params_flagged() -> None:
    f = check_dispatcher_params("https://x/app?page=about&id=5")
    assert "OWASP-DISPATCHER-PARAM" in _rules(f)


def test_dispatcher_params_clean() -> None:
    f = check_dispatcher_params("https://x/app?q=search&id=5&sort=asc")
    assert _rules(f) == set()
