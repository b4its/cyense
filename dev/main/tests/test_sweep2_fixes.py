"""Regression tests for the latest sweep fixes.

Covers:
  * worker resume overlay preserves checkpoint params (level/scan_mode/lang)
  * live_webapp header lookup is case-insensitive (crawler lowercases keys)
  * owasp_live session-entropy only flags session-like cookies
  * live_owasp SameSite=None+Secure order-independent
  * osint _vcard_country survives malformed vcardArray
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# worker resume overlay
# ---------------------------------------------------------------------------

def test_resume_overlay_preserves_checkpoint_params() -> None:
    """A fresh resume request with only mode/i_have_permission/resume_from must
    NOT overwrite the checkpoint's level/scan_mode/lang with model defaults."""
    from app.core.models_github import GithubScanRequest

    fresh = GithubScanRequest(mode="github", i_have_permission=True, resume_from="abc")
    explicit = fresh.model_dump(mode="json", exclude_defaults=True)

    checkpoint = {
        "repo_url": "https://github.com/acme/x",
        "level": "max",
        "lang": "python",
        "scan_mode": "deep",
        "mode": "github",
    }
    merged = dict(checkpoint)
    for k, v in explicit.items():
        if v is not None:
            merged[k] = v

    assert merged["level"] == "max"
    assert merged["lang"] == "python"
    assert merged["scan_mode"] == "deep"
    assert merged["repo_url"] == "https://github.com/acme/x"
    assert merged["resume_from"] == "abc"


# ---------------------------------------------------------------------------
# live_webapp header lookup
# ---------------------------------------------------------------------------

def test_live_webapp_header_lookup_case_insensitive() -> None:
    """Crawler stores headers lowercase; passive checks must still find them."""
    from app.engines import live_webapp as lw

    # A page with X-Frame-Options DENY + CSP frame-ancestors + no-store should
    # NOT produce frame-injection or cache findings.
    page = {
        "headers": {
            "x-frame-options": "DENY",
            "cache-control": "no-store, no-cache",
            "pragma": "no-cache",
            "content-security-policy": "frame-ancestors 'self'",
            "set-cookie": "sessionid=abc; Max-Age=3600; Secure; HttpOnly",
        },
        "body": "<html><body>hi</body></html>",
        "url": "http://x/",
        "status": 200,
        "content_type": "text/html",
    }
    res = lw.analyze_webapp(page)
    rules = {f["rule"] for f in res}
    assert "OWASP-CONF-008" not in rules  # frame injection not fired
    assert "OWASP-SENSITIVE-004" not in rules  # cache not fired (no password form anyway)
    assert "OWASP-AUTH-006" not in rules  # session cookie has Max-Age


def test_live_webapp_session_timeout_lowercase_set_cookie() -> None:
    """Set-Cookie stored lowercase, string (not list) — checks must parse it."""
    from app.engines import live_webapp as lw

    page = {
        "headers": {"set-cookie": "sessionid=abc; Path=/"},
        "body": "<html></html>",
        "url": "http://x/",
        "status": 200,
        "content_type": "text/html",
    }
    res = lw.analyze_webapp(page)
    assert any(f["rule"] == "OWASP-AUTH-006" for f in res)


# ---------------------------------------------------------------------------
# owasp_live session entropy
# ---------------------------------------------------------------------------

def test_session_entropy_ignores_benign_cookies() -> None:
    from app.utils.owasp_live import check_session_id_entropy

    benign = {
        "Set-Cookie": "lang=en; Path=/, theme=dark; Path=/",
    }
    assert check_session_id_entropy(benign, "https://x/") == []


def test_session_entropy_flags_session_like_short_cookie() -> None:
    from app.utils.owasp_live import check_session_id_entropy

    f = check_session_id_entropy(
        {"Set-Cookie": "PHPSESSID=ab12cd34ef56; path=/"}, "https://x/",
    )
    assert any(x["rule"] == "OWASP-SESSION-ENTROPY" for x in f)


# ---------------------------------------------------------------------------
# live_owasp SameSite=None + Secure order independence
# ---------------------------------------------------------------------------

def test_samesite_none_secure_order_independent() -> None:
    from app.engines import live_owasp as lo

    # Secure BEFORE SameSite=None is correctly configured → the combined
    # OWASP-CSRF-004 condition (SameSite=None present AND Secure absent) must
    # NOT be satisfied.
    samesite_present = lo._SAMESITE_NONE_RE.search("a=1; Secure; SameSite=None") is not None
    secure_present = lo._SECURE_RE.search("a=1; Secure; SameSite=None") is not None
    assert samesite_present and secure_present
    assert not (samesite_present and not secure_present)

    # SameSite=None WITHOUT Secure → insecure condition is satisfied.
    s2 = lo._SAMESITE_NONE_RE.search("a=1; SameSite=None") is not None
    secure2 = lo._SECURE_RE.search("a=1; SameSite=None") is not None
    assert s2 and not secure2


# ---------------------------------------------------------------------------
# osint _vcard_country malformed input
# ---------------------------------------------------------------------------

def test_vcard_country_malformed_no_crash() -> None:
    from app.utils.osint import _vcard_country

    assert _vcard_country([{"vcardArray": [["vcard"]]}]) is None
    assert _vcard_country([{"vcardArray": "bad"}]) is None
    assert _vcard_country([{
        "vcardArray": [["vcard"], [["adr", {}, "text", ["", "", "", "US"]]]],
    }]) == "US"
