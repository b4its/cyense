"""Live XSS surface analysis for fetched pages (HTML + external JS).

Unlike the static ``app/program/xss_rules.py`` (which inspects source code),
this module inspects the *runtime* HTML, HTTP response, and fetched external
JavaScript of a live site and looks for:

  * Missing or weak security headers (CSP, HSTS, X-Content-Type-Options, ...)
  * Dangerous JS patterns in inline scripts AND external JS bundles
  * Inline event handlers bound to untrusted expressions
  * iframe ``srcdoc`` injection sinks
  * ``document.cookie`` exfiltration via network APIs to remote origins
  * Reflected request parameters echoed back verbatim (heuristic)

Only HTTP 2xx responses are analyzed — error pages (404/5xx) would otherwise
generate false positives for "missing CSP / missing security header".

All checks are **read-only** and purely observational — no probe payloads
are injected into the target (keeps the scan in the PRD's ethical envelope).
"""

from __future__ import annotations

import re
from typing import Any

# (regex, rule_id, severity, title, remediation)
_JS_PATTERN_CHECKS: list[tuple[str, str, str, str, str]] = [
    (r"(?<![\w$])eval\s*\(",
     "XS-LIVE-005", "critical",
     "eval() usage detected in page script",
     "Replace eval() with a safe parser (JSON.parse, DOM APIs, etc.)."),
    (r"new\s+Function\s*\(",
     "XS-LIVE-008", "high",
     "new Function() constructor usage",
     "Replace new Function() with a declarative alternative."),
    (r"document\.write\s*\(",
     "XS-LIVE-004", "high",
     "document.write() usage",
     "Use DOM APIs (createElement/textContent) instead of document.write()."),
    (r"\.innerHTML\s*=[^=]",
     "XS-LIVE-003", "high",
     "innerHTML assignment in page script",
     "Replace innerHTML with textContent or a sanitizer like DOMPurify."),
    (r"\.outerHTML\s*=[^=]",
     "XS-LIVE-014", "high",
     "outerHTML assignment in page script",
     "Prefer DOM APIs over outerHTML assignment."),
    (r"dangerouslySetInnerHTML\s*=",
     "XS-LIVE-020", "high",
     "React dangerouslySetInnerHTML usage",
     "Avoid dangerouslySetInnerHTML; render user data through safe components."),
    (r"v-html\s*=",
     "XS-LIVE-021", "high",
     "Vue v-html directive usage",
     "Avoid v-html with untrusted values; use interpolation instead."),
    (r"setTimeout\s*\(\s*['\"`]",
     "XS-LIVE-006", "medium",
     "setTimeout() with string argument (eval-like)",
     "Pass a function reference to setTimeout instead of a string."),
    (r"setInterval\s*\(\s*['\"`]",
     "XS-LIVE-007", "medium",
     "setInterval() with string argument (eval-like)",
     "Pass a function reference to setInterval instead of a string."),
    (r"\.insertAdjacentHTML\s*\(",
     "XS-LIVE-015", "medium",
     "insertAdjacentHTML() usage (HTML injection sink)",
     "Use insertAdjacentText or createElement for untrusted input."),
    (r"document\.location\s*=",
     "XS-LIVE-010", "medium",
     "Direct document.location assignment",
     "Verify the assignment target is not attacker-controlled."),
    (r"window\.location\s*=",
     "XS-LIVE-016", "medium",
     "Direct window.location assignment",
     "Verify the assignment target is not attacker-controlled."),
    (r"javascript\s*:[^\s]",
     "XS-LIVE-009", "medium",
     "javascript: URL scheme in markup or script",
     "Replace javascript: URLs with proper event handlers."),
]

# Inline event handlers (on<event>=) — a classic XSS surface.
_INLINE_HANDLER_RE = re.compile(
    r"\s(on(?:click|load|error|mouseover|mouseout|focus|blur|change|submit"
    r"|keyup|keydown|keypress|input|dblclick|mouseenter|mouseleave|scroll"
    r"|resize|abort|beforeunload|unload|drag|drop|touchstart|touchend"
    r"|touchmove|pointerdown|pointerup|pointermove))\s*=\s*['\"][^'\"]+['\"]",
    re.I,
)

# iframe srcdoc — inline HTML injected into a frame (XSS sink).
_SRCDOC_RE = re.compile(r"<iframe[^>]*\bsrcdoc\s*=", re.I)

# document.cookie used near a network API (fetch / XHR / beacon).
_COOKIE_EXFIL_CTX_RE = re.compile(
    r"(?:fetch\s*\(|sendBeacon\s*\(|XMLHttpRequest|\.open\s*\()"
    r".{0,300}?document\.cookie",
    re.I | re.S,
)
# External origin inside a quoted string: scheme://host or protocol-relative //host.
_EXTERNAL_ORIGIN_RE = re.compile(r"[\"'](?:https?:)?//[^\"'\s/]+", re.I)


def analyze_page_xss(page: dict[str, Any]) -> list[dict[str, Any]]:
    """Return XSS/security-posture findings for one fetched page.

    ``page`` is a crawler record: ``{url, status, body, content_type, headers}``.
    Handles both HTML documents and external JavaScript bundles; non-2xx
    responses are skipped to avoid false positives from error pages.
    """
    findings: list[dict[str, Any]] = []
    url = page.get("url", "")
    body = page.get("body", "") or ""
    headers = page.get("headers", {}) or {}
    content_type = (page.get("content_type") or "").lower()
    status = int(page.get("status", 0) or 0)

    # Error pages / redirects must not be analyzed (false-positive source).
    if not (200 <= status < 300):
        return findings

    is_html = "html" in content_type
    is_js = _is_js_content(content_type)
    if not is_html and not is_js:
        return findings

    # Normalize header lookup (headers may be stored in mixed case)
    headers_lc = {k.lower(): v for k, v in headers.items()}

    # ---- Document-level checks (HTML only) --------------------------------
    if is_html:
        # 1. Content-Security-Policy
        csp = headers_lc.get("content-security-policy", "")
        if not csp:
            findings.append(_finding(
                rule="XS-LIVE-001", severity="medium", confidence=0.75,
                title="Missing Content-Security-Policy header",
                description=(
                    "The response has no CSP header, which leaves the page "
                    "vulnerable to a wider range of XSS payloads."
                ),
                evidence={"headers_checked": ["content-security-policy"]},
                remediation=(
                    "Deploy a strict CSP: default-src 'self'; script-src 'self'; "
                    "object-src 'none'; base-uri 'self'."
                ),
                url=url,
            ))
        else:
            weak = []
            if "'unsafe-inline'" in csp:
                weak.append("unsafe-inline")
            if "'unsafe-eval'" in csp:
                weak.append("unsafe-eval")
            if weak:
                findings.append(_finding(
                    rule="XS-LIVE-002", severity="low", confidence=0.85,
                    title=f"Weak CSP allows {', '.join(weak)}",
                    description=(
                        f"CSP permits {', '.join(weak)} — these directives widen "
                        "the XSS attack surface."
                    ),
                    evidence={"csp": csp[:500]},
                    remediation=(
                        "Remove 'unsafe-inline' / 'unsafe-eval' from CSP and "
                        "use nonces or strict-dynamic."
                    ),
                    url=url,
                ))

        # 2. Inline event handlers
        handler_matches = _INLINE_HANDLER_RE.findall(body)
        if handler_matches:
            unique_handlers = sorted({m.lower() for m in handler_matches})
            findings.append(_finding(
                rule="XS-LIVE-013", severity="low",
                confidence=min(0.45 + 0.05 * len(unique_handlers), 0.85),
                title=(
                    f"Inline event handler(s) detected ({len(unique_handlers)} types)"
                ),
                description=(
                    f"Page uses inline event handlers ({', '.join(unique_handlers[:6])}). "
                    "Inline handlers are an XSS sink when bound to untrusted data."
                ),
                evidence={
                    "handlers": unique_handlers[:10],
                    "count": len(handler_matches),
                },
                remediation=(
                    "Bind event listeners via addEventListener() in external JS; "
                    "avoid inline handlers in templates."
                ),
                url=url,
            ))

        # 3. iframe srcdoc — inline HTML injection sink
        if _SRCDOC_RE.search(body):
            findings.append(_finding(
                rule="XS-LIVE-018", severity="medium", confidence=0.6,
                title="iframe srcdoc attribute detected",
                description=(
                    "Page injects inline HTML via iframe srcdoc. If the content "
                    "is derived from user input this is an XSS vector."
                ),
                evidence={"pattern": "srcdoc="},
                remediation=(
                    "Avoid srcdoc with untrusted content; use a sandboxed iframe "
                    "with a src URL served from your own origin."
                ),
                url=url,
            ))

        # 4. Missing / weak security headers
        _missing_header_checks(findings, headers_lc, url, body)

        # 5. Reflected URL parameter (heuristic)
        reflected = _find_reflected_params(page)
        for param, sample in reflected:
            findings.append(_finding(
                rule="XS-LIVE-017", severity="high", confidence=0.65,
                title=f"Possible reflected parameter: {param!r}",
                description=(
                    f"Query parameter {param!r} appears verbatim in the response "
                    "body without obvious HTML encoding — potential reflected XSS."
                ),
                evidence={"param": param, "sample": sample[:120]},
                remediation=(
                    "HTML-encode the reflected value (or reject/validate it) "
                    "before inserting into the response."
                ),
                url=url,
            ))

    # ---- Dangerous JS patterns (HTML inline scripts AND external JS) ------
    for pattern, rule, severity, title, remediation in _JS_PATTERN_CHECKS:
        matches = list(re.finditer(pattern, body))
        if not matches:
            continue
        # Confidence scales with occurrence count (diminishing returns).
        confidence = min(0.55 + 0.1 * len(matches), 0.95)
        samples = [m.group(0)[:80] for m in matches[:3]]
        findings.append(_finding(
            rule=rule, severity=severity, confidence=confidence,
            title=title,
            description=(
                f"Detected {len(matches)} occurrence(s) of a dangerous "
                "pattern in the page's HTML/JS."
            ),
            evidence={
                "pattern": pattern,
                "count": len(matches),
                "samples": samples,
            },
            remediation=remediation,
            url=url,
        ))

    # ---- document.cookie exfiltration (network API → remote origin) -------
    exfil = _find_cookie_exfil(body)
    if exfil:
        findings.append(_finding(
            rule="XS-LIVE-019", severity="critical", confidence=0.7,
            title="document.cookie exfiltrated via network API to remote origin",
            description=(
                "document.cookie is read inside a fetch/XHR/beacon call that "
                "targets an external origin — session tokens may be leaked to "
                "a third party."
            ),
            evidence={"occurrences": len(exfil), "samples": exfil[:3]},
            remediation=(
                "Never send document.cookie to third-party origins; use "
                "same-origin endpoints and short-lived, HttpOnly cookies."
            ),
            url=url,
        ))

    return findings


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _is_js_content(content_type: str) -> bool:
    return (
        "javascript" in content_type
        or "ecmascript" in content_type
        or content_type == "application/x-javascript"
    )


def _finding(
    *, rule: str, severity: str, confidence: float,
    title: str, description: str, evidence: dict,
    remediation: str, url: str,
) -> dict[str, Any]:
    return {
        "rule": rule,
        "severity": severity,
        "confidence": round(confidence, 2),
        "title": title,
        "description": description,
        "evidence": evidence,
        "remediation": remediation,
        "location": url,
    }


def _missing_header_checks(
    findings: list[dict[str, Any]],
    headers_lc: dict[str, str],
    url: str,
    body: str,
) -> None:
    """Append findings for missing security headers (HTML documents only)."""
    csp = headers_lc.get("content-security-policy", "")

    if not headers_lc.get("x-content-type-options"):
        findings.append(_finding(
            rule="XS-LIVE-011", severity="info", confidence=1.0,
            title="Missing X-Content-Type-Options: nosniff",
            description="This header prevents MIME-sniffing attacks.",
            evidence={},
            remediation="Add 'X-Content-Type-Options: nosniff' header.",
            url=url,
        ))

    csp_frame = "frame-ancestors" in csp if csp else False
    xfo = headers_lc.get("x-frame-options", "")
    if not xfo and not csp_frame:
        findings.append(_finding(
            rule="XS-LIVE-012", severity="info", confidence=1.0,
            title="Missing clickjacking protection",
            description=(
                "No X-Frame-Options header and no CSP frame-ancestors "
                "directive — page can be embedded in an attacker frame."
            ),
            evidence={},
            remediation=(
                "Add 'X-Frame-Options: DENY' or a CSP 'frame-ancestors' "
                "directive."
            ),
            url=url,
        ))

    # HSTS is only meaningful over HTTPS.
    if url.lower().startswith("https://") and not headers_lc.get(
        "strict-transport-security"
    ):
        findings.append(_finding(
            rule="XS-LIVE-022", severity="info", confidence=1.0,
            title="Missing Strict-Transport-Security (HSTS) header",
            description=(
                "HTTPS response without HSTS allows protocol-downgrade and "
                "SSL-stripping attacks."
            ),
            evidence={},
            remediation=(
                "Add 'Strict-Transport-Security: max-age=31536000; "
                "includeSubDomains' on all HTTPS responses."
            ),
            url=url,
        ))

    if not headers_lc.get("referrer-policy"):
        findings.append(_finding(
            rule="XS-LIVE-023", severity="info", confidence=0.9,
            title="Missing Referrer-Policy header",
            description=(
                "Without Referrer-Policy the full URL (including query strings) "
                "may leak to third-party origins in the Referer header."
            ),
            evidence={},
            remediation=(
                "Add 'Referrer-Policy: strict-origin-when-cross-origin'."
            ),
            url=url,
        ))

    if not headers_lc.get("permissions-policy"):
        findings.append(_finding(
            rule="XS-LIVE-024", severity="info", confidence=0.8,
            title="Missing Permissions-Policy header",
            description=(
                "No Permissions-Policy header — browser features (camera, "
                "microphone, geolocation) remain available to the page."
            ),
            evidence={},
            remediation=(
                "Add a Permissions-Policy header restricting unused "
                "browser features (e.g. camera=(), microphone=())."
            ),
            url=url,
        ))


def _find_reflected_params(page: dict[str, Any]) -> list[tuple[str, str]]:
    """Return (param_name, matched_snippet) for each reflected query param.

    We only flag params whose raw value is >= 4 chars and appears in the body
    without the standard HTML entities (&lt; &gt; &quot; &#39; &amp;).
    """
    from urllib.parse import parse_qs, urlparse

    results: list[tuple[str, str]] = []
    body = page.get("body", "") or ""
    url = page.get("url", "") or ""
    if not body or not url:
        return results

    query = parse_qs(urlparse(url).query, keep_blank_values=False)
    for name, values in query.items():
        for value in values:
            if len(value) < 4:
                continue
            if value not in body:
                continue
            # Heuristic: if the HTML-encoded form ALSO appears, prefer that
            # as a sign of intentional encoding.
            import html as _html
            encoded = _html.escape(value)
            if encoded != value and encoded in body:
                continue
            results.append((name, value))
            break  # one hit per param is enough
    return results


def _find_cookie_exfil(body: str) -> list[str]:
    """Return sample snippets where document.cookie is sent to a remote origin.

    Heuristic: a fetch / XHR / sendBeacon call that references
    ``document.cookie`` within the same ~300-char window AND targets an
    external origin (``http(s)://host`` or protocol-relative ``//host``).
    """
    results: list[str] = []
    for m in _COOKIE_EXFIL_CTX_RE.finditer(body):
        snippet = m.group(0)
        if _EXTERNAL_ORIGIN_RE.search(snippet):
            results.append(snippet[:120])
    return results
