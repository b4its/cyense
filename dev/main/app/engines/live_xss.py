"""Live XSS surface analysis for fetched HTML pages.

Unlike the static ``app/program/xss_rules.py`` (which inspects source code),
this module inspects the *runtime* HTML + HTTP response of a live page and
looks for:

  * Missing or weak security headers (CSP, X-Content-Type-Options, etc.)
  * Dangerous JS patterns already present in the served markup
  * Inline event handlers bound to untrusted expressions
  * Reflected request parameters echoed back verbatim (heuristic)

Each finding is produced with an explicit confidence and severity so the
report can rank them alongside IDOR findings from the same scan.

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


def analyze_page_xss(page: dict[str, Any]) -> list[dict[str, Any]]:
    """Return XSS/security-posture findings for one fetched page."""
    findings: list[dict[str, Any]] = []
    url = page.get("url", "")
    body = page.get("body", "") or ""
    headers = page.get("headers", {}) or {}
    content_type = (page.get("content_type") or "").lower()

    if "html" not in content_type:
        return findings

    # Normalize header lookup (headers may be stored in mixed case)
    headers_lc = {k.lower(): v for k, v in headers.items()}

    # ---- 1. Content-Security-Policy -------------------------------------
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

    # ---- 2. Dangerous JS patterns --------------------------------------
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

    # ---- 3. Inline event handlers --------------------------------------
    handler_matches = _INLINE_HANDLER_RE.findall(body)
    if handler_matches:
        unique_handlers = sorted({m.lower() for m in handler_matches})
        findings.append(_finding(
            rule="XS-LIVE-013", severity="low",
            confidence=min(0.45 + 0.05 * len(unique_handlers), 0.85),
            title=f"Inline event handler(s) detected ({len(unique_handlers)} types)",
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

    # ---- 4. Missing security headers -----------------------------------
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

    # ---- 5. Reflected URL parameter (heuristic) ------------------------
    # If the page URL has query parameters whose values appear verbatim in
    # the response body without HTML-encoding, that's a reflected-XSS signal.
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

    return findings


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

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


def _find_reflected_params(page: dict[str, Any]) -> list[tuple[str, str]]:
    """Return (param_name, matched_snippet) for each reflected query param.

    We only flag params whose raw value is >= 4 chars and appears in the body
    without the standard HTML entities (&lt; &gt; &quot; &#39; &amp;).
    """
    from urllib.parse import urlparse, parse_qs

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
