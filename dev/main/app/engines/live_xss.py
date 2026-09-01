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
    r"\s(on(?:click|dblclick|auxclick|contextmenu|load|error|unload|abort"
    r"|mouseover|mouseout|mousedown|mouseup|mousemove|mouseenter|mouseleave"
    r"|mousewheel|wheel|focus|focusin|focusout|blur|change|submit|reset"
    r"|keyup|keydown|keypress|input|select|copy|cut|paste"
    r"|scroll|resize|drag|dragstart|dragend|dragover|dragenter|dragleave|drop"
    r"|touchstart|touchend|touchmove|touchcancel"
    r"|pointerdown|pointerup|pointermove|pointerenter|pointerleave|pointercancel"
    r"|animationstart|animationend|transitionend|visibilitychange"
    r"|beforeunload|pageshow|pagehide))\s*=\s*['\"][^'\"]+['\"]",
    re.I,
)

# iframe srcdoc — inline HTML injected into a frame (XSS sink).
_SRCDOC_RE = re.compile(r"<iframe[^>]*\bsrcdoc\s*=", re.I)

# ---------------------------------------------------------------------------
# DOM-XSS data-flow heuristics (sources → sinks)
# ---------------------------------------------------------------------------

# DOM sources: values an attacker can influence client-side.
_DOM_SOURCES: list[str] = [
    r"location\.hash",
    r"location\.search",
    r"location\.href",
    r"location\.pathname",
    r"document\.URL",
    r"document\.documentURI",
    r"document\.referrer",
    r"window\.name",
    r"document\.cookie",
    r"localStorage",
    r"sessionStorage",
    r"postMessage\s*\(",
    r"event\.data",
]

# DOM sinks: operations that turn a string into HTML/JS/navigation.
_DOM_SINKS: list[str] = [
    r"\.innerHTML\s*=",
    r"\.outerHTML\s*=",
    r"document\.write\s*\(",
    r"document\.writeln\s*\(",
    r"\.insertAdjacentHTML\s*\(",
    r"eval\s*\(",
    r"new\s+Function\s*\(",
    r"setTimeout\s*\(\s*['\"`]",
    r"setInterval\s*\(\s*['\"`]",
    r"\.src\s*=",
    r"\.href\s*=",
    r"\.srcdoc\s*=",
    r"document\.location\s*=",
    r"window\.location\s*=",
    r"document\.open\s*\(",
]

# postMessage broadcast to a wildcard target origin.
_POSTMESSAGE_WILDCARD_RE = re.compile(
    r"\.postMessage\s*\([^)]*?,\s*['\"]\*['\"]", re.I
)

# window.open / location navigation with a dynamic (source-derived) URL.
_WINDOW_OPEN_DYNAMIC_RE = re.compile(
    r"window\.open\s*\([^)]*?(?:location|document\.URL|document\.referrer|"
    r"window\.name|localStorage|sessionStorage|document\.cookie)",
    re.I | re.S,
)

# data: URI inside iframe/object/embed — an HTML/script injection vector.
# iframe/embed use `src`; object uses `data`.
_DATA_URI_TAG_RE = re.compile(
    r"<(?:iframe|object|embed)[^>]*\b(?:src|data)\s*=\s*['\"]\s*data:",
    re.I,
)

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
    csp = headers_lc.get("content-security-policy", "")

    # ---- Document-level checks (HTML only) --------------------------------
    if is_html:
        # 1. Content-Security-Policy
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

    # ---- DOM-based XSS (data-flow: DOM source → HTML/JS sink) -------------
    dom_xss = _find_dom_xss(body)
    if dom_xss:
        findings.append(_finding(
            rule="XS-LIVE-025", severity="high", confidence=0.7,
            title="Potential DOM-based XSS data-flow detected",
            description=(
                f"Detected {len(dom_xss)} sink(s) reached from a DOM source "
                "(location/document.URL/referrer/storage/postMessage...). "
                "Attacker-controlled input can reach an HTML/JS sink without "
                "a server round-trip."
            ),
            evidence={
                "occurrences": len(dom_xss),
                "samples": dom_xss[:3],
            },
            remediation=(
                "Treat every DOM source as untrusted: validate/encode before "
                "passing into sinks; use textContent instead of innerHTML and "
                "never eval dynamic strings."
            ),
            url=url,
        ))

    # ---- DOM storage (localStorage/sessionStorage) → sink -----------------
    storage_sinks = _find_storage_sinks(body)
    if storage_sinks:
        findings.append(_finding(
            rule="XS-LIVE-026", severity="high", confidence=0.65,
            title="DOM storage value written into HTML/JS sink",
            description=(
                f"localStorage/sessionStorage data flows into {len(storage_sinks)} "
                "rendering sink(s). Stored attacker-controlled values can "
                "execute when the page renders them."
            ),
            evidence={"occurrences": len(storage_sinks), "samples": storage_sinks[:3]},
            remediation=(
                "Never render storage values via innerHTML/eval; validate on "
                "write and escape on read."
            ),
            url=url,
        ))

    # ---- postMessage wildcard target origin --------------------------------
    wildcard = _POSTMESSAGE_WILDCARD_RE.findall(body)
    if wildcard:
        findings.append(_finding(
            rule="XS-LIVE-027", severity="medium", confidence=0.6,
            title="postMessage broadcast to wildcard target origin (*)",
            description=(
                "postMessage is called with '*' as the target origin, letting "
                "any window receive the message — an XSS / data-leak vector "
                "when the payload is trusted and used in a sink."
            ),
            evidence={"count": len(wildcard), "pattern": "postMessage(..., '*')"},
            remediation=(
                "Specify the exact target origin in postMessage and validate "
                "event.origin on the receiving side before trusting event.data."
            ),
            url=url,
        ))

    # ---- window.open with a dynamic URL -------------------------------------
    dyn_open = _WINDOW_OPEN_DYNAMIC_RE.findall(body)
    if dyn_open:
        findings.append(_finding(
            rule="XS-LIVE-028", severity="medium", confidence=0.55,
            title="window.open with user-influenced URL",
            description=(
                "window.open is called with a URL derived from a DOM source. "
                "An attacker-controlled value can open arbitrary pages "
                "(phishing / javascript: execution)."
            ),
            evidence={"count": len(dyn_open), "samples": dyn_open[:3]},
            remediation=(
                "Validate/normalize the URL scheme and host before opening; "
                "avoid javascript: URLs entirely."
            ),
            url=url,
        ))

    # ---- data: URI inside iframe/object/embed ------------------------------
    data_uri = _DATA_URI_TAG_RE.findall(body)
    if data_uri:
        findings.append(_finding(
            rule="XS-LIVE-029", severity="medium", confidence=0.6,
            title="data: URI in iframe/object/embed src",
            description=(
                "A data: URI is used as the src of a frame/object/embed. If the "
                "payload is user-controlled it can carry HTML/script into the "
                "page context."
            ),
            evidence={"count": len(data_uri), "pattern": "src=\"data:...\""},
            remediation=(
                "Serve embedded content from a same-origin URL; never accept "
                "user-supplied data: URIs for scriptable elements."
            ),
            url=url,
        ))

    # ---- CSP hardening gaps (missing object-src / base-uri) ----------------
    if is_html and csp:
        csp_gaps = _csp_hardening_gaps(csp)
        if csp_gaps:
            findings.append(_finding(
                rule="XS-LIVE-030", severity="low", confidence=0.85,
                title="CSP hardening gaps: " + ", ".join(csp_gaps),
                description=(
                    "CSP is present but missing directives that harden against "
                    "common XSS bypasses: " + ", ".join(csp_gaps) + "."
                ),
                evidence={"csp": csp[:500], "gaps": csp_gaps},
                remediation=(
                    "Add 'object-src none' and 'base-uri self' (and avoid "
                    "wildcard script-src sources) to the CSP."
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


def _find_dom_xss(body: str) -> list[str]:
    """Return snippets where a DOM source is used near an HTML/JS sink.

    Heuristic (DOM-based XSS): for each sink occurrence, inspect a window
    around it; if any DOM source appears within that window, the input can
    flow client-side into the sink without a server round-trip.
    """
    results: list[str] = []
    if not body:
        return results
    for sink_re in _DOM_SINKS:
        sink_regex = re.compile(sink_re, re.I)
        for m in sink_regex.finditer(body):
            start = max(0, m.start() - 200)
            end = min(len(body), m.end() + 120)
            window = body[start:end]
            for src_re in _DOM_SOURCES:
                if re.search(src_re, window, re.I):
                    results.append(f"{src_re} → {sink_re}")
                    break
    # De-duplicate identical (source → sink) pairs.
    return list(dict.fromkeys(results))


def _find_storage_sinks(body: str) -> list[str]:
    """Return snippets where localStorage/sessionStorage flows into a sink."""
    results: list[str] = []
    if not body:
        return results
    for m in re.finditer(r"(?:localStorage|sessionStorage)", body, re.I):
        start = max(0, m.start() - 60)
        end = min(len(body), m.end() + 200)
        window = body[start:end]
        for sink_re in _DOM_SINKS:
            if re.search(sink_re, window, re.I):
                results.append(window[:120])
                break
    return list(dict.fromkeys(results))


def _csp_hardening_gaps(csp: str) -> list[str]:
    """Return CSP hardening gaps: missing object-src, missing base-uri,
    and wildcard script-src hosts (common XSS-bypass enablers)."""
    gaps: list[str] = []
    if "object-src" not in csp:
        gaps.append("missing object-src")
    if "base-uri" not in csp:
        gaps.append("missing base-uri")
    # script-src with a wildcard host (https://*.cdn or http: broad sources)
    if re.search(r"script-src[^;]*\*", csp):
        gaps.append("wildcard script-src")
    return gaps
