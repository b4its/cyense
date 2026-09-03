"""Live OWASP Top 10 security-posture analysis for fetched website pages.

Extends the website scanner beyond IDOR / XSS / SQLi with the remaining OWASP
Top 10 categories that are observable from a live, read-only crawl:

  * **A01 Broken Access Control**      — IDOR already lives in the website engine
  * **A02 Cryptographic / Sensitive**  — plain-HTTP exposure, cookie leaks
  * **A03 Injection**                  — SQLi / XSS already in the website engine
  * **A04 Cross-Site Request Forgery** — CSRF token + SameSite-cookie posture
  * **A05 Security Misconfiguration**  — header disclosure, debug endpoints,
                                          directory listing
  * **A07 Identification & Auth**      — session-cookie attributes (HttpOnly/
                                          Secure), login-form presence
  * **A08 Data Integrity**             — insecure-deserialization markers
  * **A09 Logging & Monitoring**       — verbose/internal error disclosure
  * **A06 Vulnerable Components**      — CVE matching already in the engine

Every check is deterministic and read-only — no payloads are injected, no
state is mutated. Findings are plain dicts mirroring ``app.engines.live_xss``
so they slot directly into the website-report pipeline.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from app.engines.live_webapp import (
    analyze_webapp,
    probe_webapp_directory_traversal,
    probe_webapp_tls,
)
from app.utils.http_client import HttpClient
from app.utils.logger import get_logger

log_owasp = get_logger("owasp")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Session/auth cookie flags we look for inside a Set-Cookie header.
_HTTPONLY_RE = re.compile(r"\bhttponly\b", re.I)
_SECURE_RE = re.compile(r"\bsecure\b", re.I)
_SAMESITE_NONE_RE = re.compile(r"\bsamesite\s*=\s*none\b", re.I)
_SAMESITE_NONE_INSECURE_RE = re.compile(r"\bsamesite\s*=\s*none\b[^;]*;\s*secure", re.I)
_SET_COOKIE_ATTRS = {
    "httponly": _HTTPONLY_RE,
    "secure": _SECURE_RE,
    "samesite=none": _SAMESITE_NONE_RE,
}

# A form is protected from CSRF when it (or the page) carries a token field.
_CSRF_TOKEN_RE = re.compile(
    r"(?:csrf|_token|authenticity_token|__RequestVerificationToken|"
    r"<meta[^>]*name=[\"']csrf-token[\"'])",
    re.I,
)
_INPUT_CSRF_RE = re.compile(
    r"<input\b[^>]*name=[\"'][^\"']*(?:csrf|token)[^\"']*[\"']", re.I
)
_META_CSRF_RE = re.compile(r"<meta\b[^>]*name=[\"']csrf-token[\"']", re.I)
_FORM_RE = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.I | re.S)
_INPUT_NAME_RE = re.compile(r"<input\b[^>]*name=[\"']([^\"']+)[\"']", re.I)
_INPUT_PASSWORD_RE = re.compile(r"<input\b[^>]*type=[\"']password[\"']", re.I)
_FORM_METHOD_RE = re.compile(r"\bmethod\s*=\s*[\"']([^\"']+)[\"']", re.I)
_FORM_ACTION_RE = re.compile(r"\baction\s*=\s*[\"']([^\"']+)[\"']", re.I)
_GET_METHODS = {"get", ""}

# Insecure-deserialization markers (textual footprints in responses).
_DESERIALIZATION_MARKERS: list[tuple[str, str]] = [
    (r"\brO0AB", "Java serialized object (base64 rO0AB)"),
    (r"\bO(?:\d+|:\d+):[\"']", "PHP serialized object"),
    (r"\bC:\d+:[\"']", "PHP serialized class"),
    (r"\ba:\d+:\{[^}]{0,120}?s:\d+:[\"']", "PHP serialized array/object"),
    (r"!!python/object", "PyYAML !!python/object tag"),
    (r"\bgASV", "Python pickle (protocol 4, base64)"),
    (r"\b{[\"']?__class__[\"']?[:}]", "Python magic __class__ payload"),
]

# Verbose/internal error disclosure — your window into weak error handling and
# therefore weak logging & monitoring (A09).
_INTERNAL_ERROR_PATTERNS: list[tuple[str, str]] = [
    (r"Traceback \(most recent call last\)", "Python traceback"),
    (r"You have an error in your SQL syntax", "MySQL SQL error"),
    (r"SQLSTATE\[|psql\.error|PG::.*Error", "SQL error (SQLSTATE/Postgres)"),
    (r"Fatal error:", "PHP fatal error"),
    (r"(?:Warning|Notice):\s+.+\s+\.php on line \d+", "PHP warning with file/line"),
    (r"System\.Data\.SqlClient\.SqlException", ".NET SqlException"),
    (r"org\.(?:apache|hibernate|springframework|postgresql)\.[A-Za-z]+Exception",
     "Java exception stack"),
    (r"\.cs:line \d+", "C# compiler line info"),
    (r"pymysql\.err|sqlalchemy\.exc\.|djongo|django\.db\.utils\.DatabaseError",
     "Python DB error"),
    (r"<title>[^<]*\b(?:500|Internal Server Error)\b[^<]*</title>",
     "generic 500 error page"),
]

# Well-known debug/admin/dev endpoints that should never be public.
_SENSITIVE_ENDPOINTS: list[tuple[str, str, str]] = [
    ("/actuator/env", "Spring Boot Actuator env", "high"),
    ("/actuator/heapdump", "Spring Boot Actuator heapdump", "high"),
    ("/actuator", "Spring Boot Actuator root", "medium"),
    ("/phpinfo.php", "PHP info page", "high"),
    ("/phpmyadmin", "phpMyAdmin", "high"),
    ("/adminer.php", "Adminer DB tool", "high"),
    ("/swagger-ui", "Swagger UI", "medium"),
    ("/api-docs", "OpenAPI docs", "medium"),
    ("/v2/api-docs", "OpenAPI docs (v2)", "medium"),
    ("/console", "application dev console", "medium"),
    ("/jenkins", "Jenkins CI", "high"),
    ("/server-status", "Apache server-status", "medium"),
    ("/server-info", "Apache server-info", "medium"),
    ("/wp-admin", "WordPress admin", "medium"),
    ("/admin.php", "PHP admin entry", "medium"),
]

_DIRECTORY_LISTING_RE = re.compile(
    r"(?:<title>[^<]*Index of|Index of /|\[To Parent Directory\]|"
    r"<h1>Index of )", re.I,
)


# ---------------------------------------------------------------------------
# Public entry point (mirrors app.engines.live_xss.analyze_page_xss)
# ---------------------------------------------------------------------------

def analyze_page_owasp(page: dict[str, Any]) -> list[dict[str, Any]]:
    """Return OWASP-posture findings for one fetched page (no network).

    ``page`` is a crawler record: ``{url, status, body, content_type, headers}``.
    Non-2xx responses are skipped (error pages would skew cookie/CSRF signals).
    """
    findings: list[dict[str, Any]] = []

    url = page.get("url", "") or ""
    body = page.get("body", "") or ""
    headers = page.get("headers", {}) or {}
    content_type = (page.get("content_type") or "").lower()
    status = int(page.get("status", 0) or 0)

    if not (200 <= status < 300):
        return findings
    if "text" not in content_type and "html" not in content_type:
        # Only analyze document-ish responses for these observational checks.
        return findings

    headers_lc = {k.lower(): v for k, v in headers.items()}

    # ---- A02 Sensitive data exposure -------------------------------------
    if not url.lower().startswith("https://"):
        findings.append(_finding(
            rule="OWASP-SENSITIVE-001", severity="high", confidence=0.9,
            title="Page served over plaintext HTTP",
            description=(
                "The page is served over unencrypted HTTP. Credentials, session "
                "tokens and PII traversing this channel are exposed to "
                "man-in-the-middle attackers."
            ),
            evidence={"url": url, "scheme": urlparse(url).scheme},
            remediation=(
                "Redirect all HTTP traffic to HTTPS, obtain a valid certificate, "
                "and add HSTS with includeSubDomains."
            ),
            url=url,
        ))

    # ---- A07 Identification & authentication failures ---------------------
    findings.extend(_cookie_attribute_findings(headers_lc, url))

    if _INPUT_PASSWORD_RE.search(body):
        findings.append(_finding(
            rule="OWASP-AUTH-003", severity="low", confidence=0.6,
            title="Login form detected",
            description=(
                "A form containing a password input is exposed. Verify that it "
                "enforces account lockout / rate limiting and offers MFA; weak "
                "credential and session policies are a common auth failure."
            ),
            evidence={"form": _form_signature(body)[:160]},
            remediation=(
                "Enforce strong password + MFA, account lockout, rate limiting, "
                "and secure session cookies (HttpOnly, Secure, SameSite)."
            ),
            url=url,
        ))

    # ---- A04 CSRF ---------------------------------------------------------
    findings.extend(_csrf_findings(url, body))

    # ---- A08 Insecure deserialization -------------------------------------
    markers = _deserialization_markers(body)
    if markers:
        findings.append(_finding(
            rule="OWASP-DESER-001", severity="high", confidence=0.6,
            title="Insecure deserialization marker detected",
            description=(
                f"In response content: "
                f"{', '.join(m.split(' (')[-1].rstrip(')') for m in markers[:3])}. "
                "Attacker-controlled serialized data can lead to remote code "
                "execution or privilege escalation."
            ),
            evidence={"markers": list(dict.fromkeys(markers))[:5], "count": len(markers)},
            remediation=(
                "Avoid deserializing untrusted data; if unavoidable, use a safe "
                "format (JSON) + allow-list of classes, and never accept "
                "serialized objects from the request."
            ),
            url=url,
        ))

    # ---- A05 Security misconfiguration ------------------------------------
    server = headers_lc.get("server", "")
    if server:
        findings.append(_finding(
            rule="OWASP-CONF-001", severity="info", confidence=0.9,
            title="Server header discloses software",
            description=(
                f"The 'Server' response header reveals the web server/version "
                f"('{server[:120]}'), easing version-based attack."
            ),
            evidence={"server": server[:120]},
            remediation=(
                "Remove or obfuscate the Server header; disable the version token."
            ),
            url=url,
        ))
    xpb = headers_lc.get("x-powered-by", "")
    if xpb:
        findings.append(_finding(
            rule="OWASP-CONF-002", severity="info", confidence=0.9,
            title="X-Powered-By header reveals framework",
            description=(
                f"The 'X-Powered-By' header exposes the framework ('{xpb[:120]}'), "
                "narrowing the attack surface for known vulns."
            ),
            evidence={"x_powered_by": xpb[:120]},
            remediation="Remove the X-Powered-By header.",
            url=url,
        ))

    if _DIRECTORY_LISTING_RE.search(body):
        findings.append(_finding(
            rule="OWASP-CONF-004", severity="medium", confidence=0.85,
            title="Directory listing exposed",
            description=(
                "The server returned a directory index, revealing the folder "
                "structure and file names to attackers."
            ),
            evidence={"sample": _match_sample(_DIRECTORY_LISTING_RE, body)},
            remediation=(
                "Disable directory listing (Options -Indexes) and serve only "
                "intended files."
            ),
            url=url,
        ))

    # Debug/dev endpoint present among crawled URLs (no extra request).
    deb = _debug_endpoint_from_url(url)
    if deb:
        findings.append(_finding(
            rule="OWASP-CONF-003", severity=deb[1], confidence=0.8,
            title=f"Sensitive endpoint exposed: {deb[0]}",
            description=(
                f"The crawled page maps to {deb[0]}, a debug/admin surface that "
                "should never be publicly reachable."
            ),
            evidence={"endpoint": deb[0]},
            remediation=(
                "Restrict access to debug/admin endpoints (network allow-list) or "
                "remove them from production."
            ),
            url=url,
        ))

    # ---- A09 Insufficient logging & monitoring ----------------------------
    internal = _internal_error_markers(body)
    if internal:
        findings.append(_finding(
            rule="OWASP-MONITOR-001", severity="medium", confidence=0.7,
            title="Verbose internal error disclosed",
            description=(
                f"Response contains an internal error/stack trace "
                f"('{internal[0]}'). Exposing internals to clients impedes "
                "safe logging & monitoring and leaks implementation detail."
            ),
            evidence={"markers": internal[:3], "sample": _match_sample(
                re.compile("|".join(p for p, _ in _INTERNAL_ERROR_PATTERNS), re.I | re.S),
                body,
            )},
            remediation=(
                "Sanitize error output for clients (generic message), log the "
                "real error server-side, and enable monitoring/alerting on "
                "error rates."
            ),
            url=url,
        ))

    return findings


# ---------------------------------------------------------------------------
# Cookie attribute analysis (A07 / A02)
# ---------------------------------------------------------------------------

def _cookie_attribute_findings(
    headers_lc: dict[str, str], url: str,
) -> list[dict[str, Any]]:
    """Emit findings for session cookies lacking HttpOnly / Secure / SameSite.

    ``set-cookie`` may be a single combined header; we only flag when an
    attribute is entirely absent (conservative — avoids flagging a mix).
    """
    findings: list[dict[str, Any]] = []
    set_cookie = headers_lc.get("set-cookie", "")
    if not set_cookie:
        return findings

    is_https = url.lower().startswith("https://")

    if not _HTTPONLY_RE.search(set_cookie):
        findings.append(_finding(
            rule="OWASP-AUTH-001", severity="high", confidence=0.75,
            title="Session cookie not marked HttpOnly",
            description=(
                "Set-Cookie does not set HttpOnly, so JavaScript can read the "
                "session cookie — an XSS can exfiltrate it."
            ),
            evidence={"set_cookie": _cookie_sample(set_cookie)},
            remediation="Add HttpOnly to session cookies.",
            url=url,
        ))

    if is_https and not _SECURE_RE.search(set_cookie):
        findings.append(_finding(
            rule="OWASP-AUTH-002", severity="high", confidence=0.75,
            title="Session cookie not marked Secure",
            description=(
                "Set-Cookie does not set the Secure flag, so the cookie can be "
                "sent over plaintext HTTP and be intercepted."
            ),
            evidence={"set_cookie": _cookie_sample(set_cookie)},
            remediation="Add Secure (and HSTS) to session cookies.",
            url=url,
        ))

    if _SAMESITE_NONE_RE.search(set_cookie) and not _SAMESITE_NONE_INSECURE_RE.search(set_cookie):
        findings.append(_finding(
            rule="OWASP-CSRF-004", severity="high", confidence=0.8,
            title="SameSite=None cookie without Secure",
            description=(
                "A cookie is set with SameSite=None but not Secure. Browsers "
                "reject it (so it may be dropped) and it disables same-site "
                "CSRF protections when combined with insecure transport."
            ),
            evidence={"set_cookie": _cookie_sample(set_cookie)},
            remediation="Set SameSite=None only together with Secure.",
            url=url,
        ))

    if not _SAMESITE_RE.search(set_cookie) and _has_session_like_cookie(set_cookie):
        findings.append(_finding(
            rule="OWASP-CSRF-003", severity="medium", confidence=0.6,
            title="Session cookie missing SameSite attribute",
            description=(
                "This site sets cookies without SameSite, leaving the browser "
                "to default behaviour — weaker CSRF protection than an explicit "
                "Lax/Strict policy."
            ),
            evidence={"set_cookie": _cookie_sample(set_cookie)},
            remediation="Set SameSite=Lax (or Strict) on session cookies.",
            url=url,
        ))

    return findings


_SAMESITE_RE = re.compile(r"\bsamesite\s*=", re.I)
_SESSION_LIKE_COOKIE_RE = re.compile(
    r"(?:session|auth|token|login|jwt|sid|phpsessid|jsessionid)", re.I,
)


def _has_session_like_cookie(set_cookie: str) -> bool:
    """True when the first cookie's name looks session-shaped."""
    return bool(_SESSION_LIKE_COOKIE_RE.search(set_cookie.split(";")[0]))


def _cookie_sample(set_cookie: str) -> str:
    first = set_cookie.split(",")[0] if "," in set_cookie else set_cookie
    return first[:160]


# ---------------------------------------------------------------------------
# CSRF analysis (A04)
# ---------------------------------------------------------------------------

def _csrf_findings(url: str, body: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    page_host = (urlparse(url).hostname or "").lower()

    # Whole-page CSRF token presence (meta csrf or any token input).
    page_has_token = bool(_META_CSRF_RE.search(body)) or bool(_INPUT_CSRF_RE.search(body))

    for m in _FORM_RE.finditer(body):
        attrs = m.group(1)
        form_inner = m.group(2)
        method = (_FORM_METHOD_RE.search(attrs).group(1).lower()
                  if _FORM_METHOD_RE.search(attrs) else "")
        if method in _GET_METHODS:
            continue  # GET forms are not state-changing

        token_input = _INPUT_CSRF_RE.search(form_inner)
        if not token_input:
            token_input = _META_CSRF_RE.search(form_inner)

        # A4.2 — determine cross-origin action first so a form with neither a
        # token nor a same-origin action loses neither signal.
        action = (_FORM_ACTION_RE.search(attrs).group(1)
                  if _FORM_ACTION_RE.search(attrs) else "")
        action_parsed = urlparse(action)
        action_host = (action_parsed.hostname or "").lower()
        cross_origin = bool(action_host) and action_host != page_host

        # A4.1 — form lacks any CSRF token.
        if not token_input and not page_has_token:
            evidence = {
                "forms_without_token": 1,
                "method": method.upper() or "POST",
                "action": action,
            }
            findings.append(_finding(
                rule="OWASP-CSRF-001", severity="medium", confidence=0.6,
                title="State-changing form without CSRF token",
                description=(
                    f"A {method.upper() or 'POST'} form is submitted without any "
                    "CSRF token (and no page-level token), leaving state-changing "
                    "actions vulnerable to cross-site request forgery."
                ),
                evidence=evidence,
                remediation=(
                    "Include an unguessable CSRF token per session/request and "
                    "validate it server-side (and set SameSite cookies)."
                ),
                url=url,
            ))

        # A4.2 — cross-origin form action (POSTing data to a foreign origin).
        if cross_origin:
            findings.append(_finding(
                rule="OWASP-CSRF-002", severity="low", confidence=0.6,
                title="Form posts data to a cross-origin destination",
                description=(
                    f"The form action points to '{action_host}' while the page "
                    "is served from '{page_host}' — a cross-site data flow that "
                    "should be audited for CSRF/exfiltration risk."
                ),
                evidence={"action": action, "action_host": action_host},
                remediation=(
                    "Keep same-origin form actions and add CSRF tokens for any "
                    "state-changing POST."
                ),
                url=url,
            ))

        break  # only inspect the first state-changing form

    return findings


# ---------------------------------------------------------------------------
# Deserialization markers (A08)
# ---------------------------------------------------------------------------

def _deserialization_markers(body: str) -> list[str]:
    found: list[str] = []
    for pattern, label in _DESERIALIZATION_MARKERS:
        if re.search(pattern, body):
            found.append(label)
    return found


# ---------------------------------------------------------------------------
# Internal-error / misconfig helpers (A05 / A09)
# ---------------------------------------------------------------------------

def _internal_error_markers(body: str) -> list[str]:
    found: list[str] = []
    for pattern, label in _INTERNAL_ERROR_PATTERNS:
        if re.search(pattern, body, re.I | re.S):
            found.append(label)
    return found


def _debug_endpoint_from_url(url: str) -> tuple[str, str] | None:
    """Return (label, severity) if a crawled URL maps to a sensitive endpoint."""
    path = urlparse(url).path.rstrip("/")
    for endpoint, label, severity in _SENSITIVE_ENDPOINTS:
        ep = endpoint.rstrip("/")
        if path == ep or path.startswith(ep + "/"):
            return label, severity
    return None


def _form_signature(body: str) -> str:
    """Return a short excerpt around the first password field."""
    idx = body.lower().find('type="password"')
    if idx == -1:
        idx = body.lower().find("type='password'")
    if idx == -1:
        return ""
    return body[max(0, idx - 120):idx + 40].replace("\n", " ")[:160]


def _match_sample(pattern: re.Pattern, body: str) -> str:
    m = pattern.search(body)
    return m.group(0)[:160] if m else ""


# ---------------------------------------------------------------------------
# Active probe: sensitive endpoint reachability (read-only GET)
# ---------------------------------------------------------------------------

# Set of endpoints probed actively (subset of _SENSITIVE_ENDPOINTS to bound
# requests; the rest are only flagged when the crawler happens to visit them).
_PROBE_ENDPOINTS: list[tuple[str, str, str]] = [
    ("/actuator/env", "Spring Boot Actuator env", "high"),
    ("/phpinfo.php", "PHP info page", "high"),
    ("/phpmyadmin", "phpMyAdmin", "high"),
    ("/swagger-ui/index.html", "Swagger UI", "medium"),
    ("/adminer.php", "Adminer DB tool", "high"),
    ("/server-status", "Apache server-status", "medium"),
]


async def probe_owasp_endpoints(
    client: Any,
    origin: str,
    *,
    additional: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Probe a small allow-list of sensitive endpoints on the base origin.

    Read-only GET requests. A 2xx means the debug/admin surface is publicly
    reachable (high); a 401/403 means it exists but is gated (info). The
    ``additional`` endpoints let a caller extend the allow-list.
    """
    findings: list[dict[str, Any]] = []
    endpoints = list(_PROBE_ENDPOINTS)
    for ep in additional or []:
        endpoints.append((ep, ep, "medium"))

    for endpoint, label, _sev in endpoints:
        url = origin.rstrip("/") + endpoint
        try:
            resp = await client.get(url)
        except Exception:  # noqa: BLE001 — best effort, never fail the scan
            continue
        code = int(getattr(resp, "status", 0) or 0)
        if code == 200:
            findings.append(_finding(
                rule="OWASP-CONF-003", severity="high", confidence=0.9,
                title=f"Sensitive endpoint exposed: {label}",
                description=(
                    f"GET {endpoint} returned 200 — the debug/admin surface "
                    f"'{label}' is publicly reachable."
                ),
                evidence={"endpoint": endpoint, "status": code},
                remediation=(
                    "Restrict access to debug/admin endpoints or remove them "
                    "from production."
                ),
                url=url,
            ))
        elif code in (401, 403):
            findings.append(_finding(
                rule="OWASP-CONF-003", severity="info", confidence=0.6,
                title=f"Sensitive endpoint reachable but gated: {label}",
                description=(
                    f"GET {endpoint} returned {code} — the endpoint exists but is "
                    "gate/behind authentication, which is acceptable but should "
                    "be reviewed."
                ),
                evidence={"endpoint": endpoint, "status": code},
                remediation="Ensure the gateway enforces authentication/authorization.",
                url=url,
            ))
    return findings


# ---------------------------------------------------------------------------
# Active probe: HTTP-method audit (A05 security misconfiguration)
# ---------------------------------------------------------------------------

# Mutating / state-changing verbs that should normally be disabled for public
# web resources. When advertised by OPTIONS they are a misconfiguration (A05).
_UNAUTHORIZED_METHODS: set[str] = {"PUT", "DELETE", "PATCH", "PROPFIND", "MKCOL"}

# TRACE/TRACK reflect the request back verbatim — the basis of Cross-Site
# Tracing (XST) and a classic reasons a server should reject them.
_TRACE_METHODS = ("TRACE", "TRACK")


async def probe_http_methods(client: Any, origin: str) -> list[dict[str, Any]]:
    """Audit the base origin for unsafe / unnecessary HTTP methods (A05).

    Read-only: a single OPTIONS request reads the ``Allow``/``Access-Control-Allow-Methods``
    header, and a single TRACE request confirms trace reflection. No mutating
    request (PUT/DELETE/PATCH) is ever sent.
    """
    findings: list[dict[str, Any]] = []
    base = origin.rstrip("/")

    options = None
    try:
        options = await client.request("OPTIONS", base + "/")
    except Exception as exc:  # noqa: BLE001 — best effort, never fail the scan
        log_owasp.warning("OPTIONS probe failed for %s: %s", origin, exc)

    if options is not None:
        code = int(getattr(options, "status", 0) or 0)
        if 200 <= code < 300:
            allow = (getattr(options, "headers", {}) or {}).get("allow", "")
            cors = (getattr(options, "headers", {}) or {}).get(
                "access-control-allow-methods", ""
            )
            advertised = {
                m.strip().upper()
                for m in (allow + "," + cors).split(",") if m.strip()
            }
            forbidden = sorted(advertised & _UNAUTHORIZED_METHODS)
            if forbidden:
                findings.append(_finding(
                    rule="OWASP-CONF-005", severity="medium", confidence=0.7,
                    title="Unsafe HTTP methods advertised: " + ", ".join(forbidden),
                    description=(
                        f"{base}/ advertises state-changing HTTP method(s) "
                        f"({', '.join(forbidden)}) that should not be exposed "
                        "to anonymous clients."
                    ),
                    evidence={"methods": forbidden, "allow": allow, "status": code},
                    remediation=(
                        "Disable PUT/DELETE/PATCH/PROPFIND on public resources; "
                        "enable only GET/HEAD/POST and restrict state-changing "
                        "verbs behind authentication."
                    ),
                    url=base + "/",
                ))

    trace = None
    try:
        trace = await client.request("TRACE", base + "/")
    except Exception as exc:  # noqa: BLE001 — best effort
        log_owasp.warning("TRACE probe failed for %s: %s", origin, exc)

    if trace is not None:
        code = int(getattr(trace, "status", 0) or 0)
        reflected = (getattr(trace, "body", "") or "")
        if 200 <= code < 300 or reflected:
            findings.append(_finding(
                rule="OWASP-CONF-006", severity="medium", confidence=0.75,
                title="HTTP TRACE / TRACK method enabled (XST risk)",
                description=(
                    f"{base}/ responds to TRACE (status {code}). Reflecting the "
                    "request verbatim enables Cross-Site Tracing, letting an "
                    "attacker read HttpOnly cookies and other headers."
                ),
                evidence={"status": code, "reflected": bool(reflected)},
                remediation=(
                    "Disable the TRACE/TRACK methods at the web server rewrite "
                    "layer; they are not needed for production sites."
                ),
                url=base + "/",
            ))

    return findings


# ---------------------------------------------------------------------------
# Active probe: admin / login auth-surface reachability (A01 / A07)
# ---------------------------------------------------------------------------

# Management / admin panels that must never be reachable unauthenticated. A 200
# means the panel is exposed (Broken Access Control / Broken Authentication).
_ADMIN_PANELS: list[tuple[str, str]] = [
    ("/admin", "admin panel"),
    ("/administrator", "admin panel"),
    ("/wp-admin", "WordPress admin"),
    ("/console", "application console"),
    ("/cpanel", "cPanel"),
    ("/manager/html", "Tomcat manager"),
    ("/jenkins", "Jenkins CI"),
    ("/orion", "JBoss admin console"),
    ("/solr", "Solr admin"),
    ("/grafana", "Grafana dashboard"),
]

# Login surfaces we flag as reachable-but-info (they exist; whether weak auth is
# a flaw is for the caller to judge from the login-page posture).
_LOGIN_SURFACES: list[tuple[str, str]] = [
    ("/login", "login page"),
    ("/signin", "sign-in page"),
    ("/auth", "auth page"),
    ("/wp-login.php", "WordPress login"),
    ("/web-login", "web login page"),
]


async def probe_auth_surfaces(client: Any, origin: str) -> list[dict[str, Any]]:
    """Probe for reachable admin panels and login surfaces on the base origin.

    A 200 on an admin panel is a serious Broken Access / Authentication signal
    (high); a 200 on a login surface is informational (low) — the presence of a
    login is normal. Best-effort: any exception is swallowed so the scan never
    fails.
    """
    findings: list[dict[str, Any]] = []
    base = origin.rstrip("/")

    for path, label in _ADMIN_PANELS:
        url = base + path
        try:
            resp = await client.get(url)
        except Exception:  # noqa: BLE001 — best effort
            continue
        code = int(getattr(resp, "status", 0) or 0)
        if code == 200:
            findings.append(_finding(
                rule="OWASP-AUTH-004", severity="high", confidence=0.85,
                title=f"Admin/management panel publicly reachable: {label}",
                description=(
                    f"GET {path} returned 200 without authentication — the "
                    f"{label} is exposed, enabling privilege escalation / "
                    "configuration takeover by anonymous attackers."
                ),
                evidence={"endpoint": path, "status": code, "panel": label},
                remediation=(
                    "Restrict admin panels to a network allow-list, enforce "
                    "strong authentication, remove the panel from the public "
                    "origin, or disable it in production."
                ),
                url=url,
            ))
        elif code in (401, 403):
            findings.append(_finding(
                rule="OWASP-AUTH-004", severity="info", confidence=0.55,
                title=f"Admin panel exists but is gated: {label}",
                description=(
                    f"GET {path} returned {code} — the panel exists but is "
                    "behind authentication. Review that the gateway enforces "
                    "RBAC and MFA."
                ),
                evidence={"endpoint": path, "status": code, "panel": label},
                remediation=(
                    "Ensure the panel enforces MFA + RBAC and network "
                    "restrictions; remove it from the public origin if unused."
                ),
                url=url,
            ))

    for path, label in _LOGIN_SURFACES:
        url = base + path
        try:
            resp = await client.get(url)
        except Exception:  # noqa: BLE001 — best effort
            continue
        code = int(getattr(resp, "status", 0) or 0)
        if code == 200:
            findings.append(_finding(
                rule="OWASP-AUTH-005", severity="low", confidence=0.5,
                title=f"Login surface reachable: {label}",
                description=(
                    f"GET {path} returned 200 — a login form is exposed. "
                    "Verify MFA / lockout / rate limiting and secure session "
                    "cookies (HttpOnly, Secure, SameSite)."
                ),
                evidence={"endpoint": path, "status": code},
                remediation=(
                    "Enforce MFA, account lockout and rate limiting on login; "
                    "set HttpOnly + Secure + SameSite cookies and rotate "
                    "sessions."
                ),
                url=url,
            ))

    return findings


# ---------------------------------------------------------------------------
# Shared OWASP posture stage (website engine + link orchestrator)
# ---------------------------------------------------------------------------

async def run_owasp_posture(
    pages: list[dict[str, Any]],
    *,
    origin: str,
    headers: dict[str, str],
    cookies: dict[str, str],
    request_timeout: float = 10.0,
    rate_limit: int = 10,
    max_concurrency: int = 3,
) -> list[dict[str, Any]]:
    """Run the full live OWASP posture stage for a set of crawled pages.

    * Passive: ``analyze_page_owasp`` + ``analyze_webapp`` on every page.
    * Active:  a single read-only HttpClient drives the admin/endpoint
      allow-list, HTTP-method audit, auth-surface, directory-traversal and
      TLS checks against ``origin``.

    Best-effort: active probing is wrapped so a failure never fails the scan.
    """
    findings: list[dict[str, Any]] = []
    for page in pages:
        findings.extend(analyze_page_owasp(page))
        findings.extend(analyze_webapp(page))

    base = (origin or "").rstrip("/")
    try:
        async with HttpClient(
            timeout=request_timeout,
            headers=headers,
            cookies=cookies,
            rate_limit=int(rate_limit),
            max_concurrency=int(max_concurrency),
        ) as client:
            findings.extend(await probe_owasp_endpoints(client, base))
            findings.extend(await probe_http_methods(client, base))
            findings.extend(await probe_auth_surfaces(client, base))
            findings.extend(await probe_webapp_directory_traversal(client, base))
            findings.extend(await probe_webapp_tls(base))
    except Exception as exc:  # noqa: BLE001 — owasp posture must never fail scan
        log_owasp.warning("owasp active posture probe failed for %s: %s", base, exc)

    return findings


# ---------------------------------------------------------------------------
# Finding factory
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
