"""Live OWASP Top 10 classic web-application vulnerability posture checks
(app/engines/live_webapp.py).

Companion to app/engines/live_owasp.py. Reuses the same active-probe and
passive-analysis pattern and is wired into the website engine's
_owasp_stage() alongside the OWASP posture engine.

Coverage map — OWASP Top 10 classic (20 items):
  #1  SQL Injection ..................... SQLI-LIVE           (live_owasp)
  #2  XSS ............................... XS-LIVE             (live_owasp)
  #3  Information Leakage ............... OWASP-MONITOR-001   (live_owasp)
  #4  Frame Injection ................... OWASP-CONF-008      (this module)
  #5  Open Redirect ..................... OWASP-CONF-007      (this module, passive)
  #6  Missing Session Timeout ........... OWASP-AUTH-006      (this module)
  #7  Sensitive Info in GET URL ......... OWASP-SENSITIVE-002 (this module)
  #8  Session Cookie Not Secure ......... OWASP-AUTH-002      (live_owasp)
  #9  XFS ............................... XS-LIVE             (live_owasp)
  #10 Sensitive Info Clear Text ......... OWASP-SENSITIVE-003 (this module)
  #11 Sensitive Info Cached ............. OWASP-SENSITIVE-004 (this module)
  #12 Inadequate Encryption Strength .... OWASP-SENSITIVE-005 + TLS probe (this module)
  #13 CRLF Injection .................... NUCLEUS-CRLF-INJECTION (live_owasp)
  #14 Trust Boundary .................... requires source-code / design review
  #15 Directory Traversal ............... OWASP-CONF-009 + active probe (this module)
  #16 Session Fixation .................. OWASP-AUTH-007      (this module)
  #17 Risky Crypto Algorithm ............ source review; transport covered by OWASP-SENSITIVE-005
  #18 Credentials Management ............ DISC / NUCLEUS-SENSITIVE-DATA (program mode)
  #19 SQL Injection Hibernate ........... SQLI-LIVE / SQLI006 (live_owasp)
  #20 Improper Resource Shutdown ........ requires runtime / design review
"""

from __future__ import annotations

import asyncio
import re
import socket
import ssl
from datetime import UTC
from typing import Any
from urllib.parse import parse_qs, urlparse

from app.utils.logger import get_logger

log = get_logger("webapp")


def _h(headers: dict[str, Any], name: str) -> Any:
    """Case-insensitive header lookup.

    The crawler stores page headers with LOWERCASE keys (crawler.py builds
    ``{k.lower(): v}``), but passive checks historically read title-case keys
    (``X-Frame-Options``, ``Cache-Control``, ``Set-Cookie`` …) — which never
    matched, silently disabling those checks. Look up by lowercasing both
    sides so header-based findings actually fire.
    """
    if not headers:
        return None
    low = name.lower()
    for key, value in headers.items():
        if str(key).lower() == low:
            return value
    return None

REDIRECT_PARAMS = frozenset(
    {
        "redirect",
        "url",
        "next",
        "returnurl",
        "goto",
        "forward",
        "return",
        "redirect_uri",
        "redirecturl",
        "logout",
        "continue",
        "returnpath",
        "ref",
        "dest",
        "target",
        "callback",
    }
)

SENSITIVE_PARAM_NAMES = frozenset(
    {
        "token",
        "key",
        "secret",
        "password",
        "passwd",
        "pwd",
        "auth",
        "apikey",
        "api_key",
        "session",
        "sid",
        "cc",
        "cvv",
        "ssn",
        "credit",
        "card",
        "email",
        "phone",
        "dob",
        "user",
        "username",
        "access_token",
        "refresh_token",
    }
)

_SESSION_ID_PARAMS = frozenset(
    {
        "phpsessionid",
        "jsessionid",
        "sessionid",
        "asp.net_sessionid",
        "sid",
        "cfid",
        "cftoken",
    }
)

_SENSITIVE_NAMES = frozenset(
    {"password", "passwd", "pwd", "cc", "cvv", "credit", "card"}
)

_FILE_READ_INDICATORS = (
    "root:x:",
    "root:*",
    "Administrator:",
    "win.ini",
    "boot.ini",
    "command.com",
    "system32",
    "sensitive",
)

_CC_DIGIT = re.compile(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b")
_SSN = re.compile(r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b")
_PASSWORD_INPUT = re.compile(r'<input[^>]*type=["\']?password["\']?', re.IGNORECASE)


def _finding(
    rule: str,
    severity: str,
    confidence: float,
    title: str,
    description: str,
    evidence: dict[str, Any],
    remediation: str,
    location: str,
) -> dict[str, Any]:
    return {
        "rule": rule,
        "severity": severity,
        "confidence": confidence,
        "title": title,
        "description": description,
        "evidence": evidence,
        "remediation": remediation,
        "location": location,
    }


def analyze_webapp(page: dict[str, Any]) -> list[dict[str, Any]]:
    """Passive OWASP Top 10 checks on a single crawled page.

    Only 2xx text/html pages are analyzed; everything else returns an empty
    list (mirrors analyze_page_owasp).
    """
    findings: list[dict[str, Any]] = []
    status = page.get("status", 0)
    content_type = page.get("content_type", "")
    if status < 200 or status >= 300 or "text/html" not in content_type:
        return findings

    url = page.get("url", "")
    body = page.get("body", "") or ""
    headers = page.get("headers") or {}
    findings.extend(_check_open_redirect(url, body))
    findings.extend(_check_sensitive_url_params(url))
    findings.extend(_check_frame_injection(body, url, headers))
    findings.extend(_check_clear_text_sensitive(body))
    findings.extend(_check_sensitive_cached(body, headers, url))
    findings.extend(_check_session_fixation(url))
    findings.extend(_check_session_timeout(headers))
    return findings


def _check_open_redirect(url: str, body: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    try:
        parsed = urlparse(url)
    except Exception:
        return findings
    qp = parse_qs(parsed.query, keep_blank_values=True)
    for param in qp:
        if param.lower() in REDIRECT_PARAMS:
            value = qp[param][0] if qp[param] else ""
            reflected = value and value in body
            findings.append(
                _finding(
                    "OWASP-CONF-007",
                    "medium",
                    0.60 if reflected else 0.50,
                    "Open Redirect / URL Redirection",
                    f"Open redirect parameter '{param}' present in URL."
                    " Reflection in page body raises confidence.",
                    {"parameter": param, "reflected": reflected},
                    "Validate and whitelist redirect targets; avoid reflecting"
                    " user-supplied redirect values.",
                    url,
                )
            )
    return findings


def _check_sensitive_url_params(url: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    try:
        parsed = urlparse(url)
    except Exception:
        return findings
    qp = parse_qs(parsed.query, keep_blank_values=True)
    for param in qp:
        if param.lower() in SENSITIVE_PARAM_NAMES:
            findings.append(
                _finding(
                    "OWASP-SENSITIVE-002",
                    "medium",
                    0.60,
                    "Sensitive Information Exposed in GET Parameter",
                    f"Sensitive parameter '{param}' exposed in the URL query string."
                    " URL parameters are logged, bookmarked, and leaked via"
                    " Referer headers.",
                    {"parameter": param},
                    "Move sensitive data to POST body / headers; never put"
                    " tokens, passwords, or PII in the query string.",
                    url,
                )
            )
    return findings


def _check_frame_injection(body: str, url: str, headers: dict[str, str]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    xfo = (_h(headers, "X-Frame-Options") or "").strip()
    has_csp_fa = bool(
        re.search(r"frame-ancestors", _h(headers, "Content-Security-Policy") or "", re.IGNORECASE)
    )
    clickjacking = not (xfo or has_csp_fa)
    for m in re.finditer(r"<iframe[^>]*>", body, re.IGNORECASE):
        tag = m.group(0)
        src_m = re.search(r'src=["\']([^"\']*)["\']', tag, re.IGNORECASE)
        src = src_m.group(1) if src_m else ""
        if (
            src.lower().startswith("javascript:")
            or src.lower().startswith("data:")
            or src.strip() == ""
        ):
            findings.append(
                _finding(
                    "OWASP-CONF-008",
                    "high",
                    0.55,
                    "Frame Injection / Clickjacking Vector",
                    f"Dynamic <iframe src='{src}' found."
                    + (
                        " No clickjacking protections detected (no X-Frame-Options"
                        " nor CSP frame-ancestors)."
                        if clickjacking
                        else " Site-level X-Frame-Options/CSP protections are"
                        " in place but the dynamic src is a risk (javascript:/data:"
                        " URIs or empty) and should be sanitised."
                    ),
                    {"src": src, "clickjacking": clickjacking},
                    "Add X-Frame-Options: DENY/SAMEORIGIN and a CSP"
                    " frame-ancestors directive; sanitize iframe src values.",
                    url,
                )
            )
    return findings


def _check_clear_text_sensitive(body: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if _CC_DIGIT.search(body):
        findings.append(
            _finding(
                "OWASP-SENSITIVE-003",
                "high",
                0.35,
                "Sensitive Data Exposed in Clear Text (Credit Card)",
                "A credit-card-like pattern was echoed in HTML.",
                {"pattern": "credit_card"},
                "Do not echo card numbers in HTML; tokenize and mask."
                " Comply with PCI DSS.",
                "",
            )
        )
    if _SSN.search(body):
        findings.append(
            _finding(
                "OWASP-SENSITIVE-003",
                "high",
                0.35,
                "Sensitive Data Exposed in Clear Text (SSN)",
                "A Social-Security-Number-like pattern was echoed in HTML.",
                {"pattern": "ssn"},
                "Do not echo SSNs in HTML; mask or remove entirely.",
                "",
            )
        )
    return findings


def _check_sensitive_cached(body: str, headers: dict[str, str], url: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    has_sensitive_form = bool(_PASSWORD_INPUT.search(body))
    if not has_sensitive_form:
        return findings
    cache_control = (_h(headers, "Cache-Control") or "").lower()
    pragma = (_h(headers, "Pragma") or "").lower()
    nocache = ("no-cache" in cache_control) or ("no-cache" in pragma)
    nostore = "no-store" in cache_control
    cc_raw = _h(headers, "Cache-Control") or ""
    pragma_raw = _h(headers, "Pragma") or ""
    if not (nocache and nostore):
        findings.append(
            _finding(
                "OWASP-SENSITIVE-004",
                "medium",
                0.50,
                "Sensitive Information Cached by Browser",
                f"Page contains a password form but lacks Cache-Control:"
                f" no-store/no-cache (Cache-Control='{cc_raw}', Pragma='{pragma_raw}').",
                {"cache_control": cc_raw,
                 "pragma": pragma_raw},
                "Set Cache-Control: no-store, no-cache, must-revalidate and"
                " Pragma: no-cache on pages with sensitive inputs.",
                url,
            )
        )
    return findings


def _check_session_fixation(url: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    try:
        parsed = urlparse(url)
    except Exception:
        return findings
    qp = parse_qs(parsed.query, keep_blank_values=True)
    for param in qp:
        if param.lower() in _SESSION_ID_PARAMS:
            findings.append(
                _finding(
                    "OWASP-AUTH-007",
                    "medium",
                    0.70,
                    "Session Fixation via URL Parameter",
                    f"Session identifier parameter '{param}' transmitted in the URL."
                    " Attacker can force a known session id.",
                    {"parameter": param},
                    "Generate a new session id after login; never accept"
                    " session ids from the URL.",
                    url,
                )
            )
    return findings


def _check_session_timeout(headers: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    # Set-Cookie can arrive as a comma-joined string (crawler stores lowercase,
    # httpx merges multiple headers) OR as a raw list (unit tests / other
    # callers). Accept both.
    raw = _h(headers, "Set-Cookie")
    if isinstance(raw, (list, tuple)):
        raw = ",".join(str(v) for v in raw)
    raw = str(raw or "")
    for cookie in re.split(r",\s*(?=[^\s;,=]+=)", raw):
        name = cookie.split(";", 1)[0].split("=", 1)[0].strip().lower()
        _session_name_match = (
            "sessionid", "session", "sid", "jsessionid", "phpsessid"
        )
        if any(s == name for s in _session_name_match):
            raw_lower = cookie.lower()
            has_max_age = "max-age=" in raw_lower or "max-age =" in raw_lower
            has_expires = "expires=" in raw_lower
            if not (has_max_age or has_expires):
                name = cookie.split(";", 1)[0].split("=", 1)[0].strip()
                findings.append(
                    _finding(
                        "OWASP-AUTH-006",
                        "low",
                        0.40,
                        "Session Cookie Lacks Explicit Timeout",
                        f"Session cookie '{name}' has no Max-Age or Expires."
                        " Browsers may keep it indefinitely.",
                        {"cookie": name},
                        "Set a short Max-Age / Expires on session cookies"
                        " and rotate them after inactivity.",
                        "",
                    )
                )
    return findings


async def probe_webapp_directory_traversal(
    client: Any, origin: str,
) -> list[dict[str, Any]]:
    """Active directory-traversal probe against the base origin.

    Best-effort: sends path-traversal payloads and looks for file-read
    indicators in the response body. Exceptions are swallowed so the scan
    never fails.
    """
    findings: list[dict[str, Any]] = []
    base = origin.rstrip("/")
    payloads = ["/..%2f..%2fetc%2fpasswd", "/..%5c..%5cetc%5cpasswd"]
    for payload in payloads:
        url = base + payload
        try:
            resp = await client.get(url)
        except Exception:  # noqa: BLE001
            continue
        if resp.status == 0:
            continue
        body_lower = resp.body.lower()
        if any(ind in body_lower for ind in (
            "root:x:", "root:*", "administrator:", "win.ini",
            "boot.ini", "system32", "command.com",
        )):
            findings.append(
                _finding(
                    "OWASP-CONF-009",
                    "high",
                    0.55,
                    "Directory Traversal / Path Disclosure",
                    f"Path-traversal payload '{payload}' returned file-read indicators."
                    f" Response status {resp.status}.",
                    {"payload": payload, "status": resp.status},
                    "Validate and sanitize file-path inputs; use an allow-list"
                    " of permitted files; avoid mapping user input to disk paths.",
                    url,
                )
            )
            break
    return findings


async def probe_webapp_tls(origin: str) -> list[dict[str, Any]]:
    """Active TLS probe: flag weak key sizes, old protocols, expired certs.

    Uses a raw stdlib SSL socket so no HTTP client is required.
    Any failure is swallowed (best-effort).
    """
    info = await asyncio.to_thread(_tls_info, origin)
    if info is None:
        return []
    findings: list[dict[str, Any]] = []
    bits = info.get("bits") or 0
    proto = info.get("protocol", "")
    not_after = info.get("not_after")
    if bits > 0 and bits < 2048:
        findings.append(
            _finding(
                "OWASP-SENSITIVE-005",
                "high",
                0.80,
                "Inadequate Encryption Strength (Weak TLS Key)",
                f"TLS certificate key size is {bits} bits (< 2048).",
                {"bits": bits, "protocol": proto},
                "Upgrade to at least a 2048-bit RSA key or an ECDSA P-256+"
                " key; enforce TLS 1.2+.",
                origin,
            )
        )
    if proto in ("TLSv1", "TLSv1.1"):
        findings.append(
            _finding(
                "OWASP-SENSITIVE-005",
                "high",
                0.80,
                "Inadequate Encryption Strength (Deprecated TLS Protocol)",
                f"Server negotiates deprecated protocol '{proto}'.",
                {"protocol": proto, "bits": bits},
                "Disable TLS 1.0 and 1.1; enforce TLS 1.2 or 1.3.",
                origin,
            )
        )
    if not_after:
        try:
            from datetime import datetime
            # Parse OpenSSL-style date like "May  9 00:00:00 2026 GMT"
            parts = not_after.strip().split()
            # Reassemble into a parseable form
            raw = " ".join(parts)
            dt = datetime.strptime(raw, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
            if dt < datetime.now(UTC):
                findings.append(
                    _finding(
                        "OWASP-SENSITIVE-005",
                        "high",
                        0.80,
                        "Inadequate Encryption Strength (Expired TLS Certificate)",
                        "TLS certificate expired on {}.".format(
                            dt.strftime("%Y-%m-%d")
                        ),
                        {"not_after": not_after},
                        "Renew the TLS certificate before it expires.",
                        origin,
                    )
                )
        except Exception:  # noqa: BLE001
            pass
    return findings


def _tls_info(origin: str) -> dict[str, Any] | None:
    """Synchronously connect to the origin over TLS and return cert details."""
    try:
        parsed = urlparse(origin)
    except Exception:
        return None
    host = parsed.hostname
    if not host:
        return None
    port = parsed.port or 443
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cipher = ssock.cipher()
                bits = cipher[2] if cipher else 0
                peer = ssock.getpeercert() or {}
                return {
                    "protocol": ssock.version(),
                    "bits": bits,
                    "cipher": cipher[0] if cipher else None,
                    "not_after": peer.get("notAfter"),
                }
    except Exception:  # noqa: BLE001
        return None
