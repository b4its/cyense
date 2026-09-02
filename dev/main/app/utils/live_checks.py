"""Live HTTP-observable vulnerability checks for website/link targets.

These are **response-passive** checks: they run over pages the crawler already
retrieved (headers, body, cookies, transport) rather than launching new
requests, so they are cheap and reproducible. Each finding carries its CWE id
for consistent SARIF/CVSS/coverage classification.

Compared to the static CWE rules in ``app/program/security_rules.py`` (which
inspect source code), this module inspects a *live* target's HTTP responses —
covering the server/transport/session side of the broad CWE taxonomy.
"""

from __future__ import annotations

import re
from typing import Any

# Regexes that indicate an unhandled / verbose server error message.
_VERBOSE_ERROR_RE = re.compile(
    r"(?i)traceback \(most recent call last\)|\bstack trace\b|"
    r"(?:^|\s)(?:[a-z0-9_]+\.)+[A-Za-z_]+Exception\b|"
    r"fatal error:|warning:\s*mysql|sqlstate\[|pg_error|"
    r"\bmicrosoft\.(?:net|windows)[a-z.]*(?:exception|stacktrace)|\bdebug\s*=\s*true\b|"
    r"`[^`]{0,60}`\s+<[^>]+>|\bos error\b|\bjava\.lang\.\w+Exception\b|\bundefined index:"
)
_UNHANDLED_ERROR_RE = re.compile(
    r"(?i)sql syntax|you have an error in your sql|mysql_fetch|ora-\d{4,5}|"
    r"division by zero|uncaught (?:exception|error|typeerror)|undefined variable|"
    r"np\.oops|n[0-9]{3,4}\s*\(id=\d|weblogic|jakarta\.servlet"
)
_COOKIE_HDR = "set-cookie"


def check_verbose_errors(body: str, url: str = "") -> list[dict[str, Any]]:
    """Detect verbose stack traces / debug pages (Missing Error Handling, CWE-209)."""
    findings: list[dict[str, Any]] = []
    if not body:
        return findings
    for rule, regex, sev, cwe, title in (
        (
            "VERBOSE-ERROR", _VERBOSE_ERROR_RE, "high", "CWE-209",
            "Stack trace / detail error ter-expose",
        ),
        (
            "UNHANDLED-ERROR", _UNHANDLED_ERROR_RE, "medium", "CWE-391",
            "Pesan error server ter-expose (unhandled)",
        ),
    ):
        m = regex.search(body)
        if m:
            findings.append({
                "rule": rule,
                "severity": sev,
                "confidence": 0.8,
                "cwe": cwe,
                "title": title,
                "description": (
                    f"{title}: respons memuat detail internal "
                    f"`{m.group(0)[:80]}` yang membantu attacker memetakan stack."
                ),
                "evidence": {"match": m.group(0)[:120], "url": url},
                "remediation": (
                    "Nonaktifkan detail debug/stack trace di produksi dan "
                    "tampilkan halaman error generik; log detail di server saja."
                ),
                "location": url,
            })
    return findings


def check_cookie_security(headers: dict[str, str]) -> list[dict[str, Any]]:
    """Inspect Set-Cookie flags (Insufficient Session ID Length, CWE-614/539)."""
    findings: list[dict[str, Any]] = []
    for hdr_key, hdr_val in headers.items():
        if hdr_key.lower() != _COOKIE_HDR:
            continue
        for cookie in _split_cookies(hdr_val):
            name = cookie.split("=", 1)[0].strip()
            if not name:
                continue
            lower = cookie.lower()
            if "httponly" not in lower:
                findings.append(_cookie_flag(
                    name, "HttpOnly", "medium", "CWE-1004",
                    "Cookie tanpa flag HttpOnly — dapat dibaca JavaScript (XSS).",
                    "Tambahkan flag HttpOnly pada cookie sesi.",
                ))
            if "secure" not in lower:
                findings.append(_cookie_flag(
                    name, "Secure", "medium", "CWE-614",
                    "Cookie tanpa flag Secure — dapat bocor lewat kanal HTTP.",
                    "Set flag Secure agar cookie hanya dikirim via HTTPS.",
                ))
            if "samesite" not in lower and "lax" not in lower and "strict" not in lower:
                findings.append(_cookie_flag(
                    name, "SameSite", "low", "CWE-1275",
                    "Cookie tanpa atribut SameSite — rentan CSRF.",
                    "Tetapkan SameSite=Lax/Strict pada cookie sesi.",
                ))
    return findings


def _split_cookies(set_cookie: str) -> list[str]:
    """Split a Set-Cookie header value into individual cookie declarations."""
    return [part.strip() for part in set_cookie.split(",") if "=" in part]


def _cookie_flag(
    name: str, flag: str, severity: str, cwe: str, description: str, remediation: str,
) -> dict[str, Any]:
    return {
        "rule": f"COOKIE-NO-{flag.upper()}",
        "severity": severity,
        "confidence": 0.8,
        "cwe": cwe,
        "title": f"Cookie '{name}' tanpa flag {flag}",
        "description": description,
        "evidence": {"cookie": name, "missing_flag": flag},
        "remediation": remediation,
        "location": "set-cookie",
    }


def check_transport_security(url: str, headers: dict[str, str]) -> list[dict[str, Any]]:
    """Insecure transport (CWE-319) + HSTS (CWE-319/523) issues."""
    findings: list[dict[str, Any]] = []
    scheme = (url or "").split("://", 1)[0].lower()
    header_map = {k.lower(): v for k, v in headers.items()}

    if scheme == "http":
        findings.append({
            "rule": "INSECURE-TRANSPORT",
            "severity": "high",
            "confidence": 0.95,
            "cwe": "CWE-319",
            "title": "Kanal HTTP terang-terangan (tanpa TLS)",
            "description": (
                "Target dilayani lewat HTTP. Data (kredensial, sesi) dapat "
                "disadap atau dimodifikasi di jaringan."
            ),
            "evidence": {"url": url, "scheme": "http"},
            "remediation": "Gunakan HTTPS + HSTS dan redirect HTTP → HTTPS di semua halaman.",
            "location": url,
        })

    if scheme in ("https", "http") and header_map.get("strict-transport-security") is None:
        # On HTTPS, missing HSTS is a real weakness; on HTTP the bigger issue
        # is already flagged above. Only flag HSTS when site is HTTPS-capable.
        if scheme == "https":
            findings.append({
                "rule": "HSTS-MISSING",
                "severity": "medium",
                "confidence": 0.85,
                "cwe": "CWE-523",
                "title": "Strict-Transport-Security tidak diterapkan",
                "description": (
                    "Target HTTPS tidak mengirim header HSTS — rentan "
                    "downgrade/SSL-strip."
                ),
                "evidence": {"url": url, "missing_header": "Strict-Transport-Security"},
                "remediation": (
                    "Terapkan Strict-Transport-Security dengan max-age besar "
                    "dan includeSubDomains."
                ),
                "location": url,
            })

    return findings


def check_allow_methods(headers: dict[str, str]) -> list[dict[str, Any]]:
    """Dangerous HTTP methods advertised (Cross-Site Tracing, CWE-693)."""
    findings: list[dict[str, Any]] = []
    header_map = {k.lower(): v for k, v in headers.items()}
    allow = header_map.get("allow", "")
    acom = header_map.get("access-control-allow-methods", "")
    if "TRACE" in allow.upper() or "TRACE" in acom.upper():
        findings.append({
            "rule": "TRACE-ENABLED",
            "severity": "medium",
            "confidence": 0.8,
            "cwe": "CWE-693",
            "title": "Metode HTTP TRACE diaktifkan",
            "description": (
                "Allow/Access-Control-Allow-Methods mengizinkan TRACE — "
                "Cross-Site Tracing."
            ),
            "evidence": {"allow": allow, "access_control_allow_methods": acom},
            "remediation": "Nonaktifkan TRACE pada web server.",
            "location": "server-headers",
        })
    return findings


def check_x_powered_by(headers: dict[str, str]) -> list[dict[str, Any]]:
    """Framework/tech disclosure via X-Powered-By (Information exposure)."""
    findings: list[dict[str, Any]] = []
    header_map = {k.lower(): v for k, v in headers.items()}
    val = header_map.get("x-powered-by", "")
    if val:
        findings.append({
            "rule": "INFO-X-POWERED-BY",
            "severity": "low",
            "confidence": 0.9,
            "cwe": "CWE-200",
            "title": "X-Powered-By mengungkap teknologi",
            "description": f"X-Powered-By: {val} — bocor stack/framework ke attacker.",
            "evidence": {"header": "X-Powered-By", "value": val[:80]},
            "remediation": "Hapus atau samarkan header X-Powered-By.",
            "location": "server-headers",
        })
    return findings
