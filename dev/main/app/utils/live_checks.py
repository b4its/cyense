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

import asyncio
import re
import socket
import ssl
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

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


# ---------------------------------------------------------------------------
# Active / fingerprint checks for the "native / runtime / platform" families
# that are invisible to static web-source analysis. The accurate approach is
# to fingerprint the *platform* the app runs on (or the served artifact) and
# surface the corresponding native/runtime risk families, and to observe
# server-level things (TLS cert) directly.
# ---------------------------------------------------------------------------


def check_platform_exposure(
    headers: dict[str, str],
    body: str = "",
) -> list[dict[str, Any]]:
    """Fingerprint the runtime/platform so native risk families surface.

    Rather than half-detecting native bugs (JNI, CLR, mobile-code, compiler
    optimization, portability), we detect the platform that hosts native code
    and flag the risk family the reviewer should then assess on that platform.
    """
    findings: list[dict[str, Any]] = []
    hm = {k.lower(): v for k, v in headers.items()}
    powered = hm.get("x-powered-by", "")
    aspnet = hm.get("x-aspnet-version", "")
    server = hm.get("server", "")

    if aspnet or "asp.net" in powered.lower():
        findings.append({
            "rule": "PLATFORM-DOTNET",
            "severity": "info",
            "confidence": 0.9,
            "cwe": "CWE-693",
            "title": "Platform ASP.NET / .NET terdeteksi",
            "description": (
                ".NET/CLR terdeteksi (X-AspNet-Version/X-Powered-By). Periksa "
                "namespace .NET: Full-trust CLR verification issue, insecure "
                "compiler optimization, OWASP .NET research, dan deserialization."
            ),
            "evidence": {"x_aspnet_version": aspnet, "x_powered_by": powered[:60]},
            "remediation": (
                "Terapkan .NET hardening (runtime config, DSC/token validation), "
                "aktifkan mode kompatibilitas/run-time security."
            ),
            "location": "server-headers",
        })

    java_signal = ("jsessionid" in str(headers).lower()
                   or "tomcat" in server.lower()
                   or "java" in powered.lower()
                   or "jsessionid" in (body or "").lower())
    if java_signal:
        findings.append({
            "rule": "PLATFORM-JAVA",
            "severity": "info",
            "confidence": 0.8,
            "cwe": "CWE-859",
            "title": "Platform Java (JVM/servlet container) terdeteksi",
            "description": (
                "Java/JVM terdeteksi (JSESSIONID/Tomcat). Periksa namespace "
                "Java-native: unsafe JNI, unsafe mobile code, unsafe function "
                "call dari signal handler, dan insecure deserialization."
            ),
            "evidence": {"server": server[:60]},
            "remediation": "Terapkan Java hardening dan reviu binding native (JNI).",
            "location": "server-headers",
        })

    if "php" in powered.lower() or "phpsessid" in str(headers).lower():
        findings.append({
            "rule": "PLATFORM-PHP",
            "severity": "info",
            "confidence": 0.85,
            "cwe": "CWE-889",
            "title": "Platform PHP terdeteksi",
            "description": (
                "PHP terdeteksi (X-Powered-By/PHPSESSID). Periksa namespace PHP: "
                "PHP object injection, unsafe mobile code analog, portability flaw."
            ),
            "evidence": {"x_powered_by": powered[:60]},
            "remediation": "Perkuat konfigurasi PHP (open_basedir, disable_functions, hardening).",
            "location": "server-headers",
        })

    return findings


def check_follina(body: str, url: str = "") -> list[dict[str, Any]]:
    """Content signature for the Follina (CVE-2022-30190) MSDT payload.

    Follina ships a Word/RTF document whose external OLE relationship points at
    a remote HTML shell that invokes ``ms-msdt:``. We flag the descriptor bytes
    rather than executing anything.
    """
    findings: list[dict[str, Any]] = []
    lower = (body or "").lower()
    is_office = ("word/document.xml" in lower or "w:document" in lower
                 or "\\rtf" in lower or "word/_rels/document.xml.rels" in lower
                 or body[:2] == b"PK")
    if not is_office:
        return findings
    if ("ms-msdt:" in lower or "word/_rels/document.xml.rels" in lower
            or ("\\object" in lower and "\\objdata" in lower)
            or ("target=\"_external\"" in lower and "http" in lower
                and "msdt" in lower)):
        findings.append({
            "rule": "FOLLINA",
            "severity": "high",
            "confidence": 0.7,
            "cwe": "CWE-94",
            "title": "Payload Follina (CVE-2022-30190) terdeteksi",
            "description": (
                "Kandungan dokumen Office/RTF memuat relationship OLE eksternal "
                "dan/atau URI ms-msdt — pola exploit Follina di Microsoft Office."
            ),
            "evidence": {"url": url, "match": "external OLE + ms-msdt"},
            "remediation": (
                "Blokir lampiran office dengan eksternal-relationship, patching "
                "MSDT, dan disable ms-msdt handler."
            ),
            "location": url,
        })
    return findings


# -- TLS certificate expiry (domain/account expiry, observed directly) -------


def _parse_not_after(not_after: str) -> datetime | None:
    """Parse a TLS notAfter into a timezone-aware UTC datetime."""
    try:
        dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y GMT")
        return dt.replace(tzinfo=timezone.utc)  # noqa: UP017
    except (ValueError, TypeError):
        try:
            dt = datetime.strptime(not_after, "%Y-%m-%dT%H:%M:%SZ")
            return dt.replace(tzinfo=timezone.utc)  # noqa: UP017
        except (ValueError, TypeError):
            return None


def _read_cert_not_after(
    host: str, port: int, timeout: float, server_hostname: str | None,
) -> tuple[str | None, str | None]:
    """Return (notAfter, san) of the peer TLS cert, or (None, error).

    Uses a *verifying* context: on success the peer cert is parsed by
    ``getpeercert()`` (which yields ``notAfter``). A verification failure
    (expired/self-signed/hostname mismatch) is itself surfaced as an error
    string so the caller can report an expired certificate.
    """
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=server_hostname or host) as ssock:
                cert = ssock.getpeercert()  # dict (verified) or {}
        if not cert:
            return None, "no-cert"
        not_after = cert.get("notAfter", "")
        san = cert.get("subjectAltName", ())
        hosts = [v for k, v in san if k == "DNS"] if san else []
        return not_after or None, ",".join(hosts[:3]) or None
    except (ssl.SSLCertVerificationError) as exc:
        return None, f"cert-verify:{exc.verify_message or ''}"
    except ssl.SSLError as exc:
        return None, f"ssl:{type(exc).__name__}"
    except OSError:
        # ssl errors above are subclasses of OSError and are caught first;
        # the remainder (timeout / conn refused / no route) => unreachable.
        return None, "unreachable"
    except Exception as exc:  # noqa: BLE001 — never crash the scan
        return None, f"err:{type(exc).__name__}"


async def check_tls_certificate(url: str, *, timeout: float = 8.0) -> list[dict[str, Any]]:
    """Observe the TLS certificate expiry directly (Allowing Domains/Accounts
    to Expire → CWE-613). Needs an https target."""
    parsed = urlparse(url or "")
    if parsed.scheme != "https" or not parsed.hostname:
        return []
    host = parsed.hostname
    port = parsed.port or 443
    loop = asyncio.get_running_loop()
    not_after_raw, meta = await loop.run_in_executor(
        None, _read_cert_not_after, host, port, timeout, host,
    )
    not_after = _parse_not_after(not_after_raw) if not_after_raw else None
    findings: list[dict[str, Any]] = []

    # Unreachable: nothing was observed — do not fabricate a finding.
    if not_after_raw is None and meta == "unreachable":
        return findings

    # The peer cert failed verification (expired / self-signed / hostname
    # mismatch) — an accurate, direct observation of a real TLS weakness.
    if not_after_raw is None and meta and meta.startswith("cert-verify:"):
        findings.append({
            "rule": "TLS-CERT-CHECK-FAILED",
            "severity": "high",
            "confidence": 0.9,
            "cwe": "CWE-295",
            "title": "Sertifikat TLS tidak terverifikasi",
            "description": (
                f"Sertifikat TLS {host} gagal verifikasi ({meta}). "
                "Kemungkinan kedaluwarsa, self-signed, atau hostname mismatch."
            ),
            "evidence": {"host": host, "port": port, "error": meta},
            "remediation": "Pasang sertifikat valid dari CA terpercaya dan cocokkan hostname.",
            "location": url,
        })
        return findings

    if not_after_raw is None and meta and (meta.startswith("ssl:") or meta == "no-cert"):
        findings.append({
            "rule": "TLS-CERT-CHECK-FAILED",
            "severity": "low",
            "confidence": 0.6,
            "cwe": "CWE-295",
            "title": "Sertifikat TLS tidak dapat diverifikasi",
            "description": (
                f"Gagal membaca sertifikat TLS untuk {host}:{port} ({meta}). "
                "Sinyal konfigurasi TLS/SNI yang mencurigakan."
            ),
            "evidence": {"host": host, "port": port, "error": meta},
            "remediation": "Periksa konfigurasi sertifikat/TLS server.",
            "location": url,
        })
        return findings

    if not_after is None:
        return findings
    now = datetime.now(timezone.utc)  # noqa: UP017
    days = (not_after - now).days
    if days < 0:
        findings.append({
            "rule": "TLS-CERT-EXPIRED",
            "severity": "critical",
            "confidence": 0.95,
            "cwe": "CWE-613",
            "title": "Sertifikat TLS telah kedaluwarsa",
            "description": (
                f"Sertifikat TLS {host} kedaluwarsa {abs(days)} hari lalu "
                f"(notAfter={not_after_raw})."
            ),
            "evidence": {"host": host, "port": port, "not_after": not_after_raw, "days": days},
            "remediation": "Perbarui segera sertifikat TLS dan pastikan perpanjangan otomatis.",
            "location": url,
        })
    elif days <= 30:
        findings.append({
            "rule": "TLS-CERT-EXPIRY-SOON",
            "severity": "medium",
            "confidence": 0.85,
            "cwe": "CWE-613",
            "title": "Sertifikat TLS segera kedaluwarsa",
            "description": (
                f"Sertifikat TLS {host} kedaluwarsa dalam {days} hari "
                f"(notAfter={not_after_raw})."
            ),
            "evidence": {"host": host, "port": port, "not_after": not_after_raw, "days": days},
            "remediation": "Perpanjang sertifikat sebelum kedaluwarsa; aktifkan auto-renew.",
            "location": url,
        })
    return findings
