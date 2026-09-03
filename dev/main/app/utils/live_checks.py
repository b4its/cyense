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
#
# Careful to avoid client-side false positives on benign HTML/JS:
#   * `const DEBUG = true` / `.debug = true` in ordinary front-end config is
#     NOT an error page, so it is not a signal on its own. Genuine verbose
#     error pages virtually always also carry one of the stronger signals
#     (traceback, stack trace, fatal error, mysql warning, etc.).
#   * A bare word "os error" (prose) is not a stack dump; require a code.
_VERBOSE_ERROR_RE = re.compile(
    r"(?i)traceback \(most recent call last\)|\bstack trace\b|"
    r"(?:^|\s)(?:[a-z0-9_]+\.)+[A-Za-z_]+Exception\b|"
    r"fatal error:|warning:\s*mysql|sqlstate\[|pg_error|"
    r"\bmicrosoft\.(?:net|windows)[a-z.]*(?:exception|stacktrace)|"
    r"`[^`]{0,60}`\s+<[^>]+>|\bos\s+error\s+\d{1,3}\b|"
    r"\bjava\.lang\.\w+Exception\b|\bundefined index:"
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
            parts = [p.strip() for p in cookie.split(";")]
            if not parts:
                continue
            name_value = parts[0]
            name = name_value.split("=", 1)[0].strip()
            if not name:
                continue
            attrs = [p.lower() for p in parts[1:]]
            if not any(a == "httponly" or a.startswith("httponly=") for a in attrs):
                findings.append(_cookie_flag(
                    name, "HttpOnly", "medium", "CWE-1004",
                    "Cookie tanpa flag HttpOnly — dapat dibaca JavaScript (XSS).",
                    "Tambahkan flag HttpOnly pada cookie sesi.",
                ))
            if not any(a == "secure" or a.startswith("secure=") for a in attrs):
                findings.append(_cookie_flag(
                    name, "Secure", "medium", "CWE-614",
                    "Cookie tanpa flag Secure — dapat bocor lewat kanal HTTP.",
                    "Set flag Secure agar cookie hanya dikirim via HTTPS.",
                ))
            has_samesite = any(a == "samesite" or a.startswith("samesite=") for a in attrs)
            samesite_val = ""
            for a in attrs:
                if a.startswith("samesite="):
                    samesite_val = a.split("=", 1)[1].strip().lower()
            if not has_samesite or samesite_val == "none":
                findings.append(_cookie_flag(
                    name, "SameSite", "low", "CWE-1275",
                    "Cookie tanpa atribut SameSite (atau SameSite=None) — rentan CSRF.",
                    "Tetapkan SameSite=Lax/Strict pada cookie sesi.",
                ))
    return findings


def _split_cookies(set_cookie: str) -> list[str]:
    """Split a Set-Cookie header value into individual cookie declarations.

    Naive ``.split(",")`` breaks any cookie carrying an ``Expires`` attribute
    (RFC dates contain commas, e.g. ``Expires=Wed, 21 Oct 2026 ...``), which
    both fabricated phantom cookies and masked the real flags. Splitting on a
    comma that is followed by a new ``name=value`` declaration only keeps real
    cookie boundaries and leaves date commas (no ``=`` immediately after the
    comma-skipping-whitespace) untouched.
    """
    return [
        part.strip()
        for part in re.split(r",\s*(?=[^\s;,=]+=)", set_cookie)
        if "=" in part
    ]


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
# Response-passive surface checks — turn crawled pages into the exact attack
# surfaces of the vulnerability taxonomy. These need no new requests.
# ---------------------------------------------------------------------------

_SENSITIVE_QUERY_KEYS = re.compile(
    r"(?i)(?:password|passwd|pwd|secret|api[_-]?key|private[_-]?key|"
    r"access[_-]?token|auth[_-]?token|authz[_-]?token|bearer|otp|"
    r"refresh[_-]?token|session[_-]?id|sessionid|credential|jwt|"
    r"id[_-]?token|signature|client[_-]?secret|db[_-]?pass)\b"
)


def check_sensitive_query_params(url: str) -> list[dict[str, Any]]:
    """Sensitive data passed in the URL query string (OWASP Information
    exposure through query strings, CWE-598)."""
    parsed = urlparse(url or "")
    if parsed.scheme not in ("http", "https"):
        return []
    findings: list[dict[str, Any]] = []
    for q in (parsed.query or "").split("&"):
        if "=" not in q:
            continue
        key = q.split("=", 1)[0]
        if _SENSITIVE_QUERY_KEYS.search(key):
            findings.append({
                "rule": "INFO-QUERY-SECRET",
                "severity": "medium",
                "confidence": 0.85,
                "cwe": "CWE-598",
                "title": f"Data sensitif di query string URL: {key}",
                "description": (
                    f"Parameter `{key}` dipakai di query string — bocor ke "
                    "Referer/log/history meski pakai HTTPS (OWASP information "
                    "exposure through query strings)."
                ),
                "evidence": {"param": key, "url": url},
                "remediation": "Pindahkan data sensitif ke body POST / header aman.",
                "location": url,
            })
    return findings


def check_csv_exposure(headers: dict[str, str], url: str = "") -> list[dict[str, Any]]:
    """CSV endpoint that may embed untrusted input (OWASP CSV/Formula Injection,
    CWE-1236)."""
    header_map = {k.lower(): v for k, v in headers.items()}
    ct = (header_map.get("content-type") or "").lower()
    findings: list[dict[str, Any]] = []
    if "text/csv" in ct or "application/csv" in ct or "text/tab-separated-values" in ct:
        findings.append({
            "rule": "CSV-DOWNLOAD",
            "severity": "medium",
            "confidence": 0.75,
            "cwe": "CWE-1236",
            "title": "Endpoint CSV terdeteksi (risiko formula injection)",
            "description": (
                "Respons ber-content-type CSV. Jika sel dibangun dari input "
                "user tanpa netralisasi `= + - @`, terjadi CSV/Formula injection."
            ),
            "evidence": {"content_type": ct, "url": url},
            "remediation": "Netralisasi sel yang diawali `=`, `+`, `-`, `@`, tab/CR/LF.",
            "location": url,
        })
    return findings


def check_upload_form(body: str, url: str = "") -> list[dict[str, Any]]:
    """Detect an unrestricted file-upload surface (OWASP Unrestricted File
    Upload, CWE-434) from an upload form."""
    findings: list[dict[str, Any]] = []
    lower = (body or "").lower()
    has_file_input = 'type="file"' in lower or "type='file'" in lower
    has_multipart = "multipart/form-data" in lower
    has_upload_name = "upload" in lower and ("<form" in lower or "<input" in lower)
    if (has_file_input and has_multipart) or (has_file_input and has_upload_name):
        findings.append({
            "rule": "UPLOAD-FORM",
            "severity": "high",
            "confidence": 0.7,
            "cwe": "CWE-434",
            "title": "Form upload file ditemukan (Unrestricted File Upload)",
            "description": (
                "Halaman memuat form upload (input type=file / multipart) — "
                "validasi ekstensi/MIME diperlukan untuk mencegah upload berbahaya."
            ),
            "evidence": {"url": url},
            "remediation": (
                "Validasi ekstensi + MIME allowlist, simpan di luar webroot, "
                "re-encode file."
            ),
            "location": url,
        })
    return findings


def check_serialized_endpoint(headers: dict[str, str], url: str = "") -> list[dict[str, Any]]:
    """Endpoint accepting serialized objects (OWASP Deserialization / Insecure
    Deserialization, CWE-502)."""
    header_map = {k.lower(): v for k, v in headers.items()}
    ct = (header_map.get("content-type") or "").lower()
    findings: list[dict[str, Any]] = []
    if any(t in ct for t in (
        "application/x-java-serialized-object", "application/x-python-pickle",
        "application/x-php-serialized", "application/x-python-serialized",
        "application/x-ruby-marshal",
    )):
        findings.append({
            "rule": "DESERIALIZE-ENDPOINT",
            "severity": "high",
            "confidence": 0.8,
            "cwe": "CWE-502",
            "title": "Endpoint deserialisasi object terdeteksi",
            "description": (
                f"Endpoint menerima content-type serialized ({ct}) — berisiko "
                "Deserialization / Insecure Deserialization."
            ),
            "evidence": {"content_type": ct, "url": url},
            "remediation": (
                "Gunakan representasi aman (JSON/safe loader) & validasi strict; "
                "jangan deserialize input tak tepercaya."
            ),
            "location": url,
        })
    return findings


def check_xml_endpoint(headers: dict[str, str], url: str = "") -> list[dict[str, Any]]:
    """XML/SOAP endpoint — XXE & Missing XML Validation surface (CWE-611/20)."""
    header_map = {k.lower(): v for k, v in headers.items()}
    ct = (header_map.get("content-type") or "").lower()
    findings: list[dict[str, Any]] = []
    if "application/xml" in ct or "text/xml" in ct or "application/soap+xml" in ct:
        findings.append({
            "rule": "XML-ENDPOINT",
            "severity": "medium",
            "confidence": 0.7,
            "cwe": "CWE-611",
            "title": "Endpoint XML/SOAP terdeteksi (surface XXE)",
            "description": (
                f"Respons ber-content-type XML ({ct}). Jika parser tidak "
                "menonaktifkan external-entity/DTD, rentan XXE & Missing XML Validation."
            ),
            "evidence": {"content_type": ct, "url": url},
            "remediation": (
                "Nonaktifkan external entity & validasi terhadap schema "
                "sebelum parse XML."
            ),
            "location": url,
        })
    return findings


# ---------------------------------------------------------------------------
# Active injection reflection — classify a probe response. Pure & unit-testable.
# ---------------------------------------------------------------------------

# Benign arithmetic markers whose evaluated value is 49. If a template/EL engine
# evaluates the expression, the literal "54444439" leaks back into the response.
# (7*7777777) — a value unlikely to occur naturally, cutting false positives.
_SSTI_PAYLOADS = ("${7*7777777}", "{{7*7777777}}", "<%= 7*7777777 %>", "#{7*7777777}")
_SSTI_MARKER = "54444439"

# A CRLF / response-splitting marker. When url-encoded it becomes %0d%0a; a
# vulnerable server echoes it back as a literal CRLF followed by our header.
_CRLF_PAYLOAD = "\r\nX-Injected-CRLF: 1"


def classify_injection_reflection(body: str, payload: str) -> str | None:
    """Return the injection rule id if *payload* was evaluated/reflected.

    * For SSTI/EL payloads (``${7*7}`` etc.) we look for the evaluated
      ``49`` marker (the engine executed the expression).
    * For CRLF we look for a raw CR/LF sequence echoed back in the body.
    """
    if not body:
        return None
    if payload in _SSTI_PAYLOADS or payload in ("$%7b7*7777777%7d", "%7B7*7777777%7D"):
        # The expression was *evaluated*: the marker token is gone and the
        # arithmetic result leaks back. If the marker is still present raw,
        # it was merely reflected (not executed) — that is not SSTI.
        if payload not in body and _SSTI_MARKER in body:
            return "INJ-LIVE-SSTI"
        return None
    if payload.startswith("\r\n") or "%0d" in payload.lower():
        # Response splitting: a reflected newline + our injected header marker.
        if "x-injected-crlf" in body.lower() and "\r\n" in body:
            return "INJ-LIVE-CRLF"
        return None
    return None


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
    if isinstance(body, bytes):
        try:
            body = body.decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            return findings
    lower = (body or "").lower()
    is_office = ("word/document.xml" in lower or "w:" in lower
                 or "\\rtf" in lower or "word/_rels/document.xml.rels" in lower
                 or lower.startswith("pk"))
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
