"""OWASP community-vulnerability live checks (www-community/vulnerabilities).

Maps several OWASP vulnerability-class articles onto **deterministic, passive**
signals a link/website crawler already observes (HTTP headers, Set-Cookie,
HTML/JS body, query parameters, technology fingerprints) — no extra requests.

Each entry is tagged with its rule id + OWASP article + CWE id for consistent
SARIF/CVSS/coverage classification, matching the rest of ``app/utils``.

Coverage in this module (OWASP article → rule):
  * Information exposure through query strings  → OWASP-LOGIN-GET
  * Empty String Password                       → OWASP-PW-AUTOFILL
  * Insecure Transport (mixed content)          → OWASP-MIXED-CONTENT
  * Insecure Third Party Domain Access          → OWASP-EXTERNAL-NOSRI
  * Insecure Deserialization                    → OWASP-DESER-MAGIC
  * Insufficient Session-ID Length / Insecure Randomness /
    Insufficient Entropy / PRNG Seed Error      → OWASP-SESSION-ENTROPY
  * PHP File Inclusion / Process Control /
    Unsafe use of Reflection                    → OWASP-DISPATCHER-PARAM (lead)
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

# Regexes that sniff server-side serialized-object payloads in data the client
# can observe (cookies, hidden fields, bodies). Presence is a *surface* signal
# for Insecure Deserialization (CWE-502) — the app stores state in a native
# deserialization format rather than a safe interchange format.
_MAGIC_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    # Java ObjectOutputStream serialized stream: bytes AC ED 00 05 == base64 rO0AB
    ("java", re.compile(r"(?:rO0AB[0-9A-Za-z+/]+=*|\\xac\\xed\\x00\\x05)"), "CWE-502"),
    # PHP serialized: O:<len>:"<class>":... or a:<len>:{ (array)
    ("php", re.compile(r"(?i)\b(?:O|a|s|i|b|N):\d+:"), "CWE-502"),
    # .NET binary serialization marker
    ("dotnet", re.compile(r"\x00\x01\x00\x00\x00"), "CWE-502"),
    # Python pickle (protocol >= 0 streams begin with b'(' or protocol byte)
    ("pickle", re.compile(r"(?m)^\x80[\x00-\x05].*\(dp\d+", re.S), "CWE-502"),
]


def check_get_login_form(body: str, url: str = "") -> list[dict[str, Any]]:
    """A login form submitted via HTTP GET sends the password in the URL.

    OWASP: Information exposure through query strings in URL (CWE-598).
    """
    findings: list[dict[str, Any]] = []
    if not body:
        return findings
    # Match <form ... method="get" ...> blocks that contain an <input type=password>.
    for form in re.finditer(
        r"<form\b[^>]*>.*?</form>", body, re.I | re.S
    ):
        block = form.group(0)
        if not re.search(r"<input\b[^>]*type=[\"']password[\"']", block, re.I):
            continue
        method_m = re.search(r"method\s*=\s*[\"']([^\"']*)[\"']", block, re.I)
        method = (method_m.group(1) if method_m else "get").lower()
        if method != "get":
            continue
        action = ""
        am = re.search(r"action\s*=\s*[\"']([^\"']*)[\"']", block, re.I)
        if am:
            action = am.group(1)
        findings.append({
            "rule": "OWASP-LOGIN-GET",
            "severity": "high",
            "confidence": 0.9,
            "cwe": "CWE-598",
            "title": "Form login dengan method GET (kredensial bocor ke URL)",
            "description": (
                "Form password memakai method=GET — kredensial akan tampil di "
                "query string, log server, history browser, dan header Referer "
                "ke pihak ketiga (OWASP: information exposure through query "
                "strings)."
            ),
            "evidence": {"action": action, "url": url},
            "remediation": (
                "Ganti ke method=POST dan kirim kredensial di body; jangan "
                "menaruh rahasia di URL."
            ),
            "location": url,
        })
    return findings


def check_password_autocomplete(body: str, url: str = "") -> list[dict[str, Any]]:
    """Password inputs that permit browser autofill + no autocomplete=off.

    OWASP: Empty String Password / credential handling context. Browsers
    pre-fill stored credentials, which together with a weak blank/auto-submit
    path can allow unintended reuse. This is an informational hardening lead.
    """
    findings: list[dict[str, Any]] = []
    if not body:
        return findings
    for pw in re.finditer(
        r"<input\b[^>]*type=[\"']password[\"'][^>]*>", body, re.I
    ):
        tag = pw.group(0)
        if re.search(r"\bautocomplete\s*=\s*[\"']off[\"']", tag, re.I):
            continue
        findings.append({
            "rule": "OWASP-PW-AUTOFILL",
            "severity": "low",
            "confidence": 0.6,
            "cwe": "CWE-384",
            "title": "Input password tanpa autocomplete=off",
            "description": (
                "Field password tidak menonaktifkan autocomplete — browser "
                "dapat mengisi kredensial tersimpan otomatis pada perangkat "
                "bersama (risiko reuse/session)."
            ),
            "evidence": {"url": url},
            "remediation": (
                "Tetapkan autocomplete='off' (atau autocomplete='new-password') "
                "pada field password untuk mencegah autofill tak disengaja."
            ),
            "location": url,
        })
    return findings


def _extract_subresources(body: str, base: str) -> list[dict[str, str]]:
    """Pull <script src>, <img src>, <link href>, css url(...), form action."""
    del base  # host comparison is done by callers from the page URL
    out: list[dict[str, str]] = []
    if not body:
        return out
    for tag in re.finditer(
        r"<(script|img|iframe|embed|object|link|source|video|audio)\b[^>]*>",
        body, re.I,
    ):
        src_m = re.search(
            r"(?:src|href|data|poster)\s*=\s*[\"']([^\"']+)[\"']", tag.group(0), re.I
        )
        if not src_m:
            continue
        raw = src_m.group(1)
        if not raw or raw.startswith("data:") or raw.startswith("#"):
            continue
        integrity = re.search(r"\bintegrity\s*=\s*[\"']([^\"']*)[\"']", tag.group(0), re.I)
        out.append({
            "url": raw,
            "host": (
                (urlparse(raw).hostname or "")
                if ("://" in raw or raw.startswith("//"))
                else ""
            ),
            "integrity": integrity.group(1) if integrity else "",
            "tag": tag.group(1).lower(),
        })
    return out


def check_mixed_content_and_sri(body: str, url: str = "") -> list[dict[str, Any]]:
    """Mixed content + third-party content without Subresource Integrity.

    OWASP: Insecure Transport (mixed content) + Insecure Third Party Domain
    Access (CWE-319 / CWE-829).
    """
    findings: list[dict[str, Any]] = []
    if not body:
        return findings
    parsed = urlparse(url or "")
    page_scheme = parsed.scheme.lower()
    page_host = parsed.hostname or ""
    is_https = page_scheme == "https"

    # Mixed content: an HTTPS page pulling http:// subresources / form action.
    if is_https:
        http_refs = set()
        for sub in _extract_subresources(body, url):
            if sub["url"].startswith("http://"):
                http_refs.add(sub["url"])
        for action in re.finditer(
            r"<form\b[^>]*action\s*=\s*[\"'](http://[^\"']+)[\"']", body, re.I
        ):
            http_refs.add(action.group(1))
        if http_refs:
            findings.append({
                "rule": "OWASP-MIXED-CONTENT",
                "severity": "high",
                "confidence": 0.85,
                "cwe": "CWE-319",
                "title": "Mixed content: resource http:// pada halaman HTTPS",
                "description": (
                    "Halaman HTTPS memuat subresource lewat HTTP — data dapat "
                    "disadap/diubah, dan 'Secure' halaman jadi tidak berarti "
                    "(Insecure Transport / mixed content)."
                ),
                "evidence": {"urls": sorted(http_refs)[:8], "page": url},
                "remediation": (
                    "Sajikan seluruh resource via HTTPS dan aktifkan CSP "
                    "upgrade-insecure-requests."
                ),
                "location": url,
            })

    # Third-party scripts/styles without SRI — only meaningful on HTTPS where
    # SRI gives protection; an attacker controlling the foreign host/CDN can
    # inject scripts (Insecure Third Party Domain Access).
    if is_https:
        no_sri = set()
        for sub in _extract_subresources(body, url):
            if sub["tag"] not in ("script", "link"):
                continue
            if sub["integrity"]:
                continue
            h = sub["host"]
            # Protocol-relative //host or absolute external host
            if not h:
                continue
            if h == page_host or h.endswith("." + page_host):
                continue
            no_sri.add(sub["url"])
        if no_sri:
            findings.append({
                "rule": "OWASP-EXTERNAL-NOSRI",
                "severity": "medium",
                "confidence": 0.6,
                "cwe": "CWE-829",
                "title": "Resource pihak ketiga tanpa Subresource Integrity",
                "description": (
                    "Script/stylesheet dari host eksternal dimuat tanpa "
                    "atribut integrity= (SRI). Jika host/CDN eksternal "
                    "dikompromi, kode berbahaya dapat dijalankan di halaman "
                    "(Insecure Third Party Domain Access)."
                ),
                "evidence": {"urls": sorted(no_sri)[:8], "page": url},
                "remediation": (
                    "Tambahkan SRI (integrity= sha384-...) pada script/link "
                    "eksternal dan terapkan CSP script-src yang ketat."
                ),
                "location": url,
            })
    return findings


def check_serialization_magic(body: str, url: str = "") -> list[dict[str, Any]]:
    """Detect serialized-object payloads in content the client can observe.

    OWASP: Insecure Deserialization / Deserialization of untrusted data
    (CWE-502). A native serialization stream stored/sent to the client is a
    red flag the app deserializes untrusted data.
    """
    findings: list[dict[str, Any]] = []
    if not body:
        return findings
    for lang, pattern, _cwe in _MAGIC_PATTERNS:
        if not pattern.search(body):
            continue
        findings.append({
            "rule": "OWASP-DESER-MAGIC",
            "severity": "medium",
            "confidence": 0.6,
            "cwe": "CWE-502",
            "title": f"Serialized object terdeteksi ({lang})",
            "description": (
                "Respons memuat stream/serialized data berformat "
                + lang
                + ". Jika aplikasi men-deserialize nilai yang berasal "
                "dari pengguna (cookie, parameter, body), berisiko "
                "Insecure Deserialization (CWE-502)."
            ),
            "evidence": {"language": lang, "url": url},
            "remediation": (
                "Gunakan format interchange yang aman (JSON) dan/atau validasi "
                "allowlist ketat; jangan deserialize input tak tepercaya."
            ),
            "location": url,
        })
    return findings


# Session-id character-space estimation (OWASP Insufficient Session-ID Length /
# randomness). A token's alphabet limits the entropy per character; hex-only and
# short base64 ids cannot reach 64+ bits of entropy.
def _entropy_bits(token: str) -> float:
    """Lower-bound estimate of Shannon entropy (bits) for a token.

    Uniform-alphabet model: ``len(token) * log2(alphabet_size)`` computed
    from the character classes actually used (conservative lower bound).
    """
    import math

    token = token or ""
    if not token:
        return 0.0
    alphabet = 0.0
    if re.search(r"[a-z]", token):
        alphabet += 26
    if re.search(r"[A-Z]", token):
        alphabet += 26
    if re.search(r"[0-9]", token):
        alphabet += 10
    if re.search(r"[^A-Za-z0-9]", token):
        alphabet += 16
    if alphabet <= 0:
        return 0.0
    return len(token) * math.log2(alphabet)


def check_session_id_entropy(headers: dict[str, str], url: str = "") -> list[dict[str, Any]]:
    """Weak / low-entropy session identifiers from Set-Cookie.

    OWASP: Insufficient Session-ID Length, Insecure Randomness, Insufficient
    Entropy, PRNG Seed Error (CWE-331/330/335/338).
    """
    findings: list[dict[str, Any]] = []
    header_map = {k.lower(): v for k, v in headers.items()}
    set_cookie = header_map.get("set-cookie", "")
    # Split on cookie boundaries only (a comma that begins a new name=value),
    # so Expires/date commas do not chop a cookie into phantom parts.
    for cookie in re.split(r",\s*(?=[^\s;,=]+=)", set_cookie):
        cookie = cookie.strip()
        if not cookie or "=" not in cookie:
            continue
        name, _, value = cookie.partition("=")
        value = value.split(";", 1)[0].strip()
        name = name.strip()
        # Only consider plausibly-session tokens (a small value is unremarkable).
        if not name or not value:
            continue
        # Skip non-session values such as flags/selectors with no length.
        skip_toks = ("path", "expires", "domain", "samesite", "secure",
                     "httponly", "max-age")
        if any(tok in name.lower() for tok in skip_toks):
            continue
        # Only treat PLAUSIBLY-SESSION cookies (session/sid/token-like names)
        # as session ids — flagging every short cookie (`lang=en`,
        # `theme=dark`) drowned real session findings in false positives.
        _session_like = re.compile(
            r"(?i)session|sess|sid(?![a-z])|token|auth|jsessionid|phpsessid",
        )
        if not _session_like.search(name):
            continue
        low = re.fullmatch(r"[0-9a-f]{1,16}", value, re.I)  # hex shorter than 16 => <64 bits
        numeric = re.fullmatch(r"\d{1,18}", value)
        bits = _entropy_bits(value)
        weak = bool(low or numeric) and len(value) < 20
        if weak or bits < 32:
            findings.append({
                "rule": "OWASP-SESSION-ENTROPY",
                "severity": "medium",
                "confidence": 0.6,
                "cwe": "CWE-331",
                "title": f"Session id berentropi rendah: {name}",
                "description": (
                    f"Nilai session cookie '{name}' pendek/berpola "
                    "(hex/numerik) — estimasi entropi rendah, id dapat ditebak "
                    "(Insufficient Session-ID Length / Insecure Randomness)."
                ),
                "evidence": {
                    "cookie": name,
                    "pattern": "hex" if low else ("numeric" if numeric else "short"),
                    "approx_bits": int(bits),
                    "url": url,
                },
                "remediation": (
                    "Gunakan id sesi acak kriptografis >= 128 bit (contoh: 32 "
                    "hex / 22+ base64url chars) dan regenerasi setelah login."
                ),
                "location": url,
            })
    return findings


def check_dispatcher_params(url: str) -> list[dict[str, Any]]:
    """URL query parameters that act as server-side selectors.

    Parameters named like a file/include, OS command, class or method are the
    classic attack surface for PHP File Inclusion (CWE-98), Process Control /
    OS command injection (CWE-78) and Unsafe use of Reflection (CWE-470). This
    is a low-confidence surface *lead* (the parameter may be benign), reported
    so a reviewer can inspect the corresponding handler.
    """
    parsed = urlparse(url or "")
    if parsed.scheme not in ("http", "https"):
        return []
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    for q in (parsed.query or "").split("&"):
        if "=" not in q:
            continue
        key = q.split("=", 1)[0].strip().lower()
        if key in seen:
            continue
        if key in (
            "page", "file", "include", "inc", "path", "doc", "view", "dir",
            "template", "load", "module", "handler", "action", "cmd", "exec",
            "command", "class", "method", "func", "function", "util",
        ):
            seen.add(key)
    if seen:
        findings.append({
            "rule": "OWASP-DISPATCHER-PARAM",
            "severity": "low",
            "confidence": 0.5,
            "cwe": "CWE-470",
            "title": "Parameter dispatcher/selector pada URL (surface LFI/RFI/reflection)",
            "description": (
                "URL memuat parameter pemilih server-side "
                f"({', '.join(sorted(seen))}) yang berpotensi mengarah ke "
                "PHP File Inclusion, Process Control (OS command), atau Unsafe "
                "Reflection bila nilainya dipakai memilih file/command/class "
                "tanpa validasi."
            ),
            "evidence": {"params": sorted(seen), "url": url},
            "remediation": (
                "Jangan menurunkan path/class/command dari input user; gunakan "
                "allowlist/indeks, validasi input, dan tolak traversal."
            ),
            "location": url,
        })
    return findings


def run_owasp_passive_checks(
    headers: dict[str, str], body: str, url: str,
) -> list[dict[str, Any]]:
    """Run all passive OWASP checks and return their findings."""
    findings: list[dict[str, Any]] = []
    findings.extend(check_get_login_form(body, url))
    findings.extend(check_password_autocomplete(body, url))
    findings.extend(check_mixed_content_and_sri(body, url))
    findings.extend(check_serialization_magic(body, url))
    findings.extend(check_session_id_entropy(headers, url))
    findings.extend(check_dispatcher_params(url))
    return findings


__all__ = [
    "check_get_login_form",
    "check_password_autocomplete",
    "check_mixed_content_and_sri",
    "check_serialization_magic",
    "check_session_id_entropy",
    "check_dispatcher_params",
    "run_owasp_passive_checks",
]
