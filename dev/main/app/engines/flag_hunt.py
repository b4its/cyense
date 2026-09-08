"""CTF flag-hunt engine — read-only, same-origin (§3.5 / authorised CTF & lab).

The feature request ("setelah mendapat kerentanan, cari flag dari link
website") is implemented without violating ground rule #6: probing stays
HTTP GET/HEAD on the scanned host only — we never auto-exploit, never
write, never send a payload to a third party. A "flag" is only ever a
*read-only* observation of marker text a site already serves publicly to
an authenticated/browsing client of the scan scope.

Pipeline (invoked as an optional stage of the website/domain engines):
  1. scan crawled pages for known flag marker formats (pure regex on bodies
     the crawler already fetched — zero extra requests),
  2. probe a small, deterministic list of common flag-file paths
     (GET only, same origin, rate-limited),
  3. report any marker hit as a finding with rule ``FLAG-PAGE`` (content
     already served) or ``FLAG-PATH`` (common location reachable).

Findings are `info`-severity *observations*, not vulnerabilities — the
presence of marker text on an authorised CTF/lab target is the intended
outcome there, while on production scopes it is a signal to check whether
the "flag" is actually a leaked secret (severity is left at ``info`` so
flag hunts never distort vulnerability summaries).
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from app.utils.http_client import HttpClient
from app.utils.logger import get_logger

log = get_logger("engine.flag")

# Known CTF marker envelopes — keep conservative: case-insensitive word
# ``flag`` or ``ctf`` followed by a balanced-ish brace group of printable
# chars (no newlines, no closing brace inside). Covers picoCTF{...},
# CTF{...}, FLAG{...}, flag{...}, and plain ctf{...}.
FLAG_RE = re.compile(
    r"(?i)(?:\b(?:pico)?ctf|flag)\s*[:\-]?\s*\{([^{}\r\n]{3,256})\}",
)

# Some CTFs dump the flag in a header/cookie/comment rather than body text;
# these are still read-only observations of the same HTTP response.
HEADER_FLAG_RE = re.compile(
    r"(?i)(?:x-flag|flag|ctf)\s*:\s*[^;\r\n]{3,256}",
)

# Deterministic list of common flag-file paths probed on the scanned origin.
# Kept deliberately short & read-only; each entry is GET-ed and only a 200
# whose body carries a marker (or whose content-type is text and has
# ``flag`` in the URL) produces a finding.
COMMON_FLAG_PATHS: tuple[str, ...] = (
    "/flag.txt",
    "/flag",
    "/flag/",
    "/ctf/flag.txt",
    "/ctf/flag",
    "/.flag",
    "/static/flag.txt",
    "/assets/flag.txt",
    "/robots.txt",  # may disclose a /flag*.txt Disallow entry
    "/backup/flag.txt",
)

def find_flags(body: str) -> list[dict[str, Any]]:
    """Return marker matches in ``body``: [{marker, sample, start}]."""
    hits: list[dict[str, Any]] = []
    for m in FLAG_RE.finditer(body or ""):
        start = max(m.start() - 24, 0)
        hits.append({
            "marker": m.group(0)[:200],
            "sample": body[start : m.end() + 24][:200],
        })
        if len(hits) >= 8:
            break
    if not hits and body:
        m = HEADER_FLAG_RE.search(body)
        if m:
            hits.append({"marker": m.group(0)[:200], "sample": body[max(m.start() - 24, 0):][:200]})
    return hits

def scan_pages_for_flags(pages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Flag markers in pages the crawler already fetched (no extra requests).

    Each page is checked for body markers AND response-header flags (e.g. an
    ``X-Flag`` header or a ``flag:`` header leaked in a comment/whitespace).
    """
    out: list[dict[str, Any]] = []
    for page in pages or []:
        url = page.get("url", "")
        body = page.get("body") or ""
        body_hits = find_flags(body)
        header_hits: list[dict[str, Any]] = []
        for k, v in (page.get("headers") or {}).items():
            if FLAG_RE.search(str(v)) or HEADER_FLAG_RE.search(f"{k}: {v}"):
                header_hits.append({
                    "marker": f"{k}: {v}"[:200],
                    "sample": f"{k}: {v}"[:200],
                })
        hits = (body_hits + header_hits)[:2]
        for hit in hits:
            out.append({
                "rule": "FLAG-PAGE",
                "severity": "info",
                "confidence": 0.55,
                "title": "Flag marker ditemukan pada halaman yang di-crawl",
                "description": (
                    "Halaman yang sudah di-crawl memuat teks berformat marker "
                    "flag (ctf{...}/flag{...}) — pada target CTF/lab yang "
                    "terotorisasi ini artefak yang dicari; pada scope produksi "
                    "periksa apakah itu secret yang bocor."
                ),
                "evidence": {
                    "marker": hit["marker"],
                    "sample": hit["sample"],
                    "in_header": bool(header_hits) and hit in header_hits,
                },
                "remediation": (
                    "Konteks CTF/lab: amankan artefak flag (kelola di server "
                    "otorisasi, jangan di-embed statis). Konteks produksi: "
                    "redaksi secret yang bocor & rotasi kredensial."
                ),
                "location": url,
            })
    return out

def flag_probe_urls(base_url: str) -> list[str]:
    """Same-origin candidate URLs derived from ``base_url``."""
    parsed = urlparse(base_url)
    scheme = parsed.scheme or "http"
    netloc = parsed.netloc
    if not netloc:
        return []
    return [f"{scheme}://{netloc}{p}" for p in COMMON_FLAG_PATHS]

async def probe_flag_paths(
    base_url: str,
    *,
    rate_limit: int = 10,
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    """GET the common flag paths on the scanned origin (read-only).

    A hit is reported only when the response carries a flag marker in its
    body (or the URL/path itself is a known flag file AND status < 400) —
    plain 404s produce nothing. Honors the engine's rate_limit; caps the
    requests to the fixed short list above. Uses its own HttpClient inside
    ``async with`` (same pattern as the other live_* engines).
    """
    urls = flag_probe_urls(base_url)
    if not urls:
        return []
    findings: list[dict[str, Any]] = []
    async with HttpClient(
        rate_limit=rate_limit,
        headers=dict(headers or {}),
        cookies=dict(cookies or {}),
    ) as client:
        for url in urls:
            try:
                resp = await client.get(url)
            except Exception as exc:  # noqa: BLE001 — best effort
                log.debug("flag path probe failed %s: %s", url, exc)
                continue
            if resp.status >= 400:
                continue
            hits = find_flags(resp.body or "")
            path_name = urlparse(url).path.lower()
            if not hits and "flag" not in path_name:
                continue
            marker = hits[0]["marker"] if hits else path_name
            findings.append({
                "rule": "FLAG-PATH",
                "severity": "info",
                "confidence": 0.5 if hits else 0.35,
                "title": f"Lokasi flag umum dapat diakses: {urlparse(url).path}",
                "description": (
                    "Path berformat-flag pada origin yang di-scan merespons "
                    "200 (read-only GET). Pada CTF/lab yang terotorisasi ini "
                    "temuan yang dicari; pastikan scope mengizinkan akses."
                ),
                "evidence": {
                    "url": url,
                    "status": resp.status,
                    "content_type": resp.headers.get("content-type", ""),
                    "marker": marker,
                    "sample": hits[0]["sample"] if hits else "",
                },
                "remediation": (
                    "CTF/lab: pindahkan flag ke jalur yang tidak dapat "
                    "ditebak bila perlu. Produksi: cabut file & rotasi."
                ),
                "location": url,
            })
    return findings

async def run_flag_hunt(
    base_url: str,
    pages: list[dict[str, Any]] | None = None,
    *,
    rate_limit: int = 10,
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Full flag-hunt stage (read-only): crawled pages + common path probes."""
    findings: list[dict[str, Any]] = []
    findings += scan_pages_for_flags(pages or [])
    findings += await probe_flag_paths(
        base_url,
        rate_limit=rate_limit,
        headers=headers,
        cookies=cookies,
    )
    return findings
