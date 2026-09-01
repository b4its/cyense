"""Markdown report builder (cli-experience.md §3.4).

Aturan wajib:
  - Tanpa template engine — f-string murni (Jinja dilarang, konsisten html_report.py:1-7)
  - Deterministik: urutan, format angka tetap; hanya generated_at yang berbeda
  - GitHub-flavored: tabel pipa, fenced code block, anchor heading stabil
  - Redaksi dijalankan sebelum serialisasi (§6.2)

API publik:
  render_markdown_report(report, recs=None) -> str
  dump_markdown_report(report, path, recs=None) -> Path
"""

from __future__ import annotations

import re
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

from app.utils.redact import redact_headers, redact_url_credentials

if TYPE_CHECKING:
    from app.cli.models import Recommendation

_VERSION = "2.0.0"

# Bobot severity untuk ringkasan eksekutif
_SEV_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}

# Karakter kontrol yang dibuang dari data eksternal (sama seperti renderer._esc)
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f\x9b-\x9f]|\x1b\[[0-9;]*[mA-Za-z]")


def _esc(v: Any) -> str:
    """Hilangkan karakter kontrol dari data eksternal."""
    return _CTRL_RE.sub("", str(v) if not isinstance(v, str) else v)


def _md_escape(v: Any) -> str:
    """Escape karakter Markdown khusus di dalam sel tabel."""
    s = _esc(v)
    return s.replace("|", "\\|").replace("\n", " ")


# ---------------------------------------------------------------------------
# 1. Front-matter YAML

def _frontmatter(report: dict[str, Any]) -> str:
    meta     = report.get("meta", {})
    summary  = report.get("summary", {})
    repo     = meta.get("repo", {})
    scan_id  = _esc(meta.get("scan_id", ""))
    mode     = _esc(meta.get("mode", ""))
    gen      = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    counts = {
        sev: summary.get(sev, 0)
        for sev in ("critical", "high", "medium", "low", "info")
    }
    counts_str = ", ".join(f"{k}: {v}" for k, v in counts.items())

    lines = [
        "---",
        "tool: cyense",
        f"version: {_VERSION}",
        f"scan_id: {scan_id}",
        f"mode: {mode}",
        f"generated_at: {gen}",
    ]
    if repo:
        owner = _esc(repo.get("owner", ""))
        repo_name = _esc(repo.get("repo", ""))
        if owner and repo_name:
            lines.append(f"repository: {owner}/{repo_name}")
        ref = _esc(repo.get("ref", ""))
        if ref:
            lines.append(f"ref: {ref}")
        sha = _esc(repo.get("commit_sha", ""))
        if sha:
            lines.append(f"commit_sha: {sha}")
    lines.append(f"severity_counts: {{{counts_str}}}")
    lines.append("---")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 2. Ringkasan eksekutif (paragraf otomatis)

def _executive_summary(report: dict[str, Any]) -> str:
    meta     = report.get("meta", {})
    summary  = report.get("summary", {})
    findings = report.get("findings", [])
    repo     = meta.get("repo", {})

    total = summary.get("total", len(findings))
    files = summary.get("files_scanned") or summary.get("files_analyzed", "—")

    # Severity tertinggi
    top_sev = max(
        (f.get("severity", "info") for f in findings),
        key=lambda s: _SEV_ORDER.get(s, 0),
        default=None,
    )

    # Kelas kerentanan yang muncul
    idor_rules = {f.get("rule", "") for f in findings if f.get("rule", "").startswith("CY")}
    xss_rules  = {f.get("rule", "") for f in findings if f.get("rule", "").startswith("XS")}
    link_rules = {f.get("rule", "") for f in findings if "LINK" in f.get("rule", "")}
    classes = []
    if idor_rules:
        classes.append("IDOR")
    if xss_rules:
        classes.append("XSS")
    if link_rules:
        classes.append("IDOR-dinamis")

    repo_name = ""
    if repo:
        owner = repo.get("owner", "")
        rname = repo.get("repo", "")
        repo_name = f" pada `{owner}/{rname}`" if owner else ""

    if total == 0:
        return (
            f"Scan{repo_name} selesai. "
            f"**Tidak ditemukan kerentanan** dari {files} file yang dianalisis. "
            "Repository terlihat bersih berdasarkan aturan CY001–CY010 dan XS001–XS008."
        )

    class_str = " dan ".join(classes) if classes else "kerentanan"
    top_label = top_sev.upper() if top_sev else "UNKNOWN"
    rec_rule = ""
    if idor_rules:
        rec_rule = "Prioritaskan perbaikan filter kepemilikan pada query database."
    elif xss_rules:
        rec_rule = "Prioritaskan sanitasi output HTML/JS sebelum rendering."

    return (
        f"Ditemukan **{total} temuan** ({class_str}){repo_name} "
        f"dari {files} file yang dianalisis. "
        f"Severity tertinggi: **{top_label}**. "
        f"{rec_rule}"
    )


# ---------------------------------------------------------------------------
# 3. Tabel target

def _target_table(report: dict[str, Any]) -> str:
    meta    = report.get("meta", {})
    summary = report.get("summary", {})
    repo    = meta.get("repo", {})

    rows = []

    def row(label: str, value: Any) -> None:
        rows.append(f"| {_md_escape(label)} | {_md_escape(value)} |")

    row("scan_id",  meta.get("scan_id", "—"))
    row("mode",     meta.get("mode", "—"))
    row("engine",   meta.get("engine", "—"))
    if repo:
        row("repository", f"{repo.get('owner','')}/{repo.get('repo','')}")
        row("ref",         repo.get("ref", "—"))
        row("commit_sha",  repo.get("commit_sha", "—"))
        row("url",         _esc(redact_url_credentials(repo.get("url", "—"))))
        size_bytes = repo.get("size_bytes", 0)
        row("ukuran", f"{size_bytes / 1_048_576:.1f} MB" if size_bytes else "—")
    files = summary.get("files_scanned") or summary.get("files_analyzed", "—")
    dur   = summary.get("duration_ms", 0)
    row("file dianalisis", files)
    row("durasi",          f"{dur / 1000:.2f}s" if dur else "—")

    header = "| Field | Nilai |\n|---|---|"
    return header + "\n" + "\n".join(rows)


# ---------------------------------------------------------------------------
# 4. Tabel ringkasan temuan

def _summary_table(report: dict[str, Any]) -> str:
    summary  = report.get("summary", {})
    findings = report.get("findings", [])
    total    = summary.get("total", len(findings))

    # Per-severity
    lines = ["| Severity | Jumlah |", "|---|---|"]
    for sev in ("critical", "high", "medium", "low", "info"):
        lines.append(f"| {sev.upper()} | {summary.get(sev, 0)} |")
    lines.append(f"| **TOTAL** | **{total}** |")
    sev_table = "\n".join(lines)

    # Per-rule
    rule_counts: dict[str, dict[str, Any]] = {}
    for f in findings:
        rule = _esc(f.get("rule", "UNKNOWN"))
        sev  = f.get("severity", "info")
        if rule not in rule_counts:
            rule_counts[rule] = {"count": 0, "severity": sev, "class": _rule_class(rule)}
        rule_counts[rule]["count"] += 1

    if rule_counts:
        rule_lines = ["", "| Rule | Jumlah | Severity | Kelas |", "|---|---|---|---|"]
        for rule, info in sorted(
            rule_counts.items(),
            key=lambda x: -_SEV_ORDER.get(x[1]["severity"], 0),
        ):
            rule_lines.append(
                f"| `{rule}` | {info['count']} | {info['severity'].upper()} | {info['class']} |"
            )
        return sev_table + "\n" + "\n".join(rule_lines)

    return sev_table


def _rule_class(rule: str) -> str:
    if rule.startswith("CY"):
        return "IDOR (statis)"
    if rule.startswith("XS"):
        return "XSS (statis)"
    if "LINK" in rule:
        return "IDOR (dinamis)"
    return "—"


# ---------------------------------------------------------------------------
# 5. Detail tiap temuan

def _finding_section(idx: int, f: dict[str, Any]) -> str:
    finding_id = _esc(f.get("finding_id", f"F{idx:03d}"))
    rule       = _esc(f.get("rule", "—"))
    sev        = _esc(f.get("severity", "info")).upper()
    title      = _esc(f.get("title", "(untitled)"))
    conf       = f.get("confidence", 0.0)
    desc       = _esc(f.get("description") or "")
    location   = _esc(f.get("location") or "")
    remediation = _esc(f.get("remediation") or "")
    cwe        = f.get("cwe")
    cvss_score = f.get("cvss_score")
    cvss_vector = f.get("cvss_vector")

    lines = [
        f"### {idx}. [{sev}] `{rule}` — {title}",
        "",
        "| Field | Nilai |",
        "|---|---|",
        f"| **Finding ID** | `{finding_id}` |",
        f"| **Rule** | `{rule}` |",
        f"| **Severity** | {sev} |",
        f"| **Confidence** | {conf:.2f} |",
    ]
    if cwe:
        lines.append(f"| **CWE** | `{_esc(cwe)}` |")
    if cvss_score is not None:
        lines.append(f"| **CVSS Score** | {cvss_score:.1f} |")
    if cvss_vector:
        lines.append(f"| **CVSS Vector** | `{_esc(cvss_vector)}` |")
    if location:
        lines.append(f"| **Lokasi** | `{_md_escape(location)}` |")

    if desc:
        lines += ["", f"**Deskripsi:** {desc}"]

    # Evidence
    evidence = f.get("evidence") or {}
    if isinstance(evidence, dict):
        _append_evidence(lines, evidence)

    # Verifikasi (mode link)
    verification = f.get("verification") or {}
    if isinstance(verification, dict) and any(
        v is not None for v in verification.values()
    ):
        lines += ["", "**Verifikasi:**", ""]
        vkeys = ["similarity", "retry_consistent", "control_id_blocked",
                 "similarity_to_control", "pii_matches", "notes"]
        for vk in vkeys:
            vv = verification.get(vk)
            if vv is not None and vv != "" and vv != []:
                lines.append(f"- `{vk}`: {_esc(str(vv))}")

    if remediation:
        lines += ["", "**Remediasi:**", "", f"> {remediation}"]

    lines.append("")
    return "\n".join(lines)


def _append_evidence(lines: list[str], evidence: dict[str, Any]) -> None:
    # Statis: file + snippet
    snippet = evidence.get("snippet") or evidence.get("code") or ""
    file_   = evidence.get("file", "")
    line_   = evidence.get("line", "")

    if file_ or line_:
        loc = f"{_esc(file_)}:{_esc(line_)}" if file_ and line_ else _esc(file_ or str(line_))
        lines += ["", f"**Lokasi bukti:** `{loc}`"]

    if snippet:
        lang = _detect_lang(str(file_))
        snippet_lines = snippet.splitlines()[:12]  # max_evidence_lines
        snippet_block = "\n".join(snippet_lines)
        lines += ["", f"```{lang}", snippet_block, "```"]

    # Dinamis: request/response (sudah ter-redaksi oleh engine)
    req = evidence.get("request", {})
    res = evidence.get("response", {})
    if req:
        method = _esc(req.get("method", "GET"))
        url    = _esc(redact_url_credentials(req.get("url", "")))
        hdrs   = redact_headers(req.get("headers", {}))
        lines += ["", f"**Request:** `{method} {url}`"]
        if hdrs:
            lines += ["```", "\n".join(f"{k}: {v}" for k, v in hdrs.items()), "```"]
    if res:
        st = res.get("status", "—")
        body = _esc(str(res.get("body_snippet", "")))[:200]
        lines += [f"**Response:** `HTTP {st}`"]
        if body:
            lines += ["```", body, "```"]


def _detect_lang(filename: str) -> str:
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    return {"py": "python", "js": "javascript", "ts": "typescript",
            "php": "php", "html": "html"}.get(ext, "")


# ---------------------------------------------------------------------------
# 6. Rekomendasi perbaikan

def _recommendations_section(recs: list[Recommendation]) -> str:
    if not recs:
        return "_Tidak ada rekomendasi — tidak ada temuan._"

    lines: list[str] = []
    for i, rec in enumerate(recs, 1):
        label = rec.label
        aff   = ", ".join(f"`{_esc(a)}`" for a in rec.affected) if rec.affected else "—"
        lines += [
            (
                f"### {i}. {label} — `{_esc(rec.rule)}` "
                f"({rec.occurrences} temuan · {rec.severity.upper()})"
            ),
            "",
            f"> {_esc(rec.action)}",
            "",
            f"**File terdampak:** {aff}",
            "",
        ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 7. Metodologi & batasan

_METHODOLOGY = """\
Analisis dilakukan secara **statis dan read-only** terhadap source code hasil fetch.
Kode yang dianalisis **tidak pernah dieksekusi**. Tidak ada penulisan apa pun ke GitHub.

Cakupan aturan:
- **IDOR statis:** CY001–CY010 (Python AST + JS/PHP regex)
- **XSS statis:** XS001–XS008 (JS/PHP/Python regex + guards)
- **IDOR dinamis:** probing HTTP live (mode link)

Keterbatasan: analisis statis dapat menghasilkan false positive. Setiap temuan
perlu dikonfirmasi secara manual atau melalui dynamic testing sebelum dijadikan
laporan final.
"""


# ---------------------------------------------------------------------------
# 8. Lampiran — referensi aturan

def _rules_appendix(findings: list[dict[str, Any]]) -> str:
    seen_rules: dict[str, str] = {}
    for f in findings:
        rule  = f.get("rule", "")
        title = f.get("title", "")
        if rule and rule not in seen_rules:
            seen_rules[rule] = title

    if not seen_rules:
        return "_Tidak ada aturan yang aktif di scan ini._"

    lines = ["| Rule | Kelas | Deskripsi |", "|---|---|---|"]
    for rule in sorted(seen_rules):
        lines.append(
            f"| `{rule}` | {_rule_class(rule)} | {_md_escape(seen_rules[rule])} |"
        )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Public API

def render_markdown_report(
    report: dict[str, Any],
    recs: list[Recommendation] | None = None,
) -> str:
    """
    Render report dict menjadi string Markdown GitHub-flavored.
    recs: list Recommendation dari recommend.build_recommendations().
    Bila None, fungsi ini menghitung sendiri.
    """
    if recs is None:
        from app.cli.recommend import build_recommendations
        recs = build_recommendations(report.get("findings", []))

    meta    = report.get("meta", {})
    repo    = meta.get("repo", {})
    owner   = repo.get("owner", "")
    rname   = repo.get("repo", "")
    heading = f"{owner}/{rname}" if owner and rname else meta.get("scan_id", "")

    findings: list[dict[str, Any]] = report.get("findings", [])

    parts = [
        _frontmatter(report),
        "",
        f"# Laporan Audit Keamanan — {_esc(heading)}",
        "",
        "## 1. Ringkasan Eksekutif",
        "",
        _executive_summary(report),
        "",
        "---",
        "",
        "## 2. Target yang Dianalisis",
        "",
        _target_table(report),
        "",
        "---",
        "",
        "## 3. Ringkasan Temuan",
        "",
        _summary_table(report),
        "",
        "---",
        "",
        "## 4. Detail Temuan",
        "",
    ]

    if not findings:
        parts.append("_Tidak ada temuan._")
    else:
        for i, f in enumerate(findings, 1):
            parts.append(_finding_section(i, f))

    parts += [
        "---",
        "",
        "## 5. Rekomendasi Perbaikan (terprioritas)",
        "",
        _recommendations_section(recs),
        "---",
        "",
        "## 6. Catatan Metodologi & Batasan",
        "",
        _METHODOLOGY,
        "---",
        "",
        "## 7. Lampiran — Referensi Aturan",
        "",
        _rules_appendix(findings),
        "",
        "---",
        "",
        f"_Laporan dihasilkan oleh [Cyense](https://github.com/) v{_VERSION}. "
        "Analisis bersifat read-only — kode tidak pernah dieksekusi._",
        "",
    ]

    return "\n".join(parts)


def dump_markdown_report(
    report: dict[str, Any],
    path: Path,
    recs: list[Recommendation] | None = None,
) -> Path:
    """
    Tulis markdown report ke path (parent dir dibuat bila perlu).
    Penulisan atomik ditangani oleh pemanggil (main.py: tulis ke .tmp → rename).
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_markdown_report(report, recs=recs), encoding="utf-8")
    return path
