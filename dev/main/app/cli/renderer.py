"""Renderer — semua output terminal melalui modul ini.

Struktur blok (cli-experience.md §3.3):
  Blok 1  — Banner + panel TARGET
  Blok 2  — Log proses analisis repository (stage timeline + progress bar)
  Blok 3  — Log vulnerability (kartu streaming + tabel rekap)
  Blok 4  — Panel saran perbaikan
  Blok 5  — Footer artefak

Seluruh nilai dari repo (nama file, cuplikan kode, judul temuan) melewati
_esc() sebelum dirender untuk mencegah injeksi ANSI escape (cli-experience.md §6.4).
"""

from __future__ import annotations

import re
import time
from typing import Any

from rich.console import Console  # type: ignore[import-untyped]
from rich.table import Table  # type: ignore[import-untyped]
from rich.text import Text  # type: ignore[import-untyped]

from app.cli.models import (
    Recommendation,
    RenderContext,
    StageInfo,
)
from app.cli.theme import PALETTE, TermCaps

# ---------------------------------------------------------------------------
# Sanitasi: buang karakter kontrol dari data eksternal (§6.4)

_CTRL_RE = re.compile(r"[\x00-\x1f\x7f\x9b-\x9f]|\x1b\[[0-9;]*[mA-Za-z]")


def _esc(value: Any) -> str:
    """Strip control chars + ANSI sequences dari nilai eksternal."""
    s = str(value) if not isinstance(value, str) else value
    return _CTRL_RE.sub("", s)


# ---------------------------------------------------------------------------
# Blok 1 — Banner

def render_banner(console: Console, caps: TermCaps, version: str = "2.0.0") -> None:
    w = caps.width
    p = PALETTE
    g = caps.g()

    if caps.width < 40:
        console.print(f"[bold {p.blue_primary}]CYENSE v{version}[/]")
        return

    title = "C Y E N S E"
    subtitle = "Cyber Insight Engine"
    tagline = "Audit statis IDOR & XSS untuk repository GitHub"

    ver_str = f"v{version}"
    inner = w - 4  # 2 border + 2 spasi

    top    = f"[{p.blue_primary}]{g.tl}{g.h * (w - 2)}{g.tr}[/]"
    line1  = (
        f"[{p.blue_primary}]{g.v}[/]  "
        f"[bold {p.blue_primary}]{title}[/]"
        f"[{p.blue_soft}]  ·  {subtitle}[/]"
        + " " * max(0, inner - len(title) - len(subtitle) - len(ver_str) - 7)
        + f"[{p.muted}]{ver_str}[/]"
        + f"  [{p.blue_primary}]{g.v}[/]"
    )
    line2  = (
        f"[{p.blue_primary}]{g.v}[/]  "
        f"[{p.muted}]{tagline}[/]"
        + " " * max(0, inner - len(tagline))
        + f"  [{p.blue_primary}]{g.v}[/]"
    )
    bottom = f"[{p.blue_primary}]{g.bl}{g.h * (w - 2)}{g.br}[/]"

    console.print(top)
    console.print(line1)
    console.print(line2)
    console.print(bottom)
    console.print()


# ---------------------------------------------------------------------------
# Blok 1 — Panel TARGET

def render_target_panel(
    console: Console,
    caps: TermCaps,
    scan_id: str,
    mode: str,
    meta: dict[str, Any] | None = None,
) -> None:
    p = PALETTE
    g = caps.g()
    sep = f"[{p.rule_line}]{g.h * caps.width}[/]"

    label_w = 14

    def kv(label: str, value: str) -> str:
        lbl = label.rjust(label_w)
        return (
            f"  [{p.blue_soft}]{lbl}[/]  "
            f"[bold {p.ink}]{_esc(value)}[/]"
        )

    console.print(f"  [bold {p.blue_primary}]TARGET[/]")
    console.print(sep)

    if meta and "repo" in meta:
        r = meta["repo"]
        console.print(kv("repository", r.get("owner", "—") + "/" + r.get("repo", "—")))
        console.print(kv("ref", r.get("ref") or "—"))
        console.print(kv("commit", r.get("commit_sha") or "—"))
        lang = meta.get("lang_detected") or r.get("lang_detected") or "auto-detect"
        size_bytes = r.get("size_bytes", 0)
        size_str = f"{size_bytes / 1_048_576:.1f} MB" if size_bytes else "—"
        console.print(kv("ukuran", size_str))
        console.print(kv("bahasa", lang))
    elif mode == "program":
        console.print(kv("mode", "program (source lokal)"))
    elif mode == "link":
        url = (meta or {}).get("url", "—")
        console.print(kv("url", _esc(url)))

    console.print(kv("scan_id", scan_id))
    console.print()


# ---------------------------------------------------------------------------
# Blok 2 — Stage timeline

def _stage_line(
    caps: TermCaps,
    info: StageInfo,
    is_current: bool,
    spinner_frame: str,
    last_event: str = "",
) -> Text:
    p = PALETTE
    g = caps.g()
    t = Text()

    # Status marker
    if info.status == "done":
        t.append(f"  {g.ok} ", style=f"bold {p.ok}")
    elif info.status == "failed":
        t.append(f"  {g.fail} ", style=f"bold {p.error}")
    elif is_current:
        t.append(f"  {g.active} ", style=f"bold {p.blue_accent}")
    else:
        t.append("    ", style="")

    # Timestamp + stage name
    ts = time.strftime("%H:%M:%S")
    t.append(f"{ts}  ", style=p.muted)
    t.append(f"{info.name:<10}", style=f"bold {p.blue_primary}" if is_current else p.ink)

    # Spinner / message / elapsed
    if is_current:
        msg = _esc(last_event)[:40] if last_event else ""
        t.append(f" {spinner_frame} {msg}", style=p.blue_accent)
    elif info.status == "done" and info.elapsed is not None:
        elapsed_str = f"{info.elapsed:.2f}s"
        t.append(info.last_message[:40] if info.last_message else "", style=p.muted)
        t.append(f"  {elapsed_str:>8}", style=p.muted)
    elif info.status == "pending":
        t.append("menunggu", style=p.muted)

    return t


def render_stage_section(
    console: Console,
    caps: TermCaps,
    ctx: RenderContext,
    spinner_frame: str = "⠋",
    new_events: list[str] | None = None,
) -> None:
    p = PALETTE
    g = caps.g()
    sep = f"[{p.rule_line}]{g.h * caps.width}[/]"

    console.print(f"  [bold {p.blue_primary}]ANALISIS[/]")
    console.print(sep)

    for stage_name in ctx.stages:
        info = ctx.stage_info.get(stage_name, StageInfo(name=stage_name))
        is_current = stage_name == ctx.current_stage

        # Ambil pesan terakhir dari events baru
        last_event = ""
        if is_current and new_events:
            last_event = new_events[-1].split(" ", 2)[-1] if new_events else ""
            if info:
                info.last_message = last_event

        line = _stage_line(caps, info, is_current, spinner_frame, last_event)
        console.print(line)

    # Progress bar
    console.print()
    _render_progress_bar(console, caps, ctx.progress, ctx.current_stage or "")
    console.print()


def _render_progress_bar(
    console: Console,
    caps: TermCaps,
    progress: int,
    stage: str,
) -> None:
    p = PALETTE
    bar_w = min(caps.width - 20, 50)
    filled = int(bar_w * progress / 100)
    empty = bar_w - filled

    bar = (
        f"[{p.blue_accent}]{'█' * filled}[/]"
        f"[{p.muted}]{'░' * empty}[/]"
        f"  [{p.ink}]{progress:3d}%[/]"
        f"  [{p.muted}]{_esc(stage)}[/]"
    )
    console.print(f"  {bar}")


# ---------------------------------------------------------------------------
# Blok 3 — Kartu finding (streaming)

def render_finding_card(
    console: Console,
    caps: TermCaps,
    finding: dict[str, Any],
) -> None:
    p = PALETTE
    g = caps.g()

    severity = _esc(finding.get("severity", "info")).lower()
    rule     = _esc(finding.get("rule", "—"))
    conf     = finding.get("confidence", 0.0)
    title    = _esc(finding.get("title", "(untitled)"))
    location = _esc(finding.get("location") or "")
    desc     = _esc(finding.get("description") or "")

    # Cuplikan bukti (maks 3 baris)
    evidence = finding.get("evidence") or {}
    snippet: str = ""
    if isinstance(evidence, dict):
        snippet = _esc(evidence.get("snippet") or evidence.get("code") or "")
    if snippet:
        lines = snippet.splitlines()[:3]
        snippet = "\n".join("        " + ln for ln in lines)

    from app.cli.theme import SEVERITY_BADGE_COLOR
    badge_color = SEVERITY_BADGE_COLOR.get(severity, p.muted)
    sev_glyph   = caps.badge_glyph(severity)

    # Severity glyph + badge
    console.print(
        f"   [{badge_color}]{sev_glyph} {severity.upper():<9}[/]  "
        f"[bold {p.blue_soft}]{rule}[/]  "
        f"[{p.muted}]conf {conf:.2f}[/]"
    )
    console.print(f"      [{p.ink}]{title}[/]")
    if desc and desc != title:
        console.print(f"      [{p.muted}]{desc[:80]}[/]")
    if location:
        console.print(f"      [{p.blue_accent}]{g.arrow}[/] [{p.blue_mist}]{location}[/]")
    if snippet:
        console.print(f"[{p.muted}]{snippet}[/]")
    console.print()


# ---------------------------------------------------------------------------
# Blok 3 — Tabel rekap findings

def render_findings_table(
    console: Console,
    caps: TermCaps,
    findings: list[dict[str, Any]],
    summary: dict[str, Any],
) -> None:
    p = PALETTE
    g = caps.g()
    sep = f"[{p.rule_line}]{g.h * caps.width}[/]"

    console.print(f"  [bold {p.blue_primary}]RINGKASAN TEMUAN[/]")
    console.print(sep)

    if not findings:
        console.print(f"  [{p.ok}]Tidak ada temuan — repository terlihat bersih.[/]")
        console.print()
        return

    # Tabel Rich
    table = Table(
        show_header=True,
        header_style=f"bold {p.blue_primary}",
        border_style=p.rule_line,
        show_lines=False,
        padding=(0, 1),
        expand=False,
    )
    table.add_column("RULE",     style=f"bold {p.blue_soft}", width=7)
    table.add_column("SEVERITY", width=10)
    table.add_column("CVSS",     justify="right", width=5, style=p.muted)
    table.add_column("CONF",     justify="right", width=5, style=p.muted)
    table.add_column("LOCATION", style=p.blue_mist, max_width=35)
    table.add_column("TITLE",    style=p.ink,       max_width=30)

    from app.cli.theme import SEVERITY_BADGE_COLOR
    for f in findings:
        sev = _esc(f.get("severity", "info")).lower()
        bc  = SEVERITY_BADGE_COLOR.get(sev, p.muted)
        cvss_score = f.get("cvss_score")
        cvss_str = f"{cvss_score:.1f}" if cvss_score is not None else "—"
        table.add_row(
            _esc(f.get("rule", "—")),
            f"[{bc}]{sev.upper()}[/]",
            cvss_str,
            f"{f.get('confidence', 0):.2f}",
            _esc(f.get("location") or "—"),
            _esc(f.get("title", "—"))[:30],
        )

    console.print(table)
    console.print()

    # Ringkasan baris bawah
    chips = []
    for sev in ("critical", "high", "medium", "low", "info"):
        cnt = summary.get(sev, 0)
        if cnt:
            from app.cli.theme import SEVERITY_BADGE_COLOR
            bc = SEVERITY_BADGE_COLOR.get(sev, p.muted)
            chips.append(f"[{bc}]{sev}[/] [{p.ink}]{cnt}[/]")
    chips.append(f"[{p.muted}]total[/] [{p.ink}]{summary.get('total', len(findings))}[/]")

    files  = summary.get("files_scanned") or summary.get("files_analyzed", "—")
    dur_ms = summary.get("duration_ms", 0)
    dur_s  = f"{dur_ms / 1000:.2f}s" if dur_ms else "—"

    console.print("  " + "  ·  ".join(chips))
    console.print(f"  [{p.muted}]{files} file dipindai dalam {dur_s}[/]")
    console.print()


# ---------------------------------------------------------------------------
# Blok 4 — Panel saran perbaikan

def render_cve_table(
    console: Console,
    caps: TermCaps,
    cve_findings: list[dict[str, Any]],
    summary: dict[str, Any],
) -> None:
    """Render CVE findings (CVE-MATCH) in a dedicated table.

    Shows CVE id, severity, CVSS score, source (local/NVD), verified status,
    affected component, and a short description + reference.
    """
    p = PALETTE
    g = caps.g()
    sep = f"[{p.rule_line}]{g.h * caps.width}[/]"

    if not cve_findings:
        console.print(f"  [{p.ok}]Tidak ada CVE yang cocok untuk teknologi terdeteksi.[/]")
        console.print()
        return

    console.print(f"  [bold {p.blue_primary}]CVE / KERENTANAN TERKENAL[/]")
    console.print(f"  [{p.muted}]Sumber: database lokal + pencarian live (NVD/MITRE)[/]")
    console.print(sep)

    table = Table(
        show_header=True,
        header_style=f"bold {p.blue_primary}",
        border_style=p.rule_line,
        show_lines=False,
        padding=(0, 1),
        expand=False,
    )
    table.add_column("CVE",       style=f"bold {p.blue_soft}", width=18)
    table.add_column("SEVERITY",  width=10)
    table.add_column("CVSS",      justify="right", width=6, style=p.muted)
    table.add_column("SRC",       width=6)
    table.add_column("VERIFIED",  width=9)
    table.add_column("KOMPONEN",  style=p.blue_mist, max_width=16)
    table.add_column("DESKRIPSI", style=p.ink, max_width=48)

    from app.cli.theme import SEVERITY_BADGE_COLOR
    for f in cve_findings:
        sev = _esc(f.get("severity", "info")).lower()
        bc = SEVERITY_BADGE_COLOR.get(sev, p.muted)
        ev = f.get("evidence", {})
        cvss = ev.get("cvss_score")
        cvss_str = f"{cvss:.1f}" if cvss is not None else "—"
        verified = "ya" if ev.get("verified") else "potensial"
        component = _esc(ev.get("component") or "?")
        desc = _esc(f.get("description", ""))[:48]
        table.add_row(
            _esc(ev.get("cve") or f.get("title", "—"))[:18],
            f"[{bc}]{sev.upper()}[/]",
            cvss_str,
            _esc(ev.get("source", "?")),
            f"[{p.ok if ev.get('verified') else p.sev_medium}]{verified}[/]",
            component,
            desc,
        )

    console.print(table)
    console.print()

    # Reference lines
    for f in cve_findings:
        ev = f.get("evidence", {})
        ref = ev.get("ref")
        cve_id = ev.get("cve")
        if ref:
            console.print(f"  [{p.blue_soft}]→[/] [{p.ink}]{cve_id}[/]  {ref}")
    console.print()

    total_cves = len(cve_findings)
    verified_cnt = sum(1 for f in cve_findings if f.get("evidence", {}).get("verified"))
    console.print(
        f"  [{p.muted}]Total {total_cves} CVE "
        f"({verified_cnt} terverifikasi versi, {total_cves - verified_cnt} potensial)[/]"
    )
    console.print()


def render_recommendations(
    console: Console,
    caps: TermCaps,
    recs: list[Recommendation],
    scan_id: str,
) -> None:
    p = PALETTE
    g = caps.g()
    sep = f"[{p.rule_line}]{g.h * caps.width}[/]"

    console.print(f"  [bold {p.blue_primary}]SARAN PERBAIKAN[/]")
    console.print(sep)

    if not recs:
        console.print(f"  [{p.ok}]Tidak ada saran — tidak ada temuan yang terdeteksi.[/]")
        console.print()
        return

    from app.cli.theme import SEVERITY_BADGE_COLOR
    for i, rec in enumerate(recs, 1):
        bc     = SEVERITY_BADGE_COLOR.get(rec.severity, p.muted)
        marker = g.priority if rec.category in ("priority", "structural") else g.minor
        label  = rec.label

        console.print(
            f"  [{p.muted}]{i:>2}[/]  [{p.blue_accent}]{marker}[/]"
            f" [bold {p.blue_primary}]{label}[/]"
            f" · [{p.blue_soft}]{rec.rule}[/]"
            f" · [{p.muted}]{rec.occurrences} temuan[/]"
            f" · [{bc}]{rec.severity}[/]"
        )

        # Teks tindakan (word-wrap manual)
        action_lines = _wrap(_esc(rec.action), caps.width - 8)
        for ln in action_lines:
            console.print(f"     [{p.ink}]{ln}[/]")

        if rec.affected:
            affected_str = ", ".join(_esc(a) for a in rec.affected)
            console.print(f"     [{p.muted}]Terdampak: {affected_str}[/]")
        console.print()

    console.print(
        f"  [{p.blue_soft}]Jalankan [bold]cyense fix {scan_id}[/bold]"
        f" untuk melihat usulan patch otomatis.[/]"
    )
    console.print()


def render_scope_warning(
    console: Console,
    caps: TermCaps,
    scope_mode: str,
    files_scanned: int,
    files_excluded: int,
) -> None:
    """Render warning for diff-scope (ci-compliance-reporting.md §3.7.2)."""
    if scope_mode not in ("diff", "auto"):
        return

    p = PALETTE
    g = caps.g()

    if files_excluded > 0:
        console.print(
            f"  [{p.sev_medium}]{g.warn} Scan dibatasi pada {files_scanned} file yang berubah. "
            f"{files_excluded} file lain TIDAK diperiksa — lihat coverage.json.[/]"
        )
        console.print()


def _wrap(text: str, width: int) -> list[str]:
    """Word-wrap sederhana tanpa dependensi textwrap (agar testable)."""
    if width < 10:
        return [text]
    words = text.split()
    lines: list[str] = []
    current: list[str] = []
    cur_len = 0
    for w in words:
        if cur_len + len(w) + (1 if current else 0) > width:
            if current:
                lines.append(" ".join(current))
            current = [w]
            cur_len = len(w)
        else:
            current.append(w)
            cur_len += len(w) + (1 if len(current) > 1 else 0)
    if current:
        lines.append(" ".join(current))
    return lines or [""]


# ---------------------------------------------------------------------------
# Blok 5 — Footer artefak

def render_footer(
    console: Console,
    caps: TermCaps,
    scan_id: str,
    md_path: str | None,
    base_url: str,
    duration_s: float,
    exit_code: int,
) -> None:
    p = PALETTE
    g = caps.g()
    sep = f"[{p.rule_line}]{g.h * caps.width}[/]"

    console.print(sep)

    if md_path:
        console.print(
            f"   [{p.ok}]{g.ok}[/] [{p.blue_soft}]Laporan Markdown[/]  "
            f"[{p.blue_mist}]{md_path}[/]"
        )
    console.print(
        f"     [{p.muted}]Laporan JSON[/]      [{p.muted}]reports/{scan_id}/report.json[/]"
    )
    console.print(
        f"     [{p.muted}]Laporan HTML[/]      "
        f"[{p.muted}]{base_url}/api/v1/scans/{scan_id}/report/html[/]"
    )
    console.print(
        f"     [{p.muted}]Trajectories[/]      "
        f"[{p.muted}]reports/{scan_id}/trajectories/[/]"
    )
    console.print()

    code_style = p.ok if exit_code == 0 else (p.error if exit_code == 2 else p.sev_medium)
    code_label = {0: "bersih", 1: "--fail-on terpenuhi", 2: "scan gagal", 3: "error koneksi"}.get(
        exit_code, f"exit {exit_code}"
    )
    console.print(
        f"  [{p.muted}]Selesai dalam {duration_s:.2f}s[/]"
        f" · [{code_style}]exit {exit_code} ({code_label})[/]"
    )


# ---------------------------------------------------------------------------
# Panel error / peringatan

def render_error_panel(
    console: Console,
    caps: TermCaps,
    message: str,
    hint: str = "",
) -> None:
    p = PALETTE
    g = caps.g()

    console.print()
    console.print(f"  [{p.sev_high}]{g.warn}  SCAN GAGAL[/]")
    console.print(f"     [{p.ink}]{_esc(message)}[/]")
    if hint:
        console.print(f"     [{p.muted}]Saran: {_esc(hint)}[/]")
    console.print()


# ---------------------------------------------------------------------------
# Discovery renderer — grouped display of HackerOne-tools findings

def render_discovery_table(
    console: Console,
    caps: TermCaps,
    findings: list[dict[str, Any]],
) -> None:
    """Render discovery findings (SECRET/EXPOSED/DISC/SSRF/GRAPHQL/WP).

    Groups findings by category and renders each with a compact table so
    recon output stays readable (adaptation of the HackerOne 104 tools).
    """
    p = PALETTE
    g = caps.g()
    sep = f"[{p.rule_line}]{g.h * caps.width}[/]"

    secrets = [f for f in findings if f.get("rule") == "SECRET-LEAK"]
    exposed = [f for f in findings if f.get("rule") == "EXPOSED-FILE"]
    wp = [f for f in findings if f.get("rule") == "WP-EXPOSED"]
    ssrf = [f for f in findings if f.get("rule") == "SSRF-SINK"]
    graphql = [f for f in findings if f.get("rule") == "GRAPHQL-INTROSPECTION"]
    subs = [f for f in findings if f.get("rule") == "DISC-SUBDOMAIN"]
    api = [f for f in findings if f.get("rule") == "DISC-API-ENDPOINT"]
    js = [f for f in findings if f.get("rule") == "DISC-JS-URL"]
    params = [f for f in findings if f.get("rule") == "DISC-HIDDEN-PARAM"]
    wayback = [f for f in findings if f.get("rule") == "DISC-WAYBACK"]
    vhosts = [f for f in findings if f.get("rule") == "DISC-VHOST"]
    dirs = [f for f in findings if f.get("rule") == "DISC-PATH"]

    total = len(secrets) + len(exposed) + len(wp) + len(ssrf) + len(graphql) \
        + len(subs) + len(api) + len(js) + len(params) + len(wayback) \
        + len(vhosts) + len(dirs)
    if total == 0:
        console.print(f"  [{p.ok}]Tidak ada temuan discovery (recon bersih).[/]")
        console.print()
        return

    console.print(f"  [bold {p.blue_primary}]DISCOVERY / RECON[/]")
    console.print(
        f"  [{p.muted}]Adaptasi: TruffleHog · Nikto · Subfinder · "
        "Kiterunner · Wpscan · Arjun · SSRFTest[/]"
    )
    console.print(sep)

    # Secrets (always on top)
    if secrets:
        console.print(f"  [bold {p.error}]SECRET TER-EXPOSE ({len(secrets)})[/]")
        for f in secrets:
            ev = f.get("evidence", {})
            console.print(
                f"  [{p.error}]▸[/] {ev.get('secret_type','?')} — {ev.get('count',1)}x "
                f"[{p.muted}]{', '.join((f.get('evidence') or {}).get('samples', [])[:2])}[/]"
            )
        console.print()

    # Exposed files + admin panels
    if exposed:
        console.print(f"  [bold {p.error}]FILE/PANEL TER-EXPOSE ({len(exposed)})[/]")
        for f in exposed:
            ev = f.get("evidence", {})
            console.print(
                f"  [{p.error}]▸[/] {ev.get('path','?')}  [{p.muted}]HTTP {ev.get('status','?')}[/]"
            )
        console.print()

    # WordPress
    if wp:
        console.print(f"  [bold {p.sev_high}]WORDPRESS TER-EXPOSE ({len(wp)})[/]")
        for f in wp:
            ev = f.get("evidence", {})
            console.print(
                f"  [{p.sev_high}]▸[/] {ev.get('path','?')}  "
                f"[{p.muted}]HTTP {ev.get('status','?')}[/]"
            )
        console.print()

    # SSRF sinks + GraphQL
    if ssrf:
        console.print(f"  [bold {p.sev_high}]SSRF SINK ({len(ssrf)})[/]")
        for f in ssrf:
            ev = f.get("evidence", {})
            console.print(f"  [{p.sev_high}]▸[/] params: {', '.join(ev.get('params', []))}")
        console.print()
    if graphql:
        console.print(f"  [bold {p.sev_high}]GRAPHQL INTROSPECTION AKTIF[/]")
        console.print()

    # Subdomains
    if subs:
        sub_count = sum(len((f.get("evidence") or {}).get("subdomains", [])) for f in subs)
        console.print(f"  [bold {p.blue_soft}]SUBDOMAIN ({sub_count})[/]")
        chips = []
        for f in subs:
            chips.extend((f.get("evidence") or {}).get("subdomains", []))
        console.print("  " + "  ".join(f"[{p.blue_mist}]{s}[/]" for s in chips[:20]))
        console.print()

    # API endpoints + dirs
    if api:
        api_count = sum((f.get("evidence") or {}).get("count", 0) for f in api)
        console.print(f"  [bold {p.blue_soft}]API ENDPOINTS ({api_count})[/]")
        for f in api:
            eps = (f.get("evidence") or {}).get("endpoints", [])
            console.print("  " + "  ".join(f"[{p.blue_mist}]{e}[/]" for e in eps[:20]))
        console.print()
    if dirs:
        console.print(f"  [bold {p.blue_soft}]DIREKTORI ({len(dirs)})[/]")
        for f in dirs:
            ev = f.get("evidence", {})
            console.print(f"  [{p.blue_mist}]▸[/] {ev.get('path','?')}")
        console.print()

    # JS URLs / wayback / vhost / hidden params
    misc_rows = []
    if js:
        for f in js:
            misc_rows.append(
                f"[{p.blue_mist}]JS URLs[/] "
                f"{(f.get('evidence') or {}).get('count', 0)} endpoint diekstrak"
            )
    if wayback:
        for f in wayback:
            misc_rows.append(
                f"[{p.blue_mist}]Wayback[/] "
                f"{(f.get('evidence') or {}).get('count', 0)} URL historis"
            )
    if vhosts:
        for f in vhosts:
            vhs = (f.get("evidence") or {}).get("vhosts", [])
            misc_rows.append(f"[{p.blue_mist}]VHosts[/] {', '.join(vhs[:8])}")
    if params:
        for f in params:
            ev = f.get("evidence", {})
            misc_rows.append(f"[{p.blue_mist}]Hidden params[/] {ev.get('param','?')}")
    if misc_rows:
        console.print(f"  [bold {p.blue_soft}]REKON LAIN[/]")
        for row in misc_rows:
            console.print(f"  {row}")
        console.print()
