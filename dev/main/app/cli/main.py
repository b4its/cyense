"""CLI entrypoint — Typer app `cyense`.

Subcommand:
  scan github <repo_url>   — audit repo GitHub (jalur utama)
  scan program             — audit source lokal
  scan link <url>          — probing IDOR dinamis
  report <scan_id>         — render ulang laporan lama
  list                     — tabel scan terakhir
  rules                    — katalog aturan aktif
  fix <scan_id>            — usulan patch remediasi
  version                  — versi CLI + service

Arsitektur: CLI HANYA bicara ke API lewat HTTP (app/cli/client.py).
TIDAK mengimpor app.engines, app.agents, app.program, app.worker.
Lihat: instruction/feature/cli-experience.md §5.4
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import signal
import sys
import time
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console  # type: ignore[import-untyped]

from app.cli.client import CyenseClient, load_report_from_disk, open_client, poll_scan
from app.cli.models import MODE_STAGES, RenderContext, StageInfo
from app.cli.recommend import build_recommendations
from app.cli.renderer import (
    render_banner,
    render_error_panel,
    render_finding_card,
    render_findings_table,
    render_footer,
    render_recommendations,
    render_stage_section,
    render_target_panel,
)
from app.cli.theme import TermCaps, detect_caps, make_rich_console
from app.report.md_report import dump_markdown_report

# ---------------------------------------------------------------------------
# App & opsi global

app = typer.Typer(
    name="cyense",
    help="Cyense — Cyber Insight Engine: audit IDOR & XSS repository GitHub.",
    no_args_is_help=True,
    add_completion=False,
    rich_markup_mode="rich",
)

scan_app = typer.Typer(help="Jalankan scan keamanan.", no_args_is_help=True)
app.add_typer(scan_app, name="scan")

_VERSION = "2.0.0"


# ---------------------------------------------------------------------------
# State global (disiapkan oleh callback utama sebelum subcommand berjalan)

class _State:
    api_url: str = "http://localhost:8000"
    caps: TermCaps = detect_caps()
    console: Console = make_rich_console(caps)
    timeout: float = 300.0
    json_out: bool = False


_state = _State()


@app.callback()
def _global(
    api_url: Annotated[
        str, typer.Option("--api-url", envvar="CYENSE_API_URL", help="URL service Cyense.")
    ] = "http://localhost:8000",
    no_color: Annotated[bool, typer.Option("--no-color", help="Matikan warna.")] = False,
    ascii_mode: Annotated[
        bool, typer.Option("--ascii", help="Paksa glyph ASCII.")
    ] = False,
    quiet: Annotated[bool, typer.Option("--quiet", "-q", help="Ringkas.")] = False,
    json_out: Annotated[bool, typer.Option("--json", help="Output JSON mentah.")] = False,
    timeout: Annotated[
        float, typer.Option("--timeout", help="Batas waktu tunggu scan (detik).")
    ] = 300.0,
) -> None:
    """Cyense CLI — thin client ke FastAPI service."""
    _state.api_url = api_url.rstrip("/")
    _state.timeout = timeout
    _state.json_out = json_out

    caps = detect_caps(
        force_no_color=no_color,
        force_ascii=ascii_mode,
        force_quiet=quiet,
        force_json=json_out,
        width_override=shutil.get_terminal_size((100, 24)).columns,
    )
    _state.caps = caps
    _state.console = make_rich_console(caps)


# ---------------------------------------------------------------------------
# Helper: jalankan coroutine dari konteks sync Typer

def _run(coro) -> None:
    asyncio.run(coro)


# ---------------------------------------------------------------------------
# scan github

@scan_app.command("github")
def scan_github(
    repo_url: Annotated[str, typer.Argument(help="URL repository GitHub (https://github.com/...)")],
    ref: Annotated[Optional[str], typer.Option("--ref", help="Branch / tag / commit SHA.")] = None,
    subdir: Annotated[
        Optional[str], typer.Option("--subdir", help="Batasi analisis ke subfolder.")
    ] = None,
    lang: Annotated[
        str, typer.Option("--lang", help="Bahasa: python|js|php|auto.")
    ] = "auto",
    token: Annotated[
        Optional[str], typer.Option("--token", envvar="CYENSE_GITHUB_TOKEN", help="GitHub token.")
    ] = None,
    force: Annotated[bool, typer.Option("--force", help="Abaikan cache Brain.")] = False,
    i_have_permission: Annotated[
        bool,
        typer.Option(
            "--i-have-permission",
            help="[wajib] Konfirmasi bahwa Anda berhak mengaudit repository ini.",
        ),
    ] = False,
    out: Annotated[
        Optional[str], typer.Option("--out", help="Path output .md.")
    ] = None,
    no_md: Annotated[bool, typer.Option("--no-md", help="Jangan tulis .md.")] = False,
    fail_on: Annotated[
        str,
        typer.Option(
            "--fail-on",
            help="Exit 1 bila ada temuan ≥ severity ini (none|info|low|medium|high|critical).",
        ),
    ] = "none",
    min_severity: Annotated[
        str,
        typer.Option("--min-severity", help="Sembunyikan temuan di bawah severity ini (tampilan)."),
    ] = "info",
    scan_mode: Annotated[
        str,
        typer.Option(
            "--scan-mode",
            help="Mode scan: quick (cepat, IDOR saja), standard (default, IDOR+XSS), deep (komprehensif).",
        ),
    ] = "standard",
    scope_mode: Annotated[
        str,
        typer.Option(
            "--scope-mode",
            help="Mode cakupan: auto (otomatis), full (semua file), diff (hanya perubahan).",
        ),
    ] = "auto",
) -> None:
    """Audit repository GitHub — jalur input utama Cyense."""
    # Peringatan keamanan token di argumen (§6.2)
    if token and sys.argv and "--token" in " ".join(sys.argv):
        _state.console.print(
            f"  [{_state.caps.g().warn}] token diberikan lewat argumen; "
            f"pertimbangkan env CYENSE_GITHUB_TOKEN agar tidak tersimpan di riwayat shell."
        )

    payload: dict = {
        "mode": "github",
        "repo_url": repo_url,
        "lang": lang,
        "force": force,
        "i_have_permission": i_have_permission,
        "scan_mode": scan_mode,
        "scope_mode": scope_mode,
    }
    if ref:
        payload["ref"] = ref
    if subdir:
        payload["subdir"] = subdir
    if token:
        payload["github_token"] = token  # tidak pernah dicetak (redaksi di api/engine)

    _run(_run_scan(
        payload=payload,
        mode="github",
        out_path=out,
        no_md=no_md,
        fail_on=fail_on,
        min_severity=min_severity,
    ))


# ---------------------------------------------------------------------------
# scan program

@scan_app.command("program")
def scan_program(
    lang: Annotated[
        str, typer.Option("--lang", help="Bahasa: python|js|php.")
    ] = "python",
    source_type: Annotated[
        str, typer.Option("--source-type", help="mounted|sample.")
    ] = "mounted",
    i_have_permission: Annotated[
        bool, typer.Option("--i-have-permission", help="[wajib] Konfirmasi izin audit.")
    ] = False,
    out: Annotated[Optional[str], typer.Option("--out")] = None,
    no_md: Annotated[bool, typer.Option("--no-md")] = False,
    fail_on: Annotated[str, typer.Option("--fail-on")] = "none",
    min_severity: Annotated[str, typer.Option("--min-severity")] = "info",
    scan_mode: Annotated[
        str,
        typer.Option(
            "--scan-mode",
            help="Mode scan: quick (cepat, IDOR saja), standard (default, IDOR+XSS), deep (komprehensif).",
        ),
    ] = "standard",
    scope_mode: Annotated[
        str,
        typer.Option(
            "--scope-mode",
            help="Mode cakupan: auto (otomatis), full (semua file), diff (hanya perubahan).",
        ),
    ] = "auto",
) -> None:
    """Audit source code lokal (mounted / sample)."""
    payload = {
        "mode": "program",
        "lang": lang,
        "source_type": source_type,
        "i_have_permission": i_have_permission,
        "scan_mode": scan_mode,
        "scope_mode": scope_mode,
    }
    _run(_run_scan(
        payload=payload,
        mode="program",
        out_path=out,
        no_md=no_md,
        fail_on=fail_on,
        min_severity=min_severity,
    ))


# ---------------------------------------------------------------------------
# scan link

@scan_app.command("link")
def scan_link(
    url: Annotated[str, typer.Argument(help="URL target (http/https dengan placeholder {ID}).")],
    i_have_permission: Annotated[
        bool, typer.Option("--i-have-permission", help="[wajib] Konfirmasi izin audit.")
    ] = False,
    fail_on: Annotated[str, typer.Option("--fail-on")] = "none",
    min_severity: Annotated[str, typer.Option("--min-severity")] = "info",
    out: Annotated[Optional[str], typer.Option("--out")] = None,
    no_md: Annotated[bool, typer.Option("--no-md")] = False,
    scan_mode: Annotated[
        str,
        typer.Option(
            "--scan-mode",
            help="Mode scan: quick (cepat, IDOR saja), standard (default, IDOR+XSS), deep (komprehensif).",
        ),
    ] = "standard",
    scope_mode: Annotated[
        str,
        typer.Option(
            "--scope-mode",
            help="Mode cakupan: auto (otomatis), full (semua file), diff (hanya perubahan).",
        ),
    ] = "auto",
) -> None:
    """Probing IDOR dinamis pada URL live."""
    payload = {
        "mode": "link",
        "url": url,
        "i_have_permission": i_have_permission,
        "scan_mode": scan_mode,
        "scope_mode": scope_mode,
    }
    _run(_run_scan(
        payload=payload,
        mode="link",
        out_path=out,
        no_md=no_md,
        fail_on=fail_on,
        min_severity=min_severity,
    ))


# ---------------------------------------------------------------------------
# Inti: _run_scan (shared oleh semua `scan *`)

async def _run_scan(
    *,
    payload: dict,
    mode: str,
    out_path: str | None,
    no_md: bool,
    fail_on: str,
    min_severity: str,
) -> None:
    caps = _state.caps
    console = _state.console
    started_wall = time.monotonic()

    # -- Setup SIGINT handler agar kursor selalu dipulihkan (§6.4)
    original_sigint = signal.getsignal(signal.SIGINT)
    _md_tmp: list[Path] = []

    def _handle_sigint(sig, frame):
        console.print()
        console.print(f"  [{caps.g().warn}] Dibatalkan. Artefak parsial mungkin tersimpan.")
        for p in _md_tmp:
            if p.exists() and p.suffix == ".tmp":
                p.unlink(missing_ok=True)
        sys.exit(130)

    signal.signal(signal.SIGINT, _handle_sigint)

    # -- Banner
    if not caps.quiet and not caps.json_out:
        render_banner(console, caps, _VERSION)

    # -- Cek koneksi ke service
    try:
        async with open_client(_state.api_url, timeout=10) as c:
            await c.health()
    except Exception as e:
        render_error_panel(
            console, caps,
            f"Service tidak terjangkau di {_state.api_url}: {e}",
            "Jalankan 'make up' atau set --api-url",
        )
        raise typer.Exit(3)

    # -- Submit scan
    scan_id: str
    try:
        async with open_client(_state.api_url, timeout=30) as c:
            result = await c.submit_scan(payload)
        scan_id = result["scan_id"]
    except ValueError as e:
        # 422 — mis. i_have_permission = false
        render_error_panel(console, caps, str(e))
        raise typer.Exit(3)
    except Exception as e:
        render_error_panel(console, caps, f"Gagal submit scan: {e}")
        raise typer.Exit(3)

    # -- Render target panel (info awal — akan diperbarui setelah stage resolve)
    ctx = RenderContext(
        scan_id=scan_id,
        mode=mode,  # type: ignore[arg-type]
        stages=MODE_STAGES.get(mode, []),
    )
    for s in ctx.stages:
        ctx.stage_info[s] = StageInfo(name=s)

    if not caps.quiet and not caps.json_out:
        render_target_panel(console, caps, scan_id, mode)

    # -- Polling loop
    spinner_frames = caps.g().spinner if caps.unicode else caps.g().spinner_ascii
    spinner_idx = 0
    report: dict | None = None
    final_status = "unknown"

    try:
        async with open_client(_state.api_url, timeout=_state.timeout) as c:
            async for snap in poll_scan(c, scan_id, total_timeout=_state.timeout):
                status   = snap.get("status", "queued")
                stage    = snap.get("stage")
                progress = snap.get("progress", 0)
                new_events: list[str] = snap.get("_new_events", [])
                ts_now = time.monotonic()

                final_status = status

                # Update ctx
                ctx.progress = progress
                if stage and stage != ctx.current_stage:
                    if ctx.current_stage:
                        ctx.mark_stage_done(ctx.current_stage, ts_now)
                    ctx.mark_stage_active(stage, ts_now)

                # Tulis stage events ke last_message
                if new_events and stage and stage in ctx.stage_info:
                    last_msg = new_events[-1].split(" ", 2)[-1] if new_events else ""
                    ctx.stage_info[stage].last_message = last_msg

                spinner_frame = spinner_frames[spinner_idx % len(spinner_frames)]
                spinner_idx += 1

                if not caps.quiet and not caps.json_out:
                    # Clear + redraw stage section (simplified: append baris baru)
                    render_stage_section(console, caps, ctx, spinner_frame, new_events)

                if status == "completed":
                    # Tandai stage terakhir done
                    if ctx.current_stage:
                        ctx.mark_stage_done(ctx.current_stage, ts_now)
                    break
                if status == "failed":
                    if ctx.current_stage:
                        ctx.mark_stage_failed(ctx.current_stage)
                    break

            # -- Ambil report
            report = await c.get_report(scan_id)

    except TimeoutError as e:
        render_error_panel(console, caps, str(e))
        raise typer.Exit(3)
    except Exception as e:
        render_error_panel(console, caps, f"Polling error: {e}")
        raise typer.Exit(3)

    # -- Fallback: baca dari disk bila API 404 (§3.6)
    if report is None and final_status == "completed":
        report = load_report_from_disk(scan_id)
        if report and not caps.quiet:
            console.print(
                f"  [{caps.g().warn}] Report diambil dari disk (service mungkin restart)."
            )

    # -- Scan gagal
    if final_status == "failed" or report is None:
        error_msg = (snap or {}).get("error", "Scan gagal tanpa pesan error.")  # type: ignore
        render_error_panel(console, caps, error_msg)
        raise typer.Exit(2)

    # -- JSON mode: dump dan selesai
    if caps.json_out:
        typer.echo(json.dumps(report, indent=2))
        raise typer.Exit(0)

    # -- Filter findings by min_severity
    findings_all: list[dict] = report.get("findings", [])
    _sev_order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    min_sev_val = _sev_order.get(min_severity, 0)
    findings_display = [
        f for f in findings_all
        if _sev_order.get(f.get("severity", "info"), 0) >= min_sev_val
    ]

    # -- Blok 3: streaming kartu (sudah di scroll, tapi cetak rekap)
    if not caps.quiet:
        for f in findings_display:
            fid = f.get("finding_id", "")
            if fid not in ctx.rendered_findings:
                render_finding_card(console, caps, f)
                ctx.rendered_findings.add(fid)

        render_findings_table(console, caps, findings_display, report.get("summary", {}))

    # -- Blok 4: saran perbaikan
    recs = build_recommendations(findings_all)
    if not caps.quiet:
        render_recommendations(console, caps, recs, scan_id)

    # -- Blok 5: tulis .md + footer
    md_written: str | None = None
    if not no_md:
        if out_path:
            md_dest = Path(out_path)
        else:
            md_dest = Path("reports") / scan_id / "report.md"

        # Guard path (§6.3): wajib dalam cwd atau reports/
        try:
            md_dest.resolve().relative_to(Path.cwd())
        except ValueError:
            try:
                md_dest.resolve().relative_to((Path("reports")).resolve())
            except ValueError:
                render_error_panel(
                    console, caps,
                    f"--out path di luar direktori kerja: {md_dest}",
                )
                raise typer.Exit(3)

        # Jangan timpa tanpa --force-out (basic: cek eksistensi)
        if md_dest.exists():
            console.print(
                f"  [{caps.g().warn}] {md_dest} sudah ada — dilewati. "
                "Gunakan --out <path-baru> atau hapus manual."
            )
        else:
            # Tulis atomik via .tmp (§6.3)
            tmp = md_dest.with_suffix(".md.tmp")
            _md_tmp.append(tmp)
            try:
                dump_markdown_report(report, tmp, recs=recs)
                tmp.rename(md_dest)
                md_written = str(md_dest)
            except Exception as e:
                tmp.unlink(missing_ok=True)
                console.print(f"  [{caps.g().warn}] Gagal tulis .md: {e}")

    duration = time.monotonic() - started_wall

    # -- Hitung exit code
    fail_sev_val = _sev_order.get(fail_on, 0)
    exit_code = 0
    if fail_sev_val > 0:
        for f in findings_all:
            if _sev_order.get(f.get("severity", "info"), 0) >= fail_sev_val:
                exit_code = 1
                break

    if not caps.quiet:
        render_footer(
            console, caps, scan_id, md_written, _state.api_url, duration, exit_code
        )

    # Pulihkan SIGINT
    signal.signal(signal.SIGINT, original_sigint)
    raise typer.Exit(exit_code)


# ---------------------------------------------------------------------------
# report

@app.command("report")
def report_cmd(
    scan_id: Annotated[str, typer.Argument(help="Scan ID.")],
    out: Annotated[Optional[str], typer.Option("--out")] = None,
    no_md: Annotated[bool, typer.Option("--no-md")] = False,
) -> None:
    """Render ulang laporan scan yang sudah selesai."""

    async def _do():
        try:
            async with open_client(_state.api_url) as c:
                report = await c.get_report(scan_id)
        except Exception as e:
            render_error_panel(_state.console, _state.caps, str(e))
            raise typer.Exit(3)

        if report is None:
            report = load_report_from_disk(scan_id)
            if report:
                _state.console.print(
                    f"  [{_state.caps.g().warn}] Report diambil dari disk."
                )

        if report is None:
            render_error_panel(_state.console, _state.caps, f"Report tidak ditemukan: {scan_id}")
            raise typer.Exit(3)

        if _state.caps.json_out:
            typer.echo(json.dumps(report, indent=2))
            return

        findings = report.get("findings", [])
        recs = build_recommendations(findings)

        render_banner(_state.console, _state.caps, _VERSION)
        for f in findings:
            render_finding_card(_state.console, _state.caps, f)
        render_findings_table(_state.console, _state.caps, findings, report.get("summary", {}))
        render_recommendations(_state.console, _state.caps, recs, scan_id)

        if not no_md:
            dest = Path(out) if out else Path("reports") / scan_id / "report.md"
            if not dest.exists():
                dump_markdown_report(report, dest, recs=recs)
                _state.console.print(f"  Laporan Markdown → {dest}")

    _run(_do())


# ---------------------------------------------------------------------------
# list

@app.command("list")
def list_cmd() -> None:
    """Tampilkan tabel scan terakhir."""

    async def _do():
        try:
            async with open_client(_state.api_url) as c:
                scans = await c.list_scans()
        except Exception as e:
            render_error_panel(_state.console, _state.caps, str(e))
            raise typer.Exit(3)

        if _state.caps.json_out:
            typer.echo(json.dumps(scans, indent=2))
            return

        if not scans:
            _state.console.print("  Tidak ada scan.")
            return

        from rich.table import Table  # type: ignore[import-untyped]
        p = _state.caps

        table = Table(show_header=True, header_style=f"bold #{p.width}")
        # reuse theme colors
        from app.cli.theme import PALETTE as PAL
        table = Table(
            show_header=True,
            header_style=f"bold {PAL.blue_primary}",
            border_style=PAL.rule_line,
            padding=(0, 1),
        )
        table.add_column("SCAN ID",    style=PAL.blue_soft, width=14)
        table.add_column("MODE",       width=8)
        table.add_column("STATUS",     width=10)
        table.add_column("PROGRESS",   justify="right", width=8)
        table.add_column("DIBUAT",     style=PAL.muted, width=20)
        table.add_column("SELESAI",    style=PAL.muted, width=20)

        status_color = {
            "completed": PAL.ok,
            "failed":    PAL.error,
            "running":   PAL.blue_accent,
            "queued":    PAL.muted,
        }
        for s in scans:
            st = s.get("status", "—")
            sc = status_color.get(st, PAL.muted)
            table.add_row(
                s.get("scan_id", "—"),
                s.get("mode", "—"),
                f"[{sc}]{st}[/]",
                f"{s.get('progress', 0)}%",
                s.get("created_at", "—"),
                s.get("finished_at") or "—",
            )
        _state.console.print(table)

    _run(_do())


# ---------------------------------------------------------------------------
# rules

@app.command("rules")
def rules_cmd() -> None:
    """Tampilkan katalog aturan aktif (CY001–CY010, XS001–XS008)."""

    async def _do():
        try:
            async with open_client(_state.api_url) as c:
                data = await c.rules()
        except Exception as e:
            render_error_panel(_state.console, _state.caps, str(e))
            raise typer.Exit(3)

        if _state.caps.json_out:
            typer.echo(json.dumps(data, indent=2))
            return

        from app.cli.theme import PALETTE as PAL
        for category, rule_list in data.items():
            _state.console.print(f"\n  [bold {PAL.blue_primary}]{category.upper()}[/]")
            for r in rule_list:
                rule_id = r.get("rule", "—")
                sev     = r.get("severity", "—")
                lang    = r.get("lang", "—")
                title   = r.get("title") or r.get("description", "")
                _state.console.print(
                    f"  [{PAL.blue_soft}]{rule_id:<8}[/]"
                    f"  [{PAL.muted}]{sev:<10}[/]"
                    f"  [{PAL.muted}]{lang:<8}[/]"
                    f"  {title}"
                )
        _state.console.print()

    _run(_do())


# ---------------------------------------------------------------------------
# fix

@app.command("fix")
def fix_cmd(
    scan_id: Annotated[str, typer.Argument(help="Scan ID untuk diremediasi.")],
) -> None:
    """Generate usulan patch otomatis dari temuan scan."""

    async def _do():
        try:
            async with open_client(_state.api_url) as c:
                result = await c.propose_fixes(scan_id)
        except Exception as e:
            render_error_panel(_state.console, _state.caps, str(e))
            raise typer.Exit(3)

        session_id = result.get("session_id", "")
        if _state.caps.json_out:
            typer.echo(json.dumps(result, indent=2))
            return

        from app.cli.theme import PALETTE as PAL
        _state.console.print(
            f"  [{PAL.ok}]Proposal dibuat.[/]  "
            f"Session: [{PAL.blue_soft}]{session_id}[/]"
        )
        _state.console.print(f"  {result.get('message', '')}")

        if session_id:
            async with open_client(_state.api_url) as c:
                fixes = await c.get_fixes(session_id)

            proposals = fixes.get("proposals", [])
            if proposals:
                from rich.table import Table  # type: ignore[import-untyped]
                table = Table(
                    show_header=True,
                    header_style=f"bold {PAL.blue_primary}",
                    border_style=PAL.rule_line,
                    padding=(0, 1),
                )
                table.add_column("FIX ID",  style=PAL.blue_soft, width=12)
                table.add_column("RULE",    width=8)
                table.add_column("FILE",    style=PAL.blue_mist, max_width=40)
                table.add_column("LINE",    justify="right", width=5, style=PAL.muted)
                for prop in proposals:
                    table.add_row(
                        str(prop.get("fix_id", "—"))[:12],
                        prop.get("rule", "—"),
                        prop.get("target_file", "—"),
                        str(prop.get("line", "—")),
                    )
                _state.console.print(table)
                _state.console.print(
                    f"\n  Jalankan API [bold]POST /api/v1/fixes/{session_id}/apply[/bold] "
                    "dengan confirm=true untuk menerapkan patch."
                )

    _run(_do())


# ---------------------------------------------------------------------------
# version

@app.command("version")
def version_cmd() -> None:
    """Tampilkan versi CLI dan service."""

    async def _do():
        from app.cli.theme import PALETTE as PAL
        _state.console.print(
            f"  [{PAL.blue_soft}]cyense CLI[/]  [{PAL.ink}]v{_VERSION}[/]"
        )
        try:
            async with open_client(_state.api_url, timeout=5) as c:
                h = await c.health()
            svc_ver = h.get("version", "—")
            _state.console.print(
                f"  [{PAL.blue_soft}]service   [/]  [{PAL.ink}]{svc_ver}[/]"
                f"  [{PAL.ok}]online[/]  [{PAL.muted}]{_state.api_url}[/]"
            )
        except Exception:
            _state.console.print(
                f"  [{PAL.blue_soft}]service   [/]  "
                f"[{PAL.error}]offline — {_state.api_url}[/]"
            )

    _run(_do())


# ---------------------------------------------------------------------------
# Entrypoint

if __name__ == "__main__":
    app()
