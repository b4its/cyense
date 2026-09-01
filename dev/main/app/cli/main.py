"""CLI entrypoint — Typer app `cyense`.

Subcommand:
   scan github <repo_url>   — audit repo GitHub (jalur utama)
   scan program             — audit source lokal
   scan link <url>          — probing IDOR dinamis
   scan website <url>       — crawl website, cari IDOR + XSS live
   scan api <spec>          — parse OpenAPI/Swagger spec, scan endpoints (Strix)
   scan resume <scan_id>    — lanjutkan scan yang terinterupsi (Strix --resume)
   scan multi <targets>     — scan multiple targets dari file (Strix --target-list)
   report <scan_id>         — render ulang laporan lama
   list                     — tabel scan terakhir
   history                  — riwayat scan + filter status (enhanced-reporting-viewer.md)
   compare <a> <b>          — diff dua laporan scan
   view [scan_id]           — buka web viewer di browser
   export csv|pdf <id>      — unduh CSV/PDF
   config get|set|list|reset— preferensi CLI (~/.cyense/config.json, 0o600)
   rules                    — katalog aturan aktif
   fix <scan_id>            — usulan patch remediasi
   auth login|status|logout — kelola kredensial (GitHub token) (Strix)
   ci junit|check           — CI/CD helpers: JUnit XML export + quality gate (Strix)
   version                  — versi CLI + service

Arsitektur: CLI HANYA bicara ke API lewat HTTP (app/cli/client.py).
TIDAK mengimpor app.engines, app.agents, app.program, app.worker.
Lihat: instruction/feature/cli-experience.md §5.4

Strix-derived features added (usestrix/strix v1.5.3):
  --instruction/--instruction-file   custom testing focus metadata
  --diff-base                        override diff comparison base
  --resume <scan_id>                 resume interrupted scan from checkpoint
  -n/--non-interactive               headless mode for CI/CD
  --target-list <file>               batch targets from file
"""

from __future__ import annotations

import asyncio
import json
import shutil
import signal
import sys
import time
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console  # type: ignore[import-untyped]

from app.cli.client import load_report_from_disk, open_client, poll_scan
from app.cli.models import MODE_STAGES, RenderContext, StageInfo
from app.cli.recommend import build_recommendations
from app.cli.renderer import (
    render_banner,
    render_cve_table,
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

_VERSION = "2.1.0"


# ---------------------------------------------------------------------------
# State global (disiapkan oleh callback utama sebelum subcommand berjalan)

class _State:
    api_url: str = "http://localhost:8000"
    caps: TermCaps = detect_caps()
    console: Console = make_rich_console(caps)
    timeout: float = 300.0
    json_out: bool = False
    non_interactive: bool = False  # Strix -n: headless mode for CI/CD


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
    non_interactive: Annotated[
        bool, typer.Option("--non-interactive", "-n", help="Mode headless untuk CI/CD (tanpa TUI).")
    ] = False,
    timeout: Annotated[
        float, typer.Option("--timeout", help="Batas waktu tunggu scan (detik).")
    ] = 300.0,
) -> None:
    """Cyense CLI — thin client ke FastAPI service."""
    _state.timeout = timeout
    _state.json_out = json_out
    _state.non_interactive = non_interactive

    # Precedence: flag/env eksplisit > config file > default bawaan.
    resolved_api = api_url.rstrip("/")
    if resolved_api == "http://localhost:8000":
        try:
            from app.core.config_store import load_config
            cfg_url = str(load_config().get("api_url", "")).rstrip("/")
            if cfg_url and cfg_url != "http://localhost:8000":
                resolved_api = cfg_url
        except Exception:
            pass  # config bersifat best-effort
    _state.api_url = resolved_api

    caps = detect_caps(
        force_no_color=no_color,
        force_ascii=ascii_mode,
        force_quiet=quiet or non_interactive,
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
    ref: Annotated[str | None, typer.Option("--ref", help="Branch / tag / commit SHA.")] = None,
    subdir: Annotated[
        str | None, typer.Option("--subdir", help="Batasi analisis ke subfolder.")
    ] = None,
    lang: Annotated[
        str, typer.Option("--lang", help="Bahasa: python|js|php|auto.")
    ] = "auto",
    token: Annotated[
        str | None, typer.Option("--token", envvar="CYENSE_GITHUB_TOKEN", help="GitHub token.")
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
        str | None, typer.Option("--out", help="Path output .md.")
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
            help=(
                "Mode scan: quick (cepat, IDOR saja), standard "
                "(default, IDOR+XSS), deep (komprehensif)."
            ),
        ),
    ] = "standard",
    scope_mode: Annotated[
        str,
        typer.Option(
            "--scope-mode",
            help="Mode cakupan: auto (otomatis), full (semua file), diff (hanya perubahan).",
        ),
    ] = "auto",
    # Analysis depth level (low|medium|high|max)
    level: Annotated[
        str,
        typer.Option(
            "--level",
            help=(
                "Kedalaman analisis: low (cepat), medium (default), "
                "high (data flow), max (cross-file)."
            ),
        ),
    ] = "medium",
    # Strix-derived features:
    instruction: Annotated[
        str | None,
        typer.Option(
            "--instruction",
            help="Fokus testing khusus (mis. 'Focus on IDOR').",
        ),
    ] = None,
    instruction_file: Annotated[
        str | None, typer.Option("--instruction-file", help="Path file berisi instruksi testing.")
    ] = None,
    diff_base: Annotated[
        str | None,
        typer.Option(
            "--diff-base",
            help="Override base branch/commit untuk diff-scope (mis. origin/main).",
        ),
    ] = None,
    resume: Annotated[
        str | None,
        typer.Option("--resume", help="Lanjutkan scan yang terinterupsi dari scan_id ini."),
    ] = None,
) -> None:
    """Audit repository GitHub — jalur input utama Cyense."""
    # Mutual exclusion check must happen before reading instruction_file.
    if instruction and instruction_file:
        render_error_panel(
            _state.console, _state.caps,
            "Tidak bisa menggunakan --instruction dan --instruction-file bersamaan.",
        )
        raise typer.Exit(3)

    # Resolve instruction: --instruction-file overrides --instruction
    resolved_instruction = instruction
    if instruction_file:
        try:
            resolved_instruction = Path(instruction_file).read_text(encoding="utf-8").strip()
        except OSError as e:
            render_error_panel(_state.console, _state.caps, f"Gagal baca --instruction-file: {e}")
            raise typer.Exit(3) from None

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
        "level": level,
    }
    if ref:
        payload["ref"] = ref
    if subdir:
        payload["subdir"] = subdir
    if token:
        payload["github_token"] = token  # tidak pernah dicetak (redaksi di api/engine)
    if resolved_instruction:
        payload["instruction"] = resolved_instruction
    if diff_base:
        payload["diff_base"] = diff_base
    if resume:
        payload["resume_from"] = resume

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
    out: Annotated[str | None, typer.Option("--out")] = None,
    no_md: Annotated[bool, typer.Option("--no-md")] = False,
    fail_on: Annotated[str, typer.Option("--fail-on")] = "none",
    min_severity: Annotated[str, typer.Option("--min-severity")] = "info",
    scan_mode: Annotated[
        str,
        typer.Option(
            "--scan-mode",
            help=(
                "Mode scan: quick (cepat, IDOR saja), standard "
                "(default, IDOR+XSS), deep (komprehensif)."
            ),
        ),
    ] = "standard",
    scope_mode: Annotated[
        str,
        typer.Option(
            "--scope-mode",
            help="Mode cakupan: auto (otomatis), full (semua file), diff (hanya perubahan).",
        ),
    ] = "auto",
    # Analysis depth level (low|medium|high|max)
    level: Annotated[
        str,
        typer.Option(
            "--level",
            help=(
                "Kedalaman analisis: low (cepat), medium (default), "
                "high (data flow), max (cross-file)."
            ),
        ),
    ] = "medium",
    # Strix-derived features:
    instruction: Annotated[
        str | None, typer.Option("--instruction", help="Fokus testing khusus.")
    ] = None,
    instruction_file: Annotated[
        str | None, typer.Option("--instruction-file", help="Path file instruksi testing.")
    ] = None,
    resume: Annotated[
        str | None,
        typer.Option("--resume", help="Lanjutkan scan yang terinterupsi dari scan_id ini."),
    ] = None,
) -> None:
    """Audit source code lokal (mounted / sample)."""
    if instruction and instruction_file:
        render_error_panel(
            _state.console, _state.caps,
            "Tidak bisa menggunakan --instruction dan --instruction-file bersamaan.",
        )
        raise typer.Exit(3)

    resolved_instruction = instruction
    if instruction_file:
        try:
            resolved_instruction = Path(instruction_file).read_text(encoding="utf-8").strip()
        except OSError as e:
            render_error_panel(_state.console, _state.caps, f"Gagal baca --instruction-file: {e}")
            raise typer.Exit(3) from None

    payload = {
        "mode": "program",
        "lang": lang,
        "source_type": source_type,
        "i_have_permission": i_have_permission,
        "scan_mode": scan_mode,
        "scope_mode": scope_mode,
        "level": level,
    }
    if resolved_instruction:
        payload["instruction"] = resolved_instruction
    if resume:
        payload["resume_from"] = resume

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
    out: Annotated[str | None, typer.Option("--out")] = None,
    no_md: Annotated[bool, typer.Option("--no-md")] = False,
    scan_mode: Annotated[
        str,
        typer.Option(
            "--scan-mode",
            help=(
                "Mode scan: quick (cepat, IDOR saja), standard "
                "(default, IDOR+XSS), deep (komprehensif)."
            ),
        ),
    ] = "standard",
    scope_mode: Annotated[
        str,
        typer.Option(
            "--scope-mode",
            help="Mode cakupan: auto (otomatis), full (semua file), diff (hanya perubahan).",
        ),
    ] = "auto",
    # Strix-derived features:
    instruction: Annotated[
        str | None, typer.Option("--instruction", help="Fokus testing khusus.")
    ] = None,
    instruction_file: Annotated[
        str | None, typer.Option("--instruction-file", help="Path file instruksi testing.")
    ] = None,
    resume: Annotated[
        str | None,
        typer.Option("--resume", help="Lanjutkan scan yang terinterupsi dari scan_id ini."),
    ] = None,
) -> None:
    """Probing IDOR dinamis pada URL live."""
    if instruction and instruction_file:
        render_error_panel(
            _state.console, _state.caps,
            "Tidak bisa menggunakan --instruction dan --instruction-file bersamaan.",
        )
        raise typer.Exit(3)

    resolved_instruction = instruction
    if instruction_file:
        try:
            resolved_instruction = Path(instruction_file).read_text(encoding="utf-8").strip()
        except OSError as e:
            render_error_panel(_state.console, _state.caps, f"Gagal baca --instruction-file: {e}")
            raise typer.Exit(3) from None

    payload = {
        "mode": "link",
        "url": url,
        "i_have_permission": i_have_permission,
        "scan_mode": scan_mode,
        "scope_mode": scope_mode,
    }
    if resolved_instruction:
        payload["instruction"] = resolved_instruction
    if resume:
        payload["resume_from"] = resume

    _run(_run_scan(
        payload=payload,
        mode="link",
        out_path=out,
        no_md=no_md,
        fail_on=fail_on,
        min_severity=min_severity,
    ))


# ---------------------------------------------------------------------------
# scan domain — enumerate subdomains then scan every live host

@scan_app.command("domain")
def scan_domain(
    domain: Annotated[
        str,
        typer.Argument(
            help="Domain target (contoh: example.com) — seluruh subdomain "
            "yang ditemukan akan di-scan dengan pipeline lengkap."
        ),
    ],
    max_hosts: Annotated[
        int,
        typer.Option("--max-hosts", help="Batas host yang di-scan (1-100, default 20)."),
    ] = 20,
    max_pages: Annotated[
        int,
        typer.Option("--max-pages", help="Max halaman per host (default 20)."),
    ] = 20,
    rate_limit: Annotated[
        int,
        typer.Option("--rate-limit", help="Max request/s per host (default 10)."),
    ] = 10,
    i_have_permission: Annotated[
        bool,
        typer.Option(
            "--i-have-permission",
            help="[mandatory] Konfirmasi izin eksplisit untuk memindai domain ini.",
        ),
    ] = False,
    out: Annotated[str | None, typer.Option("--out", help="Path output .md.")] = None,
    no_md: Annotated[bool, typer.Option("--no-md", help="Jangan tulis .md.")] = False,
    fail_on: Annotated[
        str,
        typer.Option(
            "--fail-on",
            help="Exit 1 bila ada temuan ≥ severity ini (none|info|low|medium|high|critical).",
        ),
    ] = "none",
) -> None:
    """Scan seluruh domain — enumerasi subdomain + pipeline scan per host.

    Mode domain: subdomain ditemukan secara pasif (Wayback Machine) dan
    aktif (DNS), lalu setiap host yang hidup di-scan dengan pipeline
    website lengkap (crawl → teknologi → port → CVE → discovery → probe).
    Hasil diagregasi dengan atribusi per-host.
    """
    payload: dict = {
        "mode": "domain",
        "domain": domain,
        "max_hosts": max_hosts,
        "max_pages": max_pages,
        "rate_limit": rate_limit,
        "i_have_permission": i_have_permission,
    }
    _run(_run_scan(
        payload=payload,
        mode="domain",
        out_path=out,
        no_md=no_md,
        fail_on=fail_on,
        min_severity="info",
    ))


# scan website — crawl a public site, discover IDOR + live XSS

@scan_app.command("website")
def scan_website(
    url: Annotated[
        str,
        typer.Argument(help="Starting URL of the public website to scan (http/https)."),
    ],
    max_depth: Annotated[
        int,
        typer.Option("--max-depth", help="Max crawl depth (0-5, default 2)."),
    ] = 2,
    max_pages: Annotated[
        int,
        typer.Option("--max-pages", help="Max pages to crawl (1-500, default 50)."),
    ] = 50,
    rate_limit: Annotated[
        int,
        typer.Option(
            "--rate-limit",
            help="Max requests per second to the target (1-100, default 10).",
        ),
    ] = 10,
    i_have_permission: Annotated[
        bool,
        typer.Option(
            "--i-have-permission",
            help="[mandatory] Confirm you have explicit permission to scan this website.",
        ),
    ] = False,
    out: Annotated[str | None, typer.Option("--out", help="Path output .md.")] = None,
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
) -> None:
    """Scan a public website for IDOR & XSS vulnerabilities via crawling.

    The crawler stays same-domain and read-only (HTTP GET). It discovers
    ID-bearing endpoints automatically and inspects every HTML response for
    XSS surface (weak CSP, eval/innerHTML/document.write, inline handlers,
    reflected parameters, missing security headers).
    """
    payload: dict = {
        "mode": "website",
        "url": url,
        "max_depth": max_depth,
        "max_pages": max_pages,
        "rate_limit": rate_limit,
        "i_have_permission": i_have_permission,
    }
    _run(_run_scan(
        payload=payload,
        mode="website",
        out_path=out,
        no_md=no_md,
        fail_on=fail_on,
        min_severity=min_severity,
    ))


# ---------------------------------------------------------------------------
# cve — focused CVE lookup for a website (uses the CVE-aware website scan)
# ---------------------------------------------------------------------------

@app.command("cve")
def cli_cve(
    url: Annotated[
        str,
        typer.Argument(
            help="Website URL untuk dicari CVEs (teknologi terdeteksi dicocokkan "
            "dengan database lokal + NVD/MITRE live)."
        ),
    ],
    max_pages: Annotated[
        int,
        typer.Option("--max-pages", help="Max halaman di-crawl (default 10)."),
    ] = 10,
    rate_limit: Annotated[
        int,
        typer.Option("--rate-limit", help="Max request/s ke target (default 10)."),
    ] = 10,
    online: Annotated[
        bool,
        typer.Option(
            "--online/--no-online",
            help="Aktifkan pencarian CVE live ke NVD/MITRE (default: online).",
        ),
    ] = True,
    no_port_scan: Annotated[
        bool,
        typer.Option("--no-port-scan", help="Lewati port scan (default: jalankan)."),
    ] = False,
    i_have_permission: Annotated[
        bool,
        typer.Option(
            "--i-have-permission",
            help="[wajib] Konfirmasi izin eksplisit untuk memindai website ini.",
        ),
    ] = False,
    out: Annotated[str | None, typer.Option("--out", help="Path output .md.")] = None,
    no_md: Annotated[bool, typer.Option("--no-md", help="Jangan tulis .md.")] = False,
) -> None:
    """Cari CVE/kerentanan terkenal untuk teknologi website.

    Menjalankan website scan berfokus CVE: deteksi teknologi + port scan →
    cocokkan dengan database CVE lokal → pencarian live ke NVD/MITRE.
    Menampilkan tabel CVE khusus (severity, CVSS, sumber, status verifikasi).
    """
    if not i_have_permission:
        render_error_panel(
            _state.console, _state.caps,
            "i_have_permission wajib untuk memindai website.",
            "Ulangi dengan --i-have-permission untuk konfirmasi otorisasi.",
        )
        raise typer.Exit(3)

    payload: dict = {
        "mode": "website",
        "url": url,
        "max_depth": 1,               # fokus CVE → cukup halaman awal + tautan
        "max_pages": max_pages,
        "rate_limit": rate_limit,
        "i_have_permission": True,
    }
    if not online:
        # server-side flag untuk menonaktifkan pencarian CVE online
        payload["scan_mode"] = "standard"
        # Note: online toggle dikirim sebagai instruksi; fallback disediakan
        # oleh server default. Untuk kontrol penuh, nonaktifkan via env di
        # server (CYENSE_CVE_ONLINE_ENABLED=false).
        payload["instruction"] = "focus on CVE detection; online search " + (
            "enabled" if online else "disabled"
        )

    _run(_cve_scan_flow(payload, out_path=out, no_md=no_md, no_port_scan=no_port_scan))


# ---------------------------------------------------------------------------
# recon — reconnaissance menyeluruh (adaptasi HackerOne 104 tools)
# ---------------------------------------------------------------------------

@app.command("recon")
def cli_recon(
    url: Annotated[
        str,
        typer.Argument(
            help="Website URL untuk reconnaissance menyeluruh (subdomain, "
            "secret, exposed files, API endpoints, WP, SSRF, GraphQL, vhost)."
        ),
    ],
    max_pages: Annotated[
        int,
        typer.Option("--max-pages", help="Max halaman di-crawl (default 10)."),
    ] = 10,
    rate_limit: Annotated[
        int,
        typer.Option("--rate-limit", help="Max request/s ke target (default 10)."),
    ] = 10,
    i_have_permission: Annotated[
        bool,
        typer.Option(
            "--i-have-permission",
            help="[wajib] Konfirmasi izin eksplisit untuk memindai website ini.",
        ),
    ] = False,
    out: Annotated[str | None, typer.Option("--out", help="Path output .md.")] = None,
    no_md: Annotated[bool, typer.Option("--no-md", help="Jangan tulis .md.")] = False,
) -> None:
    """Recon menyeluruh ke website (adaptasi HackerOne 104 tools).

    Menjalankan website scan dan menampilkan hasil discovery terkelompok:
    secret ter-expose, file/panel sensitif, subdomain, API endpoints,
    WordPress, SSRF sinks, GraphQL, vhost, hidden params, wayback.
    """
    if not i_have_permission:
        render_error_panel(
            _state.console, _state.caps,
            "i_have_permission wajib untuk memindai website.",
            "Ulangi dengan --i-have-permission untuk konfirmasi otorisasi.",
        )
        raise typer.Exit(3)

    payload: dict = {
        "mode": "website",
        "url": url,
        "max_depth": 1,
        "max_pages": max_pages,
        "rate_limit": rate_limit,
        "i_have_permission": True,
    }
    _run(_recon_flow(payload, out_path=out, no_md=no_md))


async def _recon_flow(
    payload: dict,
    *,
    out_path: str | None,
    no_md: bool,
) -> None:
    """Submit a website scan and render the discovery table prominently."""
    from app.cli.theme import PALETTE as PAL

    caps = _state.caps
    console = _state.console

    if not caps.quiet:
        render_banner(console, caps, _VERSION)

    try:
        async with open_client(_state.api_url, timeout=30) as c:
            submitted = await c.submit_scan(payload)
    except Exception as e:
        render_error_panel(console, caps, f"Gagal submit scan recon: {e}")
        raise typer.Exit(3) from None

    scan_id = submitted["scan_id"]
    if not caps.quiet:
        console.print(f"  [{PAL.blue_soft}]Scan recon diajukan:[/] {scan_id}")
        console.print(
            f"  [{PAL.muted}]Menunggu hasil (crawl → framework → port → "
            "CVE → discovery → probe)...[/]"
        )

    report: dict | None = None
    try:
        async with open_client(_state.api_url, timeout=_state.timeout) as c:
            async for _snap in poll_scan(c, scan_id, total_timeout=_state.timeout):
                pass
            report = await c.get_report(scan_id)
    except TimeoutError as e:
        render_error_panel(console, caps, str(e))
        raise typer.Exit(3) from None
    except Exception as e:
        render_error_panel(console, caps, f"Polling scan gagal: {e}")
        raise typer.Exit(3) from None

    if report is None:
        report = load_report_from_disk(scan_id)
    if report is None:
        render_error_panel(console, caps, f"Report tidak ditemukan untuk {scan_id}")
        raise typer.Exit(3) from None

    findings = report.get("findings", [])
    summary = report.get("summary", {})

    # 1. Discovery table (secret, exposed, subdomain, API, WP, SSRF, ...)
    from app.cli.renderer import render_discovery_table

    render_discovery_table(console, caps, findings)

    # 2. CVE table
    cve_findings = [f for f in findings if f.get("rule") == "CVE-MATCH"]
    from app.cli.renderer import render_cve_table

    render_cve_table(console, caps, cve_findings, summary)

    # 3. Temuan lain (XSS/SQLi/IDOR) ringkas
    other = [f for f in findings
             if f.get("rule") not in ("CVE-MATCH",) and not (
                 f.get("rule", "").startswith(("SECRET", "EXPOSED", "DISC",
                                               "WP-", "SSRF", "GRAPHQL",
                                               "DETECT", "PORT"))
             )]
    if other:
        console.print(f"  [bold {PAL.blue_primary}]TEMUAN LAIN (XSS/SQLi/IDOR)[/]")
        from app.cli.renderer import render_findings_table
        render_findings_table(console, caps, other, summary)

    # 4. Output markdown opsional
    if out_path and not no_md:
        from pathlib import Path

        from app.report.md_report import dump_markdown_report
        try:
            md_dest = Path(out_path).resolve()
            cwd = Path.cwd().resolve()
            if not md_dest.is_relative_to(cwd):
                render_error_panel(
                    console, caps,
                    f"--out path di luar direktori kerja: {md_dest}",
                )
                raise typer.Exit(3)
            dump_markdown_report(report, md_dest)
            console.print(f"  [{PAL.ok}]Laporan markdown ditulis:[/] {md_dest}")
        except OSError as e:
            render_error_panel(console, caps, f"Gagal tulis markdown: {e}")
            raise typer.Exit(3) from None

    import time as _time
    _t0 = getattr(_state, "_recon_t0", _time.monotonic())
    render_footer(
        console, caps, scan_id, out_path if (out_path and not no_md) else None,
        _state.api_url, _time.monotonic() - _t0, 0,
    )


async def _cve_scan_flow(
    payload: dict,
    *,
    out_path: str | None,
    no_md: bool,
    no_port_scan: bool,
) -> None:
    """Submit a website scan and render the CVE table prominently."""
    from app.cli.theme import PALETTE as PAL

    caps = _state.caps
    console = _state.console

    if not caps.quiet:
        render_banner(console, caps, _VERSION)

    try:
        async with open_client(_state.api_url, timeout=30) as c:
            submitted = await c.submit_scan(payload)
    except Exception as e:
        render_error_panel(console, caps, f"Gagal submit scan CVE: {e}")
        raise typer.Exit(3) from None

    scan_id = submitted["scan_id"]
    if not caps.quiet:
        console.print(f"  [{PAL.blue_soft}]Scan CVE diajukan:[/] {scan_id}")
        console.print(f"  [{PAL.muted}]Menunggu hasil (teknologi → port → CVE)...[/]")

    report: dict | None = None
    try:
        async with open_client(_state.api_url, timeout=_state.timeout) as c:
            async for _snap in poll_scan(c, scan_id, total_timeout=_state.timeout):
                pass
            report = await c.get_report(scan_id)
    except TimeoutError as e:
        render_error_panel(console, caps, str(e))
        raise typer.Exit(3) from None
    except Exception as e:
        render_error_panel(console, caps, f"Polling scan gagal: {e}")
        raise typer.Exit(3) from None

    if report is None:
        report = load_report_from_disk(scan_id)
    if report is None:
        render_error_panel(console, caps, f"Report tidak ditemukan untuk {scan_id}")
        raise typer.Exit(3) from None

    findings = report.get("findings", [])
    summary = report.get("summary", {})

    # Pisahkan CVE dari temuan lain
    cve_findings = [f for f in findings if f.get("rule") == "CVE-MATCH"]
    tech_findings = [f for f in findings if f.get("rule", "").startswith("DETECT-")]
    port_findings = [f for f in findings if f.get("rule") == "PORT-OPEN"]
    other = [f for f in findings
             if f not in cve_findings and f not in tech_findings
             and f not in port_findings]

    # Teknologi terdeteksi
    if tech_findings:
        console.print(f"  [bold {PAL.blue_primary}]TEKNOLOGI TERDETEKSI[/]")
        for t in tech_findings:
            ev = t.get("evidence", {})
            version = f" v{ev['version']}" if ev.get("version") else ""
            console.print(
                f"  [{PAL.ok}]●[/] {t.get('rule','?').replace('DETECT-','')}"
                f"{version}  [{PAL.muted}]{t.get('title','')[:50]}[/]"
            )
        console.print()

    # Port terbuka
    if port_findings:
        console.print(f"  [bold {PAL.blue_primary}]PORT TERBUKA[/]")
        for p in port_findings:
            ev = p.get("evidence", {})
            banner = f" banner={ev.get('banner','')[:40]}" if ev.get("banner") else ""
            ver = f" v{ev.get('version')}" if ev.get("version") else ""
            console.print(
                f"  [{PAL.ok}]●[/] {ev.get('port')}/{ev.get('service','?')}"
                f"{ver}{banner}"
            )
        console.print()

    # Tabel CVE khusus
    render_cve_table(console, caps, cve_findings, summary)

    # Temuan lain (XSS/SQLi/IDOR) ringkas
    if other:
        console.print(f"  [bold {PAL.blue_primary}]TEMUAN LAIN (XSS/SQLi/IDOR)[/]")
        render_findings_table(console, caps, other, summary)
    else:
        console.print(f"  [{PAL.ok}]Tidak ada temuan XSS/SQLi/IDOR.[/]")
        console.print()

    # Output markdown opsional
    if out_path and not no_md:
        from pathlib import Path

        from app.report.md_report import dump_markdown_report
        try:
            md_dest = Path(out_path).resolve()
            cwd = Path.cwd().resolve()
            if not md_dest.is_relative_to(cwd):
                render_error_panel(
                    console, caps,
                    f"--out path di luar direktori kerja: {md_dest}",
                )
                raise typer.Exit(3)
            dump_markdown_report(report, md_dest)
            console.print(f"  [{PAL.ok}]Laporan markdown ditulis:[/] {md_dest}")
        except OSError as e:
            render_error_panel(console, caps, f"Gagal tulis markdown: {e}")
            raise typer.Exit(3) from None

    import time as _time
    _t0 = getattr(_state, "_cve_t0", _time.monotonic())
    render_footer(
        console, caps, scan_id, out_path if (out_path and not no_md) else None,
        _state.api_url, _time.monotonic() - _t0, 0,
    )


# ---------------------------------------------------------------------------
# scan api — parse OpenAPI/Swagger spec and scan declared endpoints (Strix pattern)

@scan_app.command("api")
def scan_api(
    spec: Annotated[
        str,
        typer.Argument(
            help="OpenAPI/Swagger spec: file path (.json/.yaml), URL, or raw JSON/YAML string.",
        ),
    ],
    base_url: Annotated[
        str | None,
        typer.Option(
            "--base-url",
            help=(
                "Override base URL (e.g. http://localhost:8080). "
                "If omitted, uses spec servers[].url."
            ),
        ),
    ] = None,
    include_all: Annotated[
        bool,
        typer.Option(
            "--include-all",
            help=(
                "Include endpoints without path parameters too "
                "(default: only ID-bearing endpoints)."
            ),
        ),
    ] = False,
    dry_run: Annotated[
        bool,
        typer.Option(
            "--dry-run",
            help="Parse and display endpoints without submitting scans.",
        ),
    ] = False,
    i_have_permission: Annotated[
        bool,
        typer.Option(
            "--i-have-permission",
            help="[mandatory] Confirm you have explicit permission to test the target API.",
        ),
    ] = False,
    fail_on: Annotated[str, typer.Option("--fail-on")] = "none",
    min_severity: Annotated[str, typer.Option("--min-severity")] = "info",
    max_targets: Annotated[
        int,
        typer.Option(
            "--max-targets",
            help="Maximum number of endpoints to scan (0 = unlimited).",
        ),
    ] = 50,
) -> None:
    """Scan an API using an OpenAPI/Swagger spec.

    Parses the spec to discover endpoints with ID-like path parameters
    (e.g. /users/{userId}, /invoices/{id}), then submits link scans for each
    one against the live base URL. Inspired by Strix's API contract scanning.

    \b
    Examples:
      cyense scan api ./openapi.yaml --base-url http://localhost:8080 --i-have-permission
      cyense scan api https://api.example.com/openapi.json --i-have-permission
      cyense scan api ./swagger.json --dry-run  # just list endpoints
    """
    from app.services.openapi_parser import get_spec_info, parse_openapi_spec

    caps = _state.caps
    console = _state.console

    if not caps.quiet:
        render_banner(console, caps, _VERSION)

    # Parse spec info for display
    try:
        info = get_spec_info(spec)
    except Exception as e:
        render_error_panel(console, caps, f"Failed to parse OpenAPI spec: {e}")
        raise typer.Exit(3) from None

    if not caps.quiet:
        from app.cli.theme import PALETTE as PAL
        console.print(
            f"\n  [{PAL.blue_soft}]API Spec:[/]  [{PAL.ink}]{info['title']} "
            f"v{info['version']}[/]"
        )
        console.print(f"  [{PAL.blue_soft}]OpenAPI:[/]   [{PAL.ink}]{info['openapi_version']}[/]")
        console.print(
            f"  [{PAL.blue_soft}]Base URL:[/]  [{PAL.ink}]"
            f"{info['base_url'] or '(none — use --base-url)'}[/]"
        )
        console.print(
            f"  [{PAL.blue_soft}]Endpoints:[/] [{PAL.ink}]{info['total_endpoints']} total, "
            f"{info['idor_candidates']} IDOR candidates[/]"
        )
        if info["security_schemes"]:
            schemes = ", ".join(info["security_schemes"])
            console.print(f"  [{PAL.blue_soft}]Auth:[/]      [{PAL.ink}]{schemes}[/]")
        console.print()

    # Parse endpoints
    try:
        endpoints = parse_openapi_spec(spec, base_url=base_url, include_all=include_all)
    except Exception as e:
        render_error_panel(console, caps, f"Failed to parse endpoints: {e}")
        raise typer.Exit(3) from None

    if not endpoints:
        render_error_panel(
            console, caps,
            "No IDOR-candidate endpoints found in spec.",
            (
                "Try --include-all to scan all endpoints, or check that "
                "paths use {id}-style parameters."
            ),
        )
        raise typer.Exit(3)

    if max_targets > 0:
        endpoints = endpoints[:max_targets]

    # Display endpoints table
    from rich.table import Table  # type: ignore[import-untyped]

    from app.cli.theme import PALETTE as PAL

    table = Table(
        show_header=True,
        header_style=f"bold {PAL.blue_primary}",
        border_style=PAL.rule_line,
        padding=(0, 1),
    )
    table.add_column("METHOD", style=PAL.blue_soft, width=8)
    table.add_column("PATH", style=PAL.blue_mist, max_width=50)
    table.add_column("ID PARAMS", width=20)
    table.add_column("AUTH", width=6)
    table.add_column("SUMMARY", max_width=40)

    for ep in endpoints:
        auth_badge = "🔒" if ep["has_auth"] else "—"
        table.add_row(
            ep["method"],
            ep["path"],
            ", ".join(ep["id_params"]) or "—",
            auth_badge,
            ep["summary"][:40] if ep["summary"] else "—",
        )

    if not caps.quiet:
        console.print(table)
        console.print(f"\n  [{PAL.muted}]{len(endpoints)} endpoint(s) selected for scanning[/]")

    if dry_run:
        if not caps.quiet:
            console.print(f"\n  [{PAL.ok}]Dry run complete. No scans submitted.[/]")
        raise typer.Exit(0)

    # Validate base URL
    effective_base = base_url or info.get("base_url", "")
    if not effective_base:
        render_error_panel(
            console, caps,
            "No base URL available. Spec has no servers[].url — use --base-url.",
        )
        raise typer.Exit(3)

    if not i_have_permission:
        render_error_panel(
            console, caps,
            "i_have_permission is required to scan live APIs.",
            "Re-run with --i-have-permission to confirm authorization.",
        )
        raise typer.Exit(3)

    # Submit link scans for each endpoint
    scan_ids: list[tuple[str, str]] = []  # (scan_id, label)
    for ep in endpoints:
        url_template = ep["url_template"]
        # Replace path params with {ID} placeholder for link scan
        # Only replace the first ID-like param with {ID}; others stay literal
        url_for_scan = url_template
        for param in ep["id_params"]:
            url_for_scan = url_for_scan.replace(f"{{{param}}}", "{ID}", 1)
            break  # only replace the first one

        label = f"{ep['method']} {ep['path']}"
        payload = {
            "mode": "link",
            "url": url_for_scan,
            "i_have_permission": True,
        }

        try:
            async def _submit(payload=payload):
                async with open_client(_state.api_url, timeout=30) as c:
                    return await c.submit_scan(payload)

            result = asyncio.run(_submit())
            sid = result["scan_id"]
            scan_ids.append((sid, label))
            if not caps.quiet:
                console.print(f"  [{PAL.blue_soft}]  → {sid}[/]  [{PAL.muted}]{label}[/]")
        except Exception as e:
            if not caps.quiet:
                console.print(f"  [{PAL.error}]  ✗ failed:[/] {label}: {e}")

    if not scan_ids:
        render_error_panel(console, caps, "No scans were submitted successfully.")
        raise typer.Exit(3)

    # Wait for all scans to complete
    if not caps.quiet:
        console.print(f"\n  [{PAL.blue_soft}]Waiting for {len(scan_ids)} scan(s) to complete...[/]")

    pending = {sid for sid, _ in scan_ids}
    deadline = time.monotonic() + _state.timeout
    while pending and time.monotonic() < deadline:
        for sid in list(pending):
            try:
                async def _check(sid=sid):
                    async with open_client(_state.api_url, timeout=10) as c:
                        return await c.get_scan(sid)

                data = asyncio.run(_check())
                if data.get("status") in ("completed", "failed"):
                    pending.discard(sid)
            except Exception:
                pass
        if pending:
            time.sleep(2.0)

    # Summary table
    if not caps.quiet:
        result_table = Table(
            show_header=True,
            header_style=f"bold {PAL.blue_primary}",
            border_style=PAL.rule_line,
            padding=(0, 1),
        )
        result_table.add_column("SCAN ID", style=PAL.blue_soft, width=14)
        result_table.add_column("ENDPOINT", style=PAL.blue_mist, max_width=40)
        result_table.add_column("STATUS", width=12)
        result_table.add_column("FINDINGS", justify="right", width=10)

        status_color = {
            "completed": PAL.ok,
            "failed": PAL.error,
            "running": PAL.blue_accent,
            "queued": PAL.muted,
        }
        total_findings = 0
        for sid, label in scan_ids:
            try:
                async def _get(sid=sid):
                    async with open_client(_state.api_url, timeout=10) as c:
                        return await c.get_scan(sid)

                data = asyncio.run(_get())
                st = data.get("status", "unknown")
                findings = data.get("summary", {}).get("total", 0)
                total_findings += findings
            except Exception:
                st = "unknown"
                findings = 0
            sc = status_color.get(st, PAL.muted)
            result_table.add_row(sid, label, f"[{sc}]{st}[/]", str(findings))

        console.print(result_table)
        console.print(f"\n  [{PAL.blue_soft}]Total findings:[/] {total_findings}")

    # Exit code
    _sev_order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    fail_sev_val = _sev_order.get(fail_on, 0)
    exit_code = 0
    if fail_sev_val > 0:
        for sid, _ in scan_ids:
            try:
                async def _report(sid=sid):
                    async with open_client(_state.api_url, timeout=10) as c:
                        return await c.get_report(sid)

                report = asyncio.run(_report())
                if report:
                    for f in report.get("findings", []):
                        if _sev_order.get(f.get("severity", "info"), 0) >= fail_sev_val:
                            exit_code = 1
                            break
            except Exception:
                pass
            if exit_code:
                break

    raise typer.Exit(exit_code)


# ---------------------------------------------------------------------------
# scan resume — lanjutkan scan yang terinterupsi (Strix --resume pattern)

@scan_app.command("resume")
def scan_resume(
    scan_id: Annotated[str, typer.Argument(help="Scan ID untuk dilanjutkan (--resume <id>).")],
    instruction: Annotated[
        str | None, typer.Option("--instruction", help="Instruksi tambahan untuk resumed scan.")
    ] = None,
    out: Annotated[str | None, typer.Option("--out")] = None,
    no_md: Annotated[bool, typer.Option("--no-md")] = False,
    fail_on: Annotated[str, typer.Option("--fail-on")] = "none",
    min_severity: Annotated[str, typer.Option("--min-severity")] = "info",
) -> None:
    """Lanjutkan scan yang terinterupsi dari checkpoint (Strix --resume pattern)."""

    async def _do():
        caps = _state.caps
        console = _state.console

        # Cek koneksi
        try:
            async with open_client(_state.api_url, timeout=10) as c:
                await c.health()
        except Exception as e:
            render_error_panel(console, caps, f"Service tidak terjangkau: {e}")
            raise typer.Exit(3) from None

        # Cek apakah scan_id ada di list resumable
        try:
            async with open_client(_state.api_url, timeout=10) as c:
                resumable = await c.list_resumable()
        except Exception as e:
            render_error_panel(console, caps, f"Gagal ambil daftar resumable: {e}")
            raise typer.Exit(3) from None

        resumable_ids = {r["scan_id"] for r in resumable}
        if scan_id not in resumable_ids:
            render_error_panel(
                console, caps,
                f"Scan {scan_id} tidak memiliki checkpoint untuk resume.",
                "Gunakan `cyense list` untuk melihat scan yang tersedia.",
            )
            raise typer.Exit(3)

        # Find the original scan's mode and build resume payload
        cp_info = next(r for r in resumable if r["scan_id"] == scan_id)
        mode = cp_info.get("mode", "program")

        payload: dict = {
            "mode": mode,
            "i_have_permission": True,
            "resume_from": scan_id,
        }
        if instruction:
            payload["instruction"] = instruction

        await _run_scan(
            payload=payload,
            mode=mode,
            out_path=out,
            no_md=no_md,
            fail_on=fail_on,
            min_severity=min_severity,
        )

    _run(_do())


# ---------------------------------------------------------------------------
# scan multi — scan multiple targets dari file (Strix --target-list pattern)

@scan_app.command("multi")
def scan_multi(
    targets_file: Annotated[
        str, typer.Argument(help="Path file berisi daftar target (satu per baris).")
    ],
    i_have_permission: Annotated[
        bool,
        typer.Option(
            "--i-have-permission",
            help="[wajib] Konfirmasi izin audit semua target.",
        ),
    ] = False,
    scan_mode: Annotated[str, typer.Option("--scan-mode")] = "standard",
    scope_mode: Annotated[str, typer.Option("--scope-mode")] = "auto",
    fail_on: Annotated[str, typer.Option("--fail-on")] = "none",
    min_severity: Annotated[str, typer.Option("--min-severity")] = "info",
) -> None:
    """Scan multiple targets dari file (Strix --target-list pattern)."""

    async def _do():
        caps = _state.caps
        console = _state.console

        if not caps.quiet:
            render_banner(console, caps, _VERSION)

        # Parse targets file
        try:
            from app.services.multi_scan import parse_targets_file
            targets = parse_targets_file(targets_file)
        except (OSError, ValueError) as e:
            render_error_panel(console, caps, f"Gagal baca targets file: {e}")
            raise typer.Exit(3) from None

        if not targets:
            render_error_panel(console, caps, "File targets kosong.")
            raise typer.Exit(3)

        # Check connection
        try:
            async with open_client(_state.api_url, timeout=10) as c:
                await c.health()
        except Exception as e:
            render_error_panel(console, caps, f"Service tidak terjangkau: {e}")
            raise typer.Exit(3) from None

        from app.cli.theme import PALETTE as PAL

        if not caps.quiet:
            console.print(
                f"  [{PAL.blue_soft}]Targets:[/] [{PAL.ink}]{len(targets)} "
                f"target dari {targets_file}[/]"
            )

        # Submit each target as individual scan
        scan_ids: list[tuple[str, str]] = []  # (scan_id, label)
        for target in targets:
            ttype = target.get("type", "unknown")
            label = target.get("url") or target.get("path") or ttype
            payload: dict = {
                "mode": ttype if ttype in ("github", "program", "link") else "program",
                "i_have_permission": i_have_permission,
                "scan_mode": scan_mode,
                "scope_mode": scope_mode,
            }
            if ttype == "github":
                payload["repo_url"] = target["url"]
                if "ref" in target:
                    payload["ref"] = target["ref"]
                if "lang" in target:
                    payload["lang"] = target["lang"]
            elif ttype in ("url", "link"):
                payload["mode"] = "link"
                payload["url"] = target["url"]
            else:
                payload["mode"] = "program"

            try:
                async with open_client(_state.api_url, timeout=30) as c:
                    result = await c.submit_scan(payload)
                sid = result["scan_id"]
                scan_ids.append((sid, label))
                if not caps.quiet:
                    console.print(f"  [{PAL.blue_soft}]  → {sid}[/]  [{PAL.muted}]{label}[/]")
            except Exception as e:
                if not caps.quiet:
                    console.print(f"  [{PAL.error}]  ✗ gagal submit:[/] {label}: {e}")

        if not scan_ids:
            render_error_panel(console, caps, "Tidak ada target yang berhasil di-submit.")
            raise typer.Exit(3)

        # Poll each scan until all are terminal
        if not caps.quiet:
            console.print(f"\n  [{PAL.blue_soft}]Menunggu {len(scan_ids)} scan selesai...[/]")

        pending = {sid for sid, _ in scan_ids}
        deadline = time.monotonic() + _state.timeout
        while pending and time.monotonic() < deadline:
            for sid in list(pending):
                try:
                    async with open_client(_state.api_url, timeout=10) as c:
                        data = await c.get_scan(sid)
                    if data.get("status") in ("completed", "failed"):
                        pending.discard(sid)
                except Exception:
                    pass
            if pending:
                await asyncio.sleep(2.0)

        # Summary
        if not caps.quiet:
            from rich.table import Table
            table = Table(
                show_header=True,
                header_style=f"bold {PAL.blue_primary}",
                border_style=PAL.rule_line,
                padding=(0, 1),
            )
            table.add_column("SCAN ID", style=PAL.blue_soft, width=14)
            table.add_column("TARGET", style=PAL.blue_mist, max_width=40)
            table.add_column("STATUS", width=12)

            status_color = {
                "completed": PAL.ok,
                "failed": PAL.error,
                "running": PAL.blue_accent,
                "queued": PAL.muted,
            }
            for sid, label in scan_ids:
                try:
                    async with open_client(_state.api_url, timeout=10) as c:
                        data = await c.get_scan(sid)
                    st = data.get("status", "unknown")
                except Exception:
                    st = "unknown"
                sc = status_color.get(st, PAL.muted)
                table.add_row(sid, label, f"[{sc}]{st}[/]")

            console.print(table)

        # Check fail_on
        _sev_order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
        fail_sev_val = _sev_order.get(fail_on, 0)
        exit_code = 0
        if fail_sev_val > 0:
            for sid, _ in scan_ids:
                try:
                    async with open_client(_state.api_url, timeout=10) as c:
                        report = await c.get_report(sid)
                    if report:
                        for f in report.get("findings", []):
                            if _sev_order.get(f.get("severity", "info"), 0) >= fail_sev_val:
                                exit_code = 1
                                break
                except Exception:
                    pass
                if exit_code:
                    break

        raise typer.Exit(exit_code)

    _run(_do())


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
        raise typer.Exit(3) from None

    # -- Submit scan
    scan_id: str
    try:
        async with open_client(_state.api_url, timeout=30) as c:
            result = await c.submit_scan(payload)
        scan_id = result["scan_id"]
    except ValueError as e:
        # 422 — mis. i_have_permission = false
        render_error_panel(console, caps, str(e))
        raise typer.Exit(3) from None
    except Exception as e:
        render_error_panel(console, caps, f"Gagal submit scan: {e}")
        raise typer.Exit(3) from None

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
        raise typer.Exit(3) from None
    except Exception as e:
        render_error_panel(console, caps, f"Polling error: {e}")
        raise typer.Exit(3) from None

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
                raise typer.Exit(3) from None

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
    out: Annotated[str | None, typer.Option("--out")] = None,
    no_md: Annotated[bool, typer.Option("--no-md")] = False,
) -> None:
    """Render ulang laporan scan yang sudah selesai."""

    async def _do():
        try:
            async with open_client(_state.api_url) as c:
                report = await c.get_report(scan_id)
        except Exception as e:
            render_error_panel(_state.console, _state.caps, str(e))
            raise typer.Exit(3) from None

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
            raise typer.Exit(3) from None

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
            raise typer.Exit(3) from None

        if _state.caps.json_out:
            typer.echo(json.dumps(data, indent=2))
            return

        from app.cli.theme import PALETTE as PAL
        for category, rule_list in data.items():
            _state.console.print(f"\n  [bold {PAL.blue_primary}]{category.upper()}[/]")
            for r in rule_list:
                rule_id = r.get("rule", "—")
                # severity may be a list (e.g. LINK rule: ["critical", "high", "medium"])
                # or a single string. Coerce to displayable string.
                sev_raw = r.get("severity", "—")
                sev = ",".join(sev_raw) if isinstance(sev_raw, list) else str(sev_raw)
                lang    = r.get("lang", "—") or "—"
                title   = r.get("title") or r.get("description", "")
                _state.console.print(
                    f"  [{PAL.blue_soft}]{rule_id:<8}[/]"
                    f"  [{PAL.muted}]{sev:<18}[/]"
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
            raise typer.Exit(3) from None

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
# view — buka web viewer di browser (enhanced-reporting-viewer.md §3.5.1)

@app.command("view")
def view_cmd(
    scan_id: Annotated[
        str | None, typer.Argument(help="Scan ID (atau gunakan --latest).")
    ] = None,
    latest: Annotated[bool, typer.Option("--latest", help="Buka scan terbaru.")] = False,
    no_browser: Annotated[
        bool, typer.Option("--no-browser", help="Cetak URL saja, jangan buka browser.")
    ] = False,
) -> None:
    """Buka dashboard web viewer untuk hasil scan."""
    from app.core.config_store import load_config

    cfg = load_config()

    async def _do():
        target_id = scan_id

        if latest or not target_id:
            try:
                async with open_client(_state.api_url, timeout=10) as c:
                    scans = await c.list_scans()
            except Exception as e:
                render_error_panel(_state.console, _state.caps, str(e))
                raise typer.Exit(3) from None
            if not scans:
                _state.console.print("  Tidak ada scan yang bisa dilihat.")
                raise typer.Exit(0)
            target_id = scans[0].get("scan_id")

        # Pastikan service hidup sebelum membuka browser
        try:
            async with open_client(_state.api_url, timeout=5) as c:
                await c.health()
        except Exception as e:
            render_error_panel(
                _state.console, _state.caps,
                f"Service tidak terjangkau: {e}",
                "Jalankan 'make up' atau set --api-url",
            )
            raise typer.Exit(3) from None

        url = f"{_state.api_url}/api/v1/viewer/{target_id}"
        from app.cli.theme import PALETTE as PAL
        _state.console.print(
            f"  [{PAL.blue_soft}]Viewer[/]  [{PAL.blue_mist}]{url}[/]"
        )

        if not no_browser and cfg.get("auto_open_viewer", True):
            import webbrowser
            webbrowser.open(url)

    _run(_do())


# ---------------------------------------------------------------------------
# history — daftar scan terakhir (enhanced-reporting-viewer.md §3.5.2)

@app.command("history")
def history_cmd(
    limit: Annotated[int, typer.Option("--limit", help="Jumlah maksimum baris.")] = 20,
    status_filter: Annotated[
        str | None,
        typer.Option("--status", help="Filter: completed|failed|running|queued."),
    ] = None,
    format: Annotated[str, typer.Option("--format", help="table|json")] = "table",
) -> None:
    """Tampilkan riwayat scan beserta ringkasannya."""

    async def _do():
        try:
            async with open_client(_state.api_url, timeout=15) as c:
                scans = await c.list_scans()
        except Exception as e:
            render_error_panel(_state.console, _state.caps, str(e))
            raise typer.Exit(3) from None

        if status_filter:
            scans = [s for s in scans if s.get("status") == status_filter]
        scans = scans[: max(1, limit)]

        if _state.caps.json_out or format == "json":
            typer.echo(json.dumps(scans, indent=2))
            return

        if not scans:
            _state.console.print("  Tidak ada scan.")
            return

        from rich.table import Table  # type: ignore[import-untyped]

        from app.cli.theme import PALETTE as PAL

        status_color = {
            "completed": PAL.ok,
            "failed": PAL.error,
            "running": PAL.blue_accent,
            "queued": PAL.muted,
        }

        table = Table(
            show_header=True,
            header_style=f"bold {PAL.blue_primary}",
            border_style=PAL.rule_line,
            padding=(0, 1),
        )
        table.add_column("SCAN ID",   style=PAL.blue_soft, width=14)
        table.add_column("MODE",     width=8)
        table.add_column("STATUS",   width=10)
        table.add_column("PROGRESS", justify="right", width=8)
        table.add_column("DIBUAT",   style=PAL.muted, width=20)

        for s in scans:
            st = s.get("status", "—")
            sc = status_color.get(st, PAL.muted)
            table.add_row(
                s.get("scan_id", "—"),
                s.get("mode", "—"),
                f"[{sc}]{st}[/]",
                f"{s.get('progress', 0)}%",
                (s.get("created_at") or "—")[:19].replace("T", " "),
            )
        _state.console.print(table)

    _run(_do())


# ---------------------------------------------------------------------------
# compare — bandingkan dua scan (enhanced-reporting-viewer.md §3.5.3)

@app.command("compare")
def compare_cmd(
    scan_a: Annotated[str, typer.Argument(help="Scan ID pertama (lama).")],
    scan_b: Annotated[str, typer.Argument(help="Scan ID kedua (baru).")],
    diff_only: Annotated[
        bool, typer.Option("--diff-only", help="Sembunyikan temuan yang tidak berubah.")
    ] = False,
    format: Annotated[str, typer.Option("--format", help="table|json")] = "table",
) -> None:
    """Bandingkan dua laporan scan (temuan baru / hilang / berubah)."""
    from app.report.scan_compare import compare_reports

    async def _fetch(scan_id: str):
        async with open_client(_state.api_url, timeout=20) as c:
            report = await c.get_report(scan_id)
        if report is None:
            report = load_report_from_disk(scan_id)
        return report

    async def _do():
        try:
            old = await _fetch(scan_a)
            new = await _fetch(scan_b)
        except Exception as e:
            render_error_panel(_state.console, _state.caps, str(e))
            raise typer.Exit(3) from None

        if old is None or new is None:
            missing = scan_a if old is None else scan_b
            render_error_panel(
                _state.console, _state.caps,
                f"Report tidak ditemukan: {missing}",
                "Pastikan scan sudah selesai dan service menyimpan hasilnya.",
            )
            raise typer.Exit(3)

        diff = compare_reports(old, new)

        if _state.caps.json_out or format == "json":
            typer.echo(json.dumps(diff, indent=2, default=str))
            return

        from rich.table import Table  # type: ignore[import-untyped]

        from app.cli.theme import PALETTE as PAL
        from app.cli.theme import SEVERITY_BADGE_COLOR

        _state.console.print(
            f"  [bold {PAL.blue_primary}]{scan_a}[/] → [bold {PAL.blue_primary}]{scan_b}[/]"
        )

        def _sev(f: dict) -> str:
            sev = str(f.get("severity", "info")).lower()
            bc = SEVERITY_BADGE_COLOR.get(sev, PAL.muted)
            return f"[{bc}]{sev.upper()}[/]"

        def _row(f: dict) -> tuple[str, str, str, str]:
            score = f.get("cvss_score")
            return (
                str(f.get("rule", "—")),
                _sev(f),
                f"{score:.1f}" if score is not None else "—",
                str(f.get("location") or "—"),
            )

        def _section(title: str, findings: list[dict]) -> None:
            if not findings:
                return
            _state.console.print(f"\n  [bold {PAL.blue_accent}]{title}[/] ({len(findings)})")
            table = Table(
                show_header=False, border_style=PAL.rule_line, padding=(0, 1),
            )
            table.add_column("RULE", style=PAL.blue_soft, width=8)
            table.add_column("SEV", width=10)
            table.add_column("CVSS", width=5, justify="right")
            table.add_column("LOCATION", style=PAL.blue_mist, max_width=48)
            for f in findings:
                table.add_row(*_row(f))
            _state.console.print(table)

        _section("TAMBAH (baru saja)", diff["added"])
        _section("HILANG (terperbaiki/dihapus)", diff["removed"])
        if diff["changed"]:
            _state.console.print(f"\n  [bold {PAL.sev_medium}]BERUBAH[/] ({len(diff['changed'])})")
            table = Table(show_header=False, border_style=PAL.rule_line, padding=(0, 1))
            table.add_column("RULE", style=PAL.blue_soft, width=8)
            table.add_column("SEBELUM", width=12)
            table.add_column("SESUDAH", width=12)
            table.add_column("LOCATION", style=PAL.blue_mist, max_width=40)
            for c in diff["changed"]:
                o, n = c["old"], c["new"]
                table.add_row(
                    str(o.get("rule", "—")),
                    _sev(o),
                    _sev(n),
                    str(o.get("location") or "—"),
                )
            _state.console.print(table)
        if not diff_only:
            _section("TIDAK BERUBAH", diff["unchanged"])

        c = diff["counts"]
        _state.console.print(
            f"\n  [{PAL.muted}]Ringkasan:[/] "
            f"[{PAL.ok}]{c['unchanged']} tetap[/] · "
            f"[{PAL.sev_high}]{c['added']} baru[/] · "
            f"[{PAL.ok}]{c['removed']} hilang[/] · "
            f"[{PAL.sev_medium}]{c['changed']} berubah[/]"
        )

    _run(_do())


# ---------------------------------------------------------------------------
# export — unduh CSV/PDF (enhanced-reporting-viewer.md §3.2, §3.3)

export_app = typer.Typer(help="Ekspor hasil scan ke format lain.", no_args_is_help=True)
app.add_typer(export_app, name="export")


@export_app.command("csv")
def export_csv_cmd(
    scan_id: Annotated[str, typer.Argument(help="Scan ID.")],
    out: Annotated[str | None, typer.Option("--out", "-o", help="Path output .csv.")] = None,
    no_remediation: Annotated[
        bool, typer.Option("--no-remediation", help="Tanpa kolom remediation.")
    ] = False,
) -> None:
    """Unduh temuan sebagai CSV."""

    async def _do():
        try:
            async with open_client(_state.api_url, timeout=60) as c:
                csv_text = await c.get_csv_export(scan_id, include_remediation=not no_remediation)
        except Exception as e:
            render_error_panel(_state.console, _state.caps, str(e))
            raise typer.Exit(3) from None

        dest = Path(out) if out else Path(f"cyense-{scan_id}-findings.csv")
        dest.write_text(csv_text, encoding="utf-8")
        from app.cli.theme import PALETTE as PAL
        _state.console.print(
            f"  [{PAL.ok}]CSV tersimpan:[/] [{PAL.blue_mist}]{dest}[/] "
            f"[{PAL.muted}]({len(csv_text.splitlines()) - 1} baris)[/]"
        )

    _run(_do())


@export_app.command("pdf")
def export_pdf_cmd(
    scan_id: Annotated[str, typer.Argument(help="Scan ID.")],
    out: Annotated[str | None, typer.Option("--out", "-o", help="Path output .pdf.")] = None,
) -> None:
    """Unduh laporan compliance PDF."""

    async def _do():
        try:
            async with open_client(_state.api_url, timeout=120) as c:
                pdf_bytes = await c.get_pdf_export(scan_id)
        except Exception as e:
            render_error_panel(_state.console, _state.caps, str(e))
            raise typer.Exit(3) from None

        dest = Path(out) if out else Path(f"cyense-{scan_id}-report.pdf")
        dest.write_bytes(pdf_bytes)
        from app.cli.theme import PALETTE as PAL
        _state.console.print(
            f"  [{PAL.ok}]PDF tersimpan:[/] [{PAL.blue_mist}]{dest}[/] "
            f"[{PAL.muted}]({len(pdf_bytes) / 1024:.0f} KB)[/]"
        )

    _run(_do())


# ---------------------------------------------------------------------------
# config — persistensi preferensi (enhanced-reporting-viewer.md §3.6)

config_app = typer.Typer(
    help="Kelola preferensi CLI (~/.cyense/config.json).",
    no_args_is_help=True,
)
app.add_typer(config_app, name="config")


@config_app.command("list")
def config_list_cmd() -> None:
    """Tampilkan seluruh konfigurasi (secret dimask)."""
    from app.core.config_store import load_config, printable_config

    cfg = printable_config(load_config())
    from app.cli.theme import PALETTE as PAL
    for key, value in cfg.items():
        _state.console.print(f"  [{PAL.blue_soft}]{key:<22}[/] [{PAL.ink}]{value}[/]")


@config_app.command("get")
def config_get_cmd(
    key: Annotated[str, typer.Argument(help="Nama key konfigurasi.")],
) -> None:
    """Tampilkan nilai satu key (secret dimask)."""
    from app.core.config_store import load_config, printable_config

    cfg = printable_config(load_config())
    if key not in cfg:
        render_error_panel(_state.console, _state.caps, f"Key tidak dikenal: {key}")
        raise typer.Exit(3)
    from app.cli.theme import PALETTE as PAL
    _state.console.print(f"  [{PAL.blue_soft}]{key}[/] = [{PAL.ink}]{cfg[key]}[/]")


@config_app.command("set")
def config_set_cmd(
    key: Annotated[str, typer.Argument(help="Nama key konfigurasi.")],
    value: Annotated[str, typer.Argument(help="Nilai baru (JSON-aware: true, 8080, \"teks\").")],
) -> None:
    """Set satu key dan simpan (file 0o600, tulis atomik)."""
    from app.core import config_store

    parsed: object
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        parsed = value

    try:
        config_store.set_value(key, parsed)
    except KeyError as e:
        render_error_panel(_state.console, _state.caps, str(e))
        raise typer.Exit(3) from None

    from app.cli.theme import PALETTE as PAL
    masked = config_store.printable_config(config_store.load_config()).get(key)
    _state.console.print(
        f"  [{PAL.ok}]Tersimpan.[/] [{PAL.blue_soft}]{key}[/] = [{PAL.ink}]{masked}[/]"
    )


@config_app.command("reset")
def config_reset_cmd(
    confirm: Annotated[
        bool,
        typer.Option("--confirm", help="Wajib untuk benar-benar reset."),
    ] = False,
) -> None:
    """Kembalikan seluruh konfigurasi ke default."""
    from app.cli.theme import PALETTE as PAL
    from app.core.config_store import reset_config

    if not confirm:
        app_name = config_app.info.name if hasattr(config_app, "info") else "config"
        _state.console.print(
            f"  [{PAL.sev_medium}]{app_name}: reset butuh --confirm[/]"
        )
        raise typer.Exit(3)
    reset_config()
    _state.console.print(f"  [{PAL.ok}]Konfigurasi direset ke default.[/]")


# ---------------------------------------------------------------------------
# version

@app.command("launch")
def launch_cmd(
    port: Annotated[int, typer.Option("--port", help="Port backend FastAPI.")] = 8000,
    host: Annotated[str, typer.Option("--host", help="Host backend FastAPI.")] = "127.0.0.1",
    mode: Annotated[
        str | None,
        typer.Option(
            "--mode",
            help="Pilih mode langsung tanpa menu: 'website' atau 'cli'.",
        ),
    ] = None,
    open_browser: Annotated[
        bool,
        typer.Option(
            "--open/--no-open",
            help="Buka browser otomatis saat mode website (default: ya).",
        ),
    ] = True,
) -> None:
    """Jalankan Cyense — pilih mode Website atau CLI.

    Website : menjalankan backend FastAPI + frontend Svelte, lalu menampilkan
              lokasi website (http://host:port/ui).
    CLI     : memastikan backend FastAPI berjalan (background bila belum),
              lalu client-side memakai CLI berbasis command.
    """
    from app.cli.launch import run_cli_mode, run_website_mode

    if mode is None:
        _state.console.print()
        _state.console.print("  [bold]Pilih cara menjalankan Cyense:[/]")
        _state.console.print()
        _state.console.print("    [bold cyan]1[/]  Website — backend FastAPI + frontend Svelte")
        _state.console.print("    [bold cyan]2[/]  Command Line Interface — CLI (backend FastAPI)")
        _state.console.print()
        try:
            choice = input("  Pilihan [1/2]: ").strip()
        except (EOFError, KeyboardInterrupt):
            _state.console.print("\n  Dibatalkan.")
            raise typer.Exit(130) from None
        if choice == "2":
            mode = "cli"
        else:
            mode = "website"

    if mode == "cli":
        code = run_cli_mode(host, port)
        raise typer.Exit(code)
    else:
        # Website mode blocks (foreground server).
        code = run_website_mode(host, port, open_browser=open_browser)
        raise typer.Exit(code)


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
# auth — credential management (Strix-inspired `strix auth login/status/logout`)

auth_app = typer.Typer(help="Kelola kredensial (GitHub token, dll).", no_args_is_help=True)
app.add_typer(auth_app, name="auth")


@auth_app.command("login")
def auth_login(
    provider: Annotated[
        str,
        typer.Argument(help="Provider: github"),
    ],
    token: Annotated[
        str | None,
        typer.Option(
            "--token",
            envvar="CYENSE_GITHUB_TOKEN",
            help="Token value. If omitted, reads from CYENSE_GITHUB_TOKEN env var.",
        ),
    ] = None,
) -> None:
    """Save a provider token to local config (0o600, atomic write).

    \b
    Examples:
      cyense auth login github --token ghp_xxxx
      export CYENSE_GITHUB_TOKEN=ghp_xxxx && cyense auth login github
    """
    from app.cli.theme import PALETTE as PAL
    from app.core.config_store import load_config, save_config

    if provider.lower() != "github":
        render_error_panel(
            _state.console, _state.caps,
            f"Unknown provider: {provider}. Currently supported: github.",
        )
        raise typer.Exit(3)

    if not token:
        render_error_panel(
            _state.console, _state.caps,
            "No token provided. Use --token or set CYENSE_GITHUB_TOKEN env var.",
        )
        raise typer.Exit(3)

    # Validate GitHub token format (basic check)
    if not token.startswith(("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_")):
        _state.console.print(
            f"  [{_state.caps.g().warn}] Warning: token tidak dimulai dengan prefix GitHub "
            f"(ghp_/gho_/ghu_/ghs_/ghr_/github_pat_). Mungkin bukan token GitHub yang valid."
        )

    config = load_config()
    config["github_token"] = token
    path = save_config(config)

    masked = f"{token[:4]}...{token[-4:]}" if len(token) > 8 else "[REDACTED]"
    _state.console.print(
        f"  [{PAL.ok}]✓ GitHub token tersimpan.[/]  "
        f"[{PAL.blue_soft}]{masked}[/]  [{PAL.muted}]→ {path}[/]"
    )
    _state.console.print(
        f"  [{PAL.muted}]Token akan otomatis dipakai oleh `cyense scan github`.[/]"
    )


@auth_app.command("status")
def auth_status() -> None:
    """Show current authentication status."""
    from app.cli.theme import PALETTE as PAL
    from app.core.config_store import load_config

    config = load_config()
    github_token = config.get("github_token")

    _state.console.print(f"\n  [{PAL.blue_primary}]Authentication Status[/]")
    _state.console.print(f"  {'─' * 40}")

    if github_token:
        if len(github_token) > 8:
            masked = f"{github_token[:4]}...{github_token[-4:]}"
        else:
            masked = "[REDACTED]"
        _state.console.print(
            f"  [{PAL.ok}]✓ GitHub[/]    [{PAL.blue_soft}]{masked}[/]"
        )
    else:
        _state.console.print(
            f"  [{PAL.muted}]✗ GitHub[/]    [{PAL.muted}]not configured[/]"
        )
        _state.console.print(
            f"  [{PAL.muted}]  Run `cyense auth login github --token <token>` to set up.[/]"
        )

    _state.console.print()


@auth_app.command("logout")
def auth_logout(
    provider: Annotated[
        str,
        typer.Argument(help="Provider: github"),
    ],
    confirm: Annotated[
        bool,
        typer.Option("--confirm", help="Required to actually remove the token."),
    ] = False,
) -> None:
    """Remove a provider token from local config.

    Requires --confirm to prevent accidental removal.
    """
    from app.cli.theme import PALETTE as PAL
    from app.core.config_store import load_config, save_config

    if provider.lower() != "github":
        render_error_panel(
            _state.console, _state.caps,
            f"Unknown provider: {provider}. Currently supported: github.",
        )
        raise typer.Exit(3)

    if not confirm:
        _state.console.print(
            f"  [{_state.caps.g().warn}] Use --confirm to remove the GitHub token."
        )
        raise typer.Exit(3)

    config = load_config()
    had_token = config.get("github_token") is not None
    config["github_token"] = None
    save_config(config)

    if had_token:
        _state.console.print(f"  [{PAL.ok}]✓ GitHub token removed from config.[/]")
    else:
        _state.console.print(f"  [{PAL.muted}]No GitHub token was configured.[/]")


# ---------------------------------------------------------------------------
# ci — CI/CD integration helpers (Strix-inspired CI workflow)

ci_app = typer.Typer(help="CI/CD integration helpers.", no_args_is_help=True)
app.add_typer(ci_app, name="ci")


@ci_app.command("junit")
def ci_junit(
    scan_id: Annotated[str, typer.Argument(help="Scan ID to export as JUnit XML.")],
    out: Annotated[
        str | None,
        typer.Option("--out", "-o", help="Output file path (default: stdout)."),
    ] = None,
) -> None:
    """Export scan findings as JUnit XML for CI/CD integration.

    Each finding becomes a test failure; clean scans produce a passing test suite.
    Compatible with GitHub Actions, GitLab CI, Jenkins, etc.

    \b
    Examples:
      cyense ci junit <scan_id> --out results.xml
      cyense ci junit <scan_id> > results.xml
    """
    import xml.etree.ElementTree as ET

    async def _do():
        try:
            async with open_client(_state.api_url) as c:
                report = await c.get_report(scan_id)
        except Exception as e:
            render_error_panel(_state.console, _state.caps, str(e))
            raise typer.Exit(3) from None

        if report is None:
            report = load_report_from_disk(scan_id)

        if report is None:
            render_error_panel(
                _state.console, _state.caps,
                f"Report not found: {scan_id}",
            )
            raise typer.Exit(3)

        findings = report.get("findings", [])
        summary = report.get("summary", {})
        meta = report.get("meta", {})

        # Build JUnit XML
        testsuite = ET.Element("testsuite")
        testsuite.set("name", f"cyense-{meta.get('mode', 'scan')}")
        # `tests` must equal the number of <testcase> elements emitted below:
        # a clean scan emits exactly 1 passing case, a findings scan emits
        # len(findings) cases. The previous "len(findings) + 1" produced a
        # phantom test that CI consumers (GitHub Actions/Jenkins) reject.
        testsuite.set("tests", str(max(1, len(findings))))
        testsuite.set("failures", str(len(findings)))
        testsuite.set("errors", "0")
        testsuite.set("time", f"{summary.get('duration_ms', 0) / 1000:.2f}")
        testsuite.set("timestamp", meta.get("created_at", ""))

        if not findings:
            # Clean scan — one passing test
            testcase = ET.SubElement(testsuite, "testcase")
            testcase.set("name", "cyense-scan-clean")
            testcase.set("classname", f"cyense.{meta.get('mode', 'scan')}")
            testcase.set("time", f"{summary.get('duration_ms', 0) / 1000:.2f}")
        else:
            for f in findings:
                testcase = ET.SubElement(testsuite, "testcase")
                rule = f.get("rule", "unknown")
                location = f.get("location", "unknown")
                testcase.set("name", f"{rule}@{location}")
                testcase.set("classname", f"cyense.{meta.get('mode', 'scan')}.{rule}")
                testcase.set("time", "0.00")

                failure = ET.SubElement(testcase, "failure")
                severity = f.get("severity", "info").upper()
                cvss = f.get("cvss_score")
                cvss_str = f" (CVSS {cvss:.1f})" if cvss else ""
                failure.set("message", f"[{severity}{cvss_str}] {f.get('title', rule)}")
                failure.set("type", rule)

                # Build failure text with details
                parts = [
                    f"Severity: {severity}{cvss_str}",
                    f"Rule: {rule}",
                    f"Location: {location}",
                    f"Title: {f.get('title', '')}",
                    f"Description: {f.get('description', '')}",
                ]
                cwe = f.get("cwe")
                if cwe:
                    parts.append(f"CWE: {cwe}")
                remediation = f.get("remediation")
                if remediation:
                    parts.append(f"\nRemediation: {remediation}")
                failure.text = "\n".join(parts)

        xml_str = ET.tostring(testsuite, encoding="unicode", xml_declaration=True)

        if out:
            Path(out).write_text(xml_str, encoding="utf-8")
            from app.cli.theme import PALETTE as PAL
            _state.console.print(
                f"  [{PAL.ok}]JUnit XML written:[/] [{PAL.blue_mist}]{out}[/] "
                f"[{PAL.muted}]({len(findings)} finding(s))[/]"
            )
        else:
            typer.echo(xml_str)

    _run(_do())


@ci_app.command("check")
def ci_check(
    scan_id: Annotated[str, typer.Argument(help="Scan ID to check.")],
    fail_on: Annotated[
        str,
        typer.Option(
            "--fail-on",
            help="Exit 1 if any finding ≥ this severity (info|low|medium|high|critical).",
        ),
    ] = "high",
) -> None:
    """Check a scan result and exit with code 1 if findings exceed threshold.

    Designed for CI/CD pipelines: use as a quality gate step.

    \b
    Exit codes:
      0 = no findings above threshold (pass)
      1 = findings above threshold (fail)
      3 = error (scan not found, service unreachable)
    """
    _sev_order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    # --fail-on none means "never fail the gate" (default 0), consistent with
    # the other scan commands; the previous default of 4 made --fail-on none
    # behave like --fail-on high.
    fail_sev_val = _sev_order.get(fail_on, 0)

    async def _do():
        from app.cli.theme import PALETTE as PAL

        try:
            async with open_client(_state.api_url) as c:
                report = await c.get_report(scan_id)
        except Exception as e:
            render_error_panel(_state.console, _state.caps, str(e))
            raise typer.Exit(3) from None

        if report is None:
            report = load_report_from_disk(scan_id)

        if report is None:
            render_error_panel(
                _state.console, _state.caps,
                f"Report not found: {scan_id}",
            )
            raise typer.Exit(3)

        findings = report.get("findings", [])
        summary = report.get("summary", {})

        # --fail-on none means "never fail the gate" — skip the threshold
        # comparison entirely (fail_sev_val == 0 would otherwise match every
        # finding including info).
        if fail_sev_val == 0:
            _state.console.print(f"\n  [{PAL.blue_primary}]CI Quality Gate[/]")
            _state.console.print(
                f"  [{PAL.ok}]✓ PASS[/] — --fail-on none: gate dilewati "
                f"({len(findings)} temuan tidak memengaruhi exit code)."
            )
            raise typer.Exit(0)

        # Count findings above threshold
        above = [
            f for f in findings
            if _sev_order.get(f.get("severity", "info"), 0) >= fail_sev_val
        ]

        _state.console.print(f"\n  [{PAL.blue_primary}]CI Quality Gate[/]")
        _state.console.print(f"  {'─' * 40}")
        _state.console.print(f"  Scan ID:       [{PAL.blue_soft}]{scan_id}[/]")
        _state.console.print(f"  Total findings: {summary.get('total', 0)}")
        _state.console.print(f"  Threshold:     [{PAL.blue_soft}]≥ {fail_on}[/]")
        _state.console.print(f"  Above threshold: {len(above)}")
        _state.console.print()

        if above:
            _state.console.print(
                f"  [{PAL.error}]✗ FAIL[/] — {len(above)} finding(s) "
                "above threshold:"
            )
            for f in above[:10]:
                sev = f.get("severity", "info").upper()
                _state.console.print(
                    f"    [{PAL.error}]{sev}[/] {f.get('rule', '?')} @ {f.get('location', '?')}"
                )
                _state.console.print(f"      {f.get('title', '')[:80]}")
            if len(above) > 10:
                _state.console.print(f"    ... and {len(above) - 10} more")
            raise typer.Exit(1)
        else:
            _state.console.print(f"  [{PAL.ok}]✓ PASS[/] — no findings above threshold.")
            raise typer.Exit(0)

    _run(_do())


# ---------------------------------------------------------------------------
# Entrypoint

if __name__ == "__main__":
    app()
