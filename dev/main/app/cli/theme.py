"""Design system token & kapabilitas terminal (cli-experience.md §3.1).

Satu sumber kebenaran untuk seluruh warna, glyph, dan degradasi.
Tidak ada hex/ANSI code tersebar di modul lain.
"""

from __future__ import annotations

import os
import shutil
import sys
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# §3.1.1  Token warna (hex → Rich color string)

@dataclass(frozen=True)
class Palette:
    # Palet biru (≥85 % dari semua output berwarna)
    navy_deep:    str = "#0B1F3A"   # 17  — latar banner, garis pemisah tebal
    blue_primary: str = "#1D4ED8"   # 27  — judul panel, border aktif, nama command
    blue_accent:  str = "#3B82F6"   # 33  — stage aktif, spinner, bar progres terisi
    blue_soft:    str = "#93C5FD"   # 111 — label field, key pada key-value
    blue_mist:    str = "#DBEAFE"   # 189 — teks sekunder, hint

    # Netral
    ink:          str = "#E2E8F0"   # 253 — teks utama
    muted:        str = "#64748B"   # 245 — timestamp, elapsed, path, bar kosong
    rule_line:    str = "#1E3A5F"   # 24  — garis pemisah tipis

    # Satu-satunya warna non-biru untuk UI umum
    ok:           str = "#22D3EE"   # 51  — cyan; stage selesai, ✔
    error:        str = "#EF4444"   # 196 — stage gagal, ✖

    # Badge severity (selaras html_report.py:14-20)
    sev_critical: str = "#7F1D1D"   # merah tua
    sev_high:     str = "#C2410C"   # oranye bakar
    sev_medium:   str = "#A16207"   # amber
    sev_low:      str = "#1D4ED8"   # biru (= blue_primary)
    sev_info:     str = "#374151"   # abu


PALETTE = Palette()


# ---------------------------------------------------------------------------
# §3.1.2  Badge severity

SEVERITY_BADGE_COLOR: dict[str, str] = {
    "critical": PALETTE.sev_critical,
    "high":     PALETTE.sev_high,
    "medium":   PALETTE.sev_medium,
    "low":      PALETTE.sev_low,
    "info":     PALETTE.sev_info,
}

# Glyph blok untuk severity (di samping badge)
SEVERITY_GLYPH: dict[str, str] = {
    "critical": "██",
    "high":     "▓▓",
    "medium":   "▒▒",
    "low":      "░░",
    "info":     "··",
}

SEVERITY_GLYPH_ASCII: dict[str, str] = {
    "critical": "**",
    "high":     "##",
    "medium":   "==",
    "low":      "--",
    "info":     "..",
}


# ---------------------------------------------------------------------------
# §3.1.3  Glyph utama

@dataclass(frozen=True)
class Glyphs:
    # Status
    ok:       str = "✔"
    fail:     str = "✖"
    active:   str = "▸"
    warn:     str = "⚠"
    bullet:   str = "•"
    priority: str = "●"
    minor:    str = "○"
    arrow:    str = "↳"

    # Box drawing (rounded)
    tl: str = "╭"
    tr: str = "╮"
    bl: str = "╰"
    br: str = "╯"
    h:  str = "─"
    v:  str = "│"
    lt: str = "├"
    rt: str = "┤"

    # Spinner frames (braille)
    spinner: tuple[str, ...] = ("⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏")
    spinner_interval_ms: int = 80

    # Fallback ASCII
    ok_ascii:      str = "[ok]"
    fail_ascii:    str = "[x]"
    active_ascii:  str = ">"
    warn_ascii:    str = "[!]"
    bullet_ascii:  str = "*"
    priority_ascii:str = "(*)"
    minor_ascii:   str = "( )"
    arrow_ascii:   str = "->"
    tl_ascii:      str = "+"
    tr_ascii:      str = "+"
    bl_ascii:      str = "+"
    br_ascii:      str = "+"
    h_ascii:       str = "-"
    v_ascii:       str = "|"
    lt_ascii:      str = "+"
    rt_ascii:      str = "+"
    spinner_ascii: tuple[str, ...] = ("|", "/", "-", "\\")


GLYPHS = Glyphs()


# ---------------------------------------------------------------------------
# §3.1.4  Deteksi kapabilitas terminal

def _env_flag(*names: str) -> bool:
    """True bila salah satu nama env var diset ke nilai truthy."""
    for name in names:
        v = os.environ.get(name, "")
        if v and v.lower() not in ("0", "false", "no", ""):
            return True
    return False


@dataclass
class TermCaps:
    """Kapabilitas terminal yang terdeteksi saat startup."""
    is_tty: bool
    width: int
    color: bool       # False = NO_COLOR, --no-color, atau non-TTY
    unicode: bool     # False = encoding bukan UTF / CYENSE_CLI_ASCII
    quiet: bool = False
    json_out: bool = False

    # Derived helpers
    @property
    def ascii_only(self) -> bool:
        return not self.unicode

    def glyph(self, unicode_char: str, ascii_char: str) -> str:
        return unicode_char if self.unicode else ascii_char

    def badge_glyph(self, severity: str) -> str:
        if self.unicode:
            return SEVERITY_GLYPH.get(severity, "··")
        return SEVERITY_GLYPH_ASCII.get(severity, "..")

    def g(self) -> Glyphs:
        return GLYPHS


def detect_caps(
    *,
    force_no_color: bool = False,
    force_ascii: bool = False,
    force_quiet: bool = False,
    force_json: bool = False,
    width_override: int | None = None,
) -> TermCaps:
    """Deteksi kapabilitas terminal — dipanggil sekali di startup CLI."""
    is_tty = sys.stdout.isatty()
    w = width_override or shutil.get_terminal_size((100, 24)).columns

    # Warna: mati bila NO_COLOR (no-color.org), --no-color, atau non-TTY
    no_color = (
        force_no_color
        or _env_flag("NO_COLOR")
        or not is_tty
    )

    # Unicode: mati bila CYENSE_CLI_ASCII, --ascii, atau encoding bukan UTF
    enc = getattr(sys.stdout, "encoding", "utf-8") or "ascii"
    no_unicode = (
        force_ascii
        or _env_flag("CYENSE_CLI_ASCII")
        or "utf" not in enc.lower()
    )

    return TermCaps(
        is_tty=is_tty,
        width=max(w, 20),
        color=not no_color,
        unicode=not no_unicode,
        quiet=force_quiet,
        json_out=force_json,
    )


def make_rich_console(caps: TermCaps):  # -> rich.console.Console
    """Buat Rich Console yang sesuai kapabilitas terminal."""
    from rich.console import Console  # type: ignore[import-untyped]

    return Console(
        color_system="truecolor" if caps.color else None,
        force_terminal=caps.is_tty,
        width=caps.width,
        highlight=False,
        markup=True,
    )
