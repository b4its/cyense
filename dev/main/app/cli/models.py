"""Data models untuk CLI state (cli-experience.md §4)."""

from __future__ import annotations

import math
from typing import Any, Literal

from pydantic import BaseModel, Field

# Severity enum diimpor dari core — CLI tidak mendefinisikan sendiri
# (cli-experience.md §4: "Severity diimpor dari app/core/models.py:15")
from app.core.models import Severity  # noqa: F401 — re-export

# ---------------------------------------------------------------------------
# Konfigurasi CLI

class CliConfig(BaseModel):
    """Konfigurasi runtime CLI — dikumpulkan dari flag + env."""

    api_url: str = "http://localhost:8000"
    color: bool = True
    ascii_only: bool = False
    quiet: bool = False
    json_out: bool = False
    timeout: float = 300.0
    width: int = 100  # hasil shutil.get_terminal_size()


# ---------------------------------------------------------------------------
# Render context (state selama polling)

class StageInfo(BaseModel):
    name: str
    status: Literal["pending", "active", "done", "failed"] = "pending"
    started_at: float | None = None   # monotonic
    elapsed: float | None = None       # detik
    last_message: str = ""


class RenderContext(BaseModel):
    """State yang dipegang renderer selama polling berlangsung."""

    scan_id: str
    mode: Literal["github", "program", "link", "website", "domain", "api"]
    stages: list[str]                             # urutan stage sesuai mode
    stage_info: dict[str, StageInfo] = Field(default_factory=dict)
    current_stage: str | None = None
    progress: int = 0
    rendered_events: int = 0                      # penanda delta events[]
    rendered_findings: set[str] = Field(default_factory=set)  # finding_id sudah dicetak

    def mark_stage_active(self, name: str, ts: float) -> None:
        if name not in self.stage_info:
            self.stage_info[name] = StageInfo(name=name)
        self.stage_info[name].status = "active"
        self.stage_info[name].started_at = ts
        self.current_stage = name

    def mark_stage_done(self, name: str, ts: float) -> None:
        info = self.stage_info.get(name)
        if info and info.started_at is not None:
            info.elapsed = ts - info.started_at
        if info:
            info.status = "done"

    def mark_stage_failed(self, name: str) -> None:
        info = self.stage_info.get(name)
        if info:
            info.status = "failed"


# ---------------------------------------------------------------------------
# Rekomendasi / saran perbaikan (cli-experience.md §3.5)

class Recommendation(BaseModel):
    """Hasil agregasi §3.5 — dipakai terminal DAN markdown."""

    rule: str
    severity: str                    # string agar tidak butuh import enum di md_report
    max_confidence: float
    occurrences: int
    score: float
    category: Literal["priority", "quick_win", "structural"]
    action: str                      # dari Finding.remediation
    affected: list[str]              # location[], maks 5 + ringkasan

    @property
    def label(self) -> str:
        """Label tampilan di terminal/markdown."""
        if self.category == "quick_win":
            return "QUICK WIN"
        if self.category == "structural":
            return "STRUKTURAL"
        return "PRIORITAS"


# ---------------------------------------------------------------------------
# Opsi laporan Markdown

class MarkdownReportOptions(BaseModel):
    include_evidence: bool = True
    include_verification: bool = True
    max_evidence_lines: int = 12
    frontmatter: bool = True


# ---------------------------------------------------------------------------
# Helper: bobot severity untuk scoring (cli-experience.md §3.5 poin 2)

SEVERITY_WEIGHT: dict[str, int] = {
    "critical": 100,
    "high": 50,
    "medium": 20,
    "low": 5,
    "info": 1,
}

# Urutan stage per mode (cli-experience.md §3.6)
MODE_STAGES: dict[str, list[str]] = {
    "github":  ["resolve", "fetch", "analyze", "report"],
    "program": ["recon", "probe", "report"],
    "link":    ["recon", "probe", "verify", "report"],
    "website": ["crawl", "analyze", "port-scan", "cve", "discovery",
                 "harvest", "osint", "re", "nikto", "nuclei", "sec-live",
                 "probe", "sqli", "report"],
    "domain":  ["enumerate", "hosts", "host", "report"],
}


def score_group(
    severity_max: str,
    confidence_max: float,
    occurrences: int,
) -> float:
    """Hitung skor kelompok temuan (cli-experience.md §3.5 poin 2)."""
    w = SEVERITY_WEIGHT.get(severity_max, 1)
    return w * confidence_max * math.log2(1 + occurrences)


def classify_recommendation(
    severity_max: str,
    locations: list[str],
) -> Literal["priority", "quick_win", "structural"]:
    """Klasifikasikan rekomendasi (cli-experience.md §3.5 poin 4)."""
    unique_files: set[str] = set()
    for loc in locations:
        if not loc:
            continue
        # URLs (website recon locations like https://t.com/login?x=1) are the
        # same target host — key by origin (scheme://host) rather than the
        # literal "https" that a naive ':' split produced, which would inflate
        # the count and mis-classify every multi-URL group as structural.
        if "://" in loc:
            try:
                from urllib.parse import urlparse
                parsed = urlparse(loc)
                unique_files.add(f"{parsed.scheme}://{parsed.netloc}")
            except ValueError:
                unique_files.add(loc)
        else:
            unique_files.add(loc.split(":")[0])
    if severity_max == "critical" or len(unique_files) >= 3:
        return "structural"
    if len(unique_files) == 1 and severity_max not in ("critical", "high"):
        return "quick_win"
    return "priority"


def get_finding_dict(f: Any) -> dict[str, Any]:
    """Normalise Finding — bisa Pydantic model atau plain dict."""
    if hasattr(f, "model_dump"):
        return f.model_dump(mode="json")
    return dict(f)
