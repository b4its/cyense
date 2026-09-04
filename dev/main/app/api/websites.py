"""Saved scan results: a persistent list of websites that have been scanned.

The web UI stores a "daftar website yang sudah di-scan" — one entry per
target host/domain — built from the job store (persisted in
``reports_dir/store.json``) plus each scan's report.json on disk. Entries
survive service restarts because they are derived from persisted artifacts
(the store dump + per-scan report files), never from in-memory state alone.

GET /websites — list scanned websites, deduplicated by host, newest first.
Each entry carries the latest scan's id, status, timestamps and the severity
summary from its saved report (disk fallback after restart).
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

from fastapi import APIRouter, Request

from app.api._disk_utils import load_disk_report_or_none
from app.core.models import ScanStatus

router = APIRouter(tags=["websites"])


def _target_of(job) -> str:
    """Best displayable target for a job (url, domain or repo_url)."""
    req = job.request
    for attr in ("url", "domain", "repo_url"):
        value = getattr(req, attr, "") or ""
        if value:
            return value
    return req.mode


def _host_of(target: str) -> str:
    """Host/domain portion of a target string; falls back to the raw string."""
    target = target.strip()
    if not target:
        return ""
    parsed = urlparse(target if "://" in target else f"http://{target}")
    host = (parsed.netloc or parsed.path or target).split("@")[-1]
    # strip userinfo, port and trailing slash
    host = host.split(":")[0].rstrip("/")
    return host or target


@router.get("/websites")
async def list_websites(request: Request) -> list[dict[str, object]]:
    store = request.app.state.store
    worker = request.app.state.worker
    reports_dir: Path = request.app.state.settings.reports_dir

    by_host: dict[str, dict[str, object]] = {}
    for job in store.list():
        target = _target_of(job)
        host = _host_of(target) or job.scan_id
        summary: dict[str, object] = {}
        if job.status == ScanStatus.COMPLETED:
            report = worker.result(job.scan_id)
            if report is None:
                report = load_disk_report_or_none(reports_dir, job.scan_id)
            if report is not None:
                summary = report.get("summary", {})

        prev = by_host.get(host)
        if prev is None or (job.created_at or "") > (prev.get("created_at") or ""):
            by_host[host] = {
                "host": host,
                "target": target,
                "mode": job.request.mode,
                "scan_id": job.scan_id,
                "status": job.status.value,
                "created_at": job.created_at,
                "finished_at": job.finished_at,
                "summary": summary,
                "scan_count": (int(prev["scan_count"]) if prev else 0) + 1,
            }
        else:
            prev["scan_count"] = int(prev["scan_count"]) + 1  # type: ignore[assignment]

    # newest first; unknown/missing timestamps sink to the bottom
    return sorted(
        by_host.values(),
        key=lambda w: w.get("created_at") or "",
        reverse=True,
    )
