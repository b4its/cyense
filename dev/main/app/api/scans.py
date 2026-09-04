"""Scan endpoints: submit (POST), list, detail, delete, resume.

POST /scans enforces the `i_have_permission` gate at the model level
(422 when absent — PRD §4.1/§4.2) and returns 202 + scan_id.
GET /scans/resumable — list scans with checkpoints available for resume.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from app.api._disk_utils import load_disk_report_or_none
from app.core.models import ScanRequest, ScanStatus
from app.services.scan_resume import list_resumable_scans

router = APIRouter(tags=["scans"])


@router.post("/scans", status_code=202)
async def submit_scan(request: Request, scan_request: ScanRequest) -> dict[str, str]:
    store = request.app.state.store
    job = store.create(scan_request)
    request.app.state.worker.enqueue(job)
    return {"scan_id": job.scan_id, "status": job.status.value}


@router.get("/scans/resumable")
async def list_resumable(request: Request) -> list[dict[str, object]]:
    """List scans with checkpoints available for --resume (Strix pattern)."""
    return list_resumable_scans(request.app.state.settings.reports_dir)


@router.get("/scans")
async def list_scans(request: Request) -> list[dict[str, object]]:
    store = request.app.state.store
    worker = request.app.state.worker
    reports_dir = request.app.state.settings.reports_dir
    out: list[dict[str, object]] = []
    for job in store.list():
        item: dict[str, object] = {
            "scan_id": job.scan_id,
            "status": job.status.value,
            "stage": job.stage,
            "progress": job.progress,
            "mode": job.request.mode,
            "created_at": job.created_at,
            "finished_at": job.finished_at,
        }
        # Include summary for completed scans so the web UI / dashboard can
        # show severity counts, CVE matched, and open ports per scan card.
        # After a restart the in-memory cache is empty — fall back to the
        # persisted report.json so saved results remain visible.
        if job.status == ScanStatus.COMPLETED:
            report = worker.result(job.scan_id)
            if report is None:
                report = load_disk_report_or_none(reports_dir, job.scan_id)
            if report is not None:
                item["summary"] = report.get("summary", {})
        out.append(item)
    return out


@router.get("/scans/{scan_id}")
async def get_scan(request: Request, scan_id: str) -> dict[str, object]:
    store = request.app.state.store
    job = store.get(scan_id)
    if job is None:
        raise HTTPException(status_code=404, detail="scan not found")
    payload: dict[str, object] = {
        "scan_id": job.scan_id,
        "status": job.status.value,
        "stage": job.stage,
        "progress": job.progress,
        "mode": job.request.mode,
        "created_at": job.created_at,
        "finished_at": job.finished_at,
        "error": job.error,
        "events": store.events(scan_id),
    }
    if job.status == ScanStatus.COMPLETED:
        report = request.app.state.worker.result(scan_id)
        if report is None:
            # Disk fallback so a completed scan's summary survives a restart,
            # consistent with list_scans (which loads from disk).
            report = load_disk_report_or_none(
                request.app.state.settings.reports_dir, scan_id,
            )
        if report is not None:
            payload["summary"] = report.get("summary", {})
    return payload


@router.delete("/scans/{scan_id}", status_code=204)
async def delete_scan(request: Request, scan_id: str) -> None:
    # Defense-in-depth: reject traversal/root scan_ids up-front. The worker
    # also refuses to resolve "." to the reports root, but failing fast here
    # keeps a raw path like "."/".." from ever reaching store/worker logic.
    if ".." in scan_id or "/" in scan_id or scan_id in (".", ""):
        raise HTTPException(status_code=403, detail="invalid scan_id")
    deleted = request.app.state.store.delete(scan_id)
    # also drop any computed report and its on-disk artifacts
    request.app.state.worker.discard(scan_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="scan not found")
