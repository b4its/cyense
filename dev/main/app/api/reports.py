"""Report endpoints: JSON report and self-contained HTML report (PRD §4.4)."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse

from app.report.html_report import render_html_report

router = APIRouter(tags=["reports"])


def _get_report(request: Request, scan_id: str) -> dict[str, object]:
    report = request.app.state.worker.result(scan_id)
    if report is None:
        raise HTTPException(
            status_code=404,
            detail="report not available (scan pending, failed, or unknown id)",
        )
    return report


@router.get("/scans/{scan_id}/report")
async def report_json(request: Request, scan_id: str) -> dict[str, object]:
    return _get_report(request, scan_id)


@router.get("/scans/{scan_id}/report/html", response_class=HTMLResponse)
async def report_html(request: Request, scan_id: str) -> HTMLResponse:
    report = _get_report(request, scan_id)
    return HTMLResponse(content=render_html_report(report), media_type="text/html")
