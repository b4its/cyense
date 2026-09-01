"""Report endpoints: JSON report and self-contained HTML report (PRD §4.4).

Also serves SARIF and coverage artifacts (ci-compliance-reporting.md §3.7).
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

from app.api._disk_utils import load_disk_report
from app.report.coverage import build_coverage_document, scope_info_from_report
from app.report.html_report import render_html_report
from app.report.sarif import build_sarif_report

router = APIRouter(tags=["reports"])


def _get_report(request: Request, scan_id: str) -> dict[str, object]:
    report = request.app.state.worker.result(scan_id)
    if report is not None:
        return report

    # Disk fallback after service restart — consistent with export/viewer.
    reports_dir: Path = request.app.state.settings.reports_dir
    if (reports_dir / scan_id / "report.json").is_file():
        return load_disk_report(reports_dir, scan_id)

    raise HTTPException(
        status_code=404,
        detail="report not available (scan pending, failed, or unknown id)",
    )


@router.get("/scans/{scan_id}/report")
async def report_json(request: Request, scan_id: str) -> dict[str, object]:
    return _get_report(request, scan_id)


@router.get("/scans/{scan_id}/report/html", response_class=HTMLResponse)
async def report_html(request: Request, scan_id: str) -> HTMLResponse:
    report = _get_report(request, scan_id)
    return HTMLResponse(content=render_html_report(report), media_type="text/html")


@router.get("/scans/{scan_id}/report/sarif")
async def report_sarif(request: Request, scan_id: str) -> JSONResponse:
    """Get SARIF 2.1.0 report for GitHub Code Scanning (ci-compliance-reporting.md §3.2)."""
    report = _get_report(request, scan_id)
    findings = report.get("findings", [])
    sarif_report = build_sarif_report(report, findings)
    return JSONResponse(
        content=sarif_report,
        media_type="application/sarif+json"
    )


@router.get("/scans/{scan_id}/coverage")
async def coverage_json(request: Request, scan_id: str) -> JSONResponse:
    """Get coverage document showing what was checked (ci-compliance-reporting.md §3.5)."""
    report = _get_report(request, scan_id)
    coverage_doc = build_coverage_document(report, scope_info_from_report(report))
    return JSONResponse(content=coverage_doc)
