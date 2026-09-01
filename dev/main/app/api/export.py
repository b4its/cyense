"""Export endpoints — CSV and PDF downloads (enhanced-reporting-viewer.md §3.2, §3.3).

The PDF path imports ``reportlab`` lazily inside the handler so a missing
optional dependency degrades into a clear 503 instead of breaking service
startup.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import PlainTextResponse, Response

from app.report.csv_export import export_csv
from app.report.cvss import enrich_finding

router = APIRouter(tags=["export"])


def _load_report(request: Request, scan_id: str) -> dict[str, Any]:
    """In-memory worker result first; disk fallback after service restart."""
    report: dict[str, Any] | None = request.app.state.worker.result(scan_id)
    if report is not None:
        return report

    reports_dir: Path = request.app.state.settings.reports_dir
    path = (reports_dir / scan_id / "report.json").resolve()
    # Path traversal guard: resolved report must live inside reports_dir.
    try:
        path.relative_to(reports_dir.resolve())
    except ValueError:
        raise HTTPException(status_code=403, detail="invalid scan_id") from None

    if path.exists():
        try:
            return json.loads(path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise HTTPException(status_code=500, detail=f"corrupt report on disk: {exc}") from exc

    raise HTTPException(
        status_code=404,
        detail="report not available (scan pending, failed, or unknown id)",
    )


@router.get("/scans/{scan_id}/export/csv")
async def export_csv_endpoint(
    scan_id: str,
    request: Request,
    include_remediation: bool = True,
) -> PlainTextResponse:
    """Download findings as CSV (UTF-8 BOM for Excel)."""
    report = _load_report(request, scan_id)
    findings = report.get("findings", [])

    if not findings:
        raise HTTPException(status_code=404, detail="no findings to export")

    csv_text = export_csv(findings, include_remediation=include_remediation)
    return PlainTextResponse(
        content=csv_text,
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="cyense-{scan_id}-findings.csv"',
        },
    )


@router.get("/scans/{scan_id}/export/pdf")
async def export_pdf_endpoint(scan_id: str, request: Request) -> Response:
    """Download a compliance-ready PDF report (requires reportlab)."""
    try:
        from reportlab import __version__ as _reportlab_version  # noqa: F401
    except ImportError:
        raise HTTPException(
            status_code=503,
            detail="PDF export unavailable: reportlab is not installed "
            "(pip install reportlab>=4.0)",
        ) from None

    report = _load_report(request, scan_id)
    findings = report.get("findings", [])
    summary = report.get("summary", {})

    if not findings:
        raise HTTPException(status_code=404, detail="no findings to export")

    # Re-enrich after disk load (see csv endpoint above).
    for f in findings:
        enrich_finding(f)

    from app.report.pdf_report import generate_pdf_report

    try:
        pdf_bytes = generate_pdf_report(findings, summary, scan_id)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {exc}") from exc

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="cyense-{scan_id}-report.pdf"',
        },
    )
