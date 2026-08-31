"""Web viewer endpoints — local dashboard for scan results (enhanced-reporting-viewer.md §3.1).

Serves a dependency-free static dashboard (vanilla JS, no build step) plus a
JSON data endpoint that prefers the in-memory worker result and falls back to
the on-disk ``reports/<scan_id>/report.json`` after a service restart.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse

router = APIRouter(prefix="/viewer", tags=["viewer"])

_STATIC_DIR = Path(__file__).resolve().parents[1] / "interface" / "viewer" / "static"


def _load_report_from_disk(scan_id: str, request: Request) -> dict[str, Any] | None:
    """Read reports/<scan_id>/report.json (worker._dump_report fallback)."""
    reports_dir: Path = request.app.state.settings.reports_dir
    path = (reports_dir / scan_id / "report.json").resolve()
    # Path traversal guard even though get_scan_data validates store membership.
    try:
        path.relative_to(reports_dir.resolve())
    except ValueError:
        return None
    try:
        if path.exists():
            return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    return None


# NOTE: static route is registered *before* /{scan_id} so "/viewer/static/..."
# can never be captured by the scan_id path parameter.
@router.get("/static/{file_path:path}")
async def serve_static(file_path: str) -> FileResponse:
    """Serve viewer static assets with a traversal guard."""
    static_path = (_STATIC_DIR / file_path).resolve()

    try:
        static_path.relative_to(_STATIC_DIR.resolve())
    except ValueError:
        raise HTTPException(status_code=403, detail="Access denied") from None

    if not static_path.is_file():
        raise HTTPException(status_code=404, detail=f"Static file not found: {file_path}")

    return FileResponse(path=static_path)


@router.get("/{scan_id}", response_class=HTMLResponse)
async def serve_viewer(scan_id: str, request: Request) -> HTMLResponse:
    """Serve the dashboard shell for a scan (scan_id injected as meta tag).

    Falls back to on-disk ``reports/<scan_id>/report.json`` when the scan
    is no longer in the in-memory store (e.g. after service restart), so
    the dashboard can still be opened for historical scans.
    """
    store = request.app.state.store
    in_memory = store.get(scan_id) is not None
    on_disk = (request.app.state.settings.reports_dir / scan_id / "report.json").is_file()
    if not in_memory and not on_disk:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    index_path = _STATIC_DIR / "index.html"
    if not index_path.exists():
        raise HTTPException(status_code=500, detail="Viewer files not found")

    html = index_path.read_text(encoding="utf-8")
    html = html.replace(
        "<title>Cyense Scan Results</title>",
        f"<title>Cyense Scan: {scan_id}</title>",
    )
    html = html.replace("</head>", f'<meta name="scan-id" content="{scan_id}"></head>')
    # Rewrite relative static asset paths (href="static/..." / src="static/...")
    # to absolute /api/v1/viewer/static/... so the browser resolves them
    # correctly regardless of the current URL depth. Without this rewrite,
    # requests like /api/v1/viewer/{scan_id}/static/app.js would 404 because
    # the static-file route lives at /api/v1/viewer/static/{file_path}.
    viewer_prefix = request.scope.get("root_path", "") + "/api/v1/viewer/static/"
    html = html.replace('href="static/', f'href="{viewer_prefix}')
    html = html.replace('src="static/', f'src="{viewer_prefix}')
    return HTMLResponse(content=html, status_code=200)


@router.get("/{scan_id}/data")
async def get_scan_data(scan_id: str, request: Request) -> dict[str, Any]:
    """JSON data feed for the dashboard (worker result, disk fallback).

    Returns in-memory scan data when available, otherwise falls back to
    on-disk ``reports/<scan_id>/report.json`` for historical scans that
    survived a service restart. Returns 404 only when neither source
    knows the scan.
    """
    store = request.app.state.store
    job = store.get(scan_id)
    reports_dir: Path = request.app.state.settings.reports_dir
    disk_report_path = reports_dir / scan_id / "report.json"

    if job is None and not disk_report_path.is_file():
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    status = job.status.value if job is not None and job.status else "completed"
    created_at = job.created_at if job is not None else None
    finished_at = job.finished_at if job is not None else None
    error = job.error if job is not None else None

    report: dict[str, Any] | None = None
    source = "unknown"
    if job is not None:
        report = request.app.state.worker.result(scan_id)
        if report is not None:
            source = "memory"
    if report is None:
        report = _load_report_from_disk(scan_id, request)
        if report is not None:
            source = "disk"

    if report is None:
        return {
            "scan_id": scan_id,
            "status": status,
            "created_at": created_at,
            "completed_at": finished_at,
            "error": error,
            "summary": {},
            "findings": [],
            "source": source,
            "message": "Report not available yet (scan pending, running, or failed).",
        }

    return {
        "scan_id": scan_id,
        "status": status,
        "created_at": created_at,
        "completed_at": finished_at,
        "error": error,
        "summary": report.get("summary", {}),
        "findings": report.get("findings", []),
        "meta": report.get("meta", {}),
        "source": source,
    }
