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
    path = reports_dir / scan_id / "report.json"
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
    """Serve the dashboard shell for a scan (scan_id injected as meta tag)."""
    store = request.app.state.store
    if store.get(scan_id) is None:
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
    return HTMLResponse(content=html, status_code=200)


@router.get("/{scan_id}/data")
async def get_scan_data(scan_id: str, request: Request) -> dict[str, Any]:
    """JSON data feed for the dashboard (worker result, disk fallback)."""
    store = request.app.state.store
    job = store.get(scan_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    status = job.status.value if job.status else "unknown"

    report: dict[str, Any] | None = request.app.state.worker.result(scan_id)
    source = "memory"
    if report is None:
        report = _load_report_from_disk(scan_id, request)
        source = "disk"

    if report is None:
        return {
            "scan_id": scan_id,
            "status": status,
            "created_at": job.created_at,
            "completed_at": job.finished_at,
            "error": job.error,
            "summary": {},
            "findings": [],
            "source": source,
            "message": "Report not available yet (scan pending, running, or failed).",
        }

    return {
        "scan_id": scan_id,
        "status": status,
        "created_at": job.created_at,
        "completed_at": job.finished_at,
        "error": job.error,
        "summary": report.get("summary", {}),
        "findings": report.get("findings", []),
        "meta": report.get("meta", {}),
        "source": source,
    }
