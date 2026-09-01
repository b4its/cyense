"""Svelte web UI — serves the built SPA (app/interface/svelte/dist).

The UI adapts the full CLI feature set into a browser dashboard: scan
library, scan detail with pipeline graph + sticky TOC, rule catalog, and
CVE/technology/port views — all via the existing /api/v1 endpoints.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

router = APIRouter(prefix="/ui", tags=["ui"])

# Built Svelte SPA output directory (created by `npm run build` in
# app/interface/svelte). When absent, endpoints return 503 so the API keeps
# running without the frontend.
_UI_DIST = Path(__file__).resolve().parents[1] / "interface" / "svelte" / "dist"
_INDEX = _UI_DIST / "index.html"


@router.get("", include_in_schema=False)
@router.get("/", include_in_schema=False)
async def ui_index() -> FileResponse:
    if not _INDEX.exists():
        raise HTTPException(
            status_code=503,
            detail=(
                "Web UI belum dibuild — jalankan: "
                "cd app/interface/svelte && npm install && npm run build"
            ),
        )
    return FileResponse(_INDEX, media_type="text/html")


@router.get("/assets/{file_path:path}", include_in_schema=False)
async def ui_assets(file_path: str) -> FileResponse:
    asset = (_UI_DIST / "assets" / file_path).resolve()
    try:
        asset.relative_to((_UI_DIST / "assets").resolve())
    except ValueError:
        raise HTTPException(status_code=403, detail="Access denied") from None
    if not asset.is_file():
        raise HTTPException(status_code=404, detail="asset not found")
    return FileResponse(asset)


# SPA fallback — hash routing means deep paths are client-side, but serve
# index.html for any /ui/* path so direct loads (and future path routing)
# work.
@router.get("/{path:path}", include_in_schema=False)
async def ui_fallback(path: str) -> FileResponse:
    if not _INDEX.exists():
        raise HTTPException(
            status_code=503,
            detail=(
                "Web UI belum dibuild — jalankan: "
                "cd app/interface/svelte && npm install && npm run build"
            ),
        )
    return FileResponse(_INDEX, media_type="text/html")
