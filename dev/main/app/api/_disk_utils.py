"""Shared disk-report loading helpers for API endpoints.

All report endpoints fall back to ``reports/<scan_id>/report.json`` after a
service restart. These helpers centralize:
  * path-traversal containment checks,
  * scan_id ".."/"/" rejection,
  * JSON parsing with type validation (a valid-JSON-but-non-dict file must
    not crash downstream ``report.get(...)`` calls).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import HTTPException


def _reject_traversal(scan_id: str, reports_dir: Path) -> Path:
    """Resolve the on-disk report path with traversal guards.

    Raises 403 for scan_ids containing ``..`` or ``/`` or escaping
    reports_dir.
    """
    if ".." in scan_id or "/" in scan_id:
        raise HTTPException(status_code=403, detail="invalid scan_id")
    path = (reports_dir / scan_id / "report.json").resolve()
    try:
        path.relative_to(reports_dir.resolve())
    except ValueError:
        raise HTTPException(status_code=403, detail="invalid scan_id") from None
    return path


def load_disk_report(reports_dir: Path, scan_id: str) -> dict[str, Any]:
    """Load and validate a report.json; raise HTTPException on any problem."""
    path = _reject_traversal(scan_id, reports_dir)
    if not path.exists():
        raise HTTPException(status_code=404, detail="report not found on disk")
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise HTTPException(
            status_code=500, detail=f"corrupt report on disk: {exc}"
        ) from exc
    if not isinstance(data, dict):
        raise HTTPException(
            status_code=500, detail="corrupt report on disk: expected JSON object"
        )
    return data


def load_disk_report_or_none(
    reports_dir: Path, scan_id: str,
) -> dict[str, Any] | None:
    """Like :func:`load_disk_report` but returns None instead of raising for
    missing files / invalid scan_id (used by viewer data feeds)."""
    try:
        return load_disk_report(reports_dir, scan_id)
    except HTTPException:
        return None
