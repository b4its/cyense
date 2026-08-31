"""Scan Resume — checkpoint serialization for interrupted scans.

Adopts the Strix pattern (usestrix/strix runner.py): save scan state at each
stage transition so an interrupted scan can resume from the last checkpoint
instead of starting over.

Cyense adaptation (no-LLM, deterministic):
  * Checkpoint is a JSON file at ``reports/{scan_id}/checkpoint.json``
  * Contains: scan_id, request dict, current stage, progress, partial findings
  * On resume: load checkpoint, continue from last stage
  * Atomic writes (temp + os.replace) following Strix secret_files discipline

Ref: enhanced-reporting-viewer.md §3.7 (deferred → now implemented)
"""

from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any

from app.utils.logger import get_logger

log = get_logger("scan_resume")

_CHECKPOINT_FILE = "checkpoint.json"
_CHECKPOINT_VERSION = 1


def _checkpoint_path(reports_dir: Path, scan_id: str) -> Path:
    return reports_dir / scan_id / _CHECKPOINT_FILE


def save_checkpoint(
    reports_dir: Path,
    scan_id: str,
    *,
    request_dict: dict[str, Any],
    stage: str | None,
    progress: int,
    findings_so_far: list[dict[str, Any]] | None = None,
    error: str | None = None,
    extra: dict[str, Any] | None = None,
) -> None:
    """Atomically write checkpoint for a scan.

    Called by the worker at each stage transition so an interrupted scan
    can resume from the last known point.
    """
    dest = _checkpoint_path(reports_dir, scan_id)
    dest.parent.mkdir(parents=True, exist_ok=True)

    payload: dict[str, Any] = {
        "version": _CHECKPOINT_VERSION,
        "scan_id": scan_id,
        "request": request_dict,
        "stage": stage,
        "progress": progress,
        "findings": findings_so_far or [],
        "error": error,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    if extra:
        payload["extra"] = extra

    # Atomic write: temp file in same dir + os.replace
    fd, tmp_path = tempfile.mkstemp(
        suffix=".tmp", prefix=".checkpoint_", dir=str(dest.parent),
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, sort_keys=True)
        os.replace(tmp_path, str(dest))
    except Exception:
        # Clean up temp file on failure
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        log.warning("failed to save checkpoint for %s", scan_id)


def load_checkpoint(reports_dir: Path, scan_id: str) -> dict[str, Any] | None:
    """Load checkpoint for a scan, or None if not found / unreadable."""
    path = _checkpoint_path(reports_dir, scan_id)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("version") != _CHECKPOINT_VERSION:
            log.warning(
                "checkpoint version mismatch for %s (got %s, expected %s)",
                scan_id, data.get("version"), _CHECKPOINT_VERSION,
            )
        return data
    except (json.JSONDecodeError, OSError) as exc:
        log.warning("failed to load checkpoint for %s: %s", scan_id, exc)
        return None


def remove_checkpoint(reports_dir: Path, scan_id: str) -> None:
    """Remove checkpoint after successful scan completion."""
    path = _checkpoint_path(reports_dir, scan_id)
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass


def list_resumable_scans(reports_dir: Path) -> list[dict[str, Any]]:
    """List all scans that have checkpoints and can be resumed."""
    results: list[dict[str, Any]] = []
    reports_dir = Path(reports_dir)
    if not reports_dir.exists():
        return results

    for scan_dir in sorted(reports_dir.iterdir()):
        if not scan_dir.is_dir():
            continue
        cp = scan_dir / _CHECKPOINT_FILE
        if not cp.exists():
            continue
        try:
            data = json.loads(cp.read_text(encoding="utf-8"))
            results.append({
                "scan_id": data.get("scan_id", scan_dir.name),
                "stage": data.get("stage"),
                "progress": data.get("progress", 0),
                "timestamp": data.get("timestamp", ""),
                "mode": data.get("request", {}).get("mode", "unknown"),
                "findings_count": len(data.get("findings", [])),
                "error": data.get("error"),
            })
        except (json.JSONDecodeError, OSError):
            continue

    # Sort by timestamp descending (most recent first)
    results.sort(key=lambda r: r.get("timestamp", ""), reverse=True)
    return results


def is_resumable(reports_dir: Path, scan_id: str) -> bool:
    """Check if a scan has a checkpoint that can be resumed."""
    cp = load_checkpoint(reports_dir, scan_id)
    if cp is None:
        return False
    # A completed scan's checkpoint should have been removed; if it exists
    # with a terminal stage, it's not resumable
    stage = cp.get("stage")
    if stage is None:
        return False
    return True
