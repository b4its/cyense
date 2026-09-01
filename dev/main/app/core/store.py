"""In-memory job store with JSON dump to volume (PRD v2.0 §5.3).

MVP keeps everything in memory and mirrors it to ``reports_dir/store.json``
so a service restart can still list previous jobs (dump is best-effort).
"""

from __future__ import annotations

import asyncio
import json
import threading
import time
import uuid
from pathlib import Path

from app.core.models import ScanJob, ScanRequest, ScanStatus

_LOCK = threading.Lock()


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class JobStore:
    def __init__(self, reports_dir: Path) -> None:
        self._jobs: dict[str, ScanJob] = {}
        self._reports_dir = Path(reports_dir)
        self._reports_dir.mkdir(parents=True, exist_ok=True)
        self._events: dict[str, list[str]] = {}
        self._lock = asyncio.Lock()

    # -- lifecycle ----------------------------------------------------------

    def create(self, request: ScanRequest) -> ScanJob:
        scan_id = uuid.uuid4().hex[:12]
        job = ScanJob(scan_id=scan_id, request=request, created_at=_now())
        with _LOCK:
            self._jobs[scan_id] = job
            self._events[scan_id] = []
        self._dump()
        return job

    def get(self, scan_id: str) -> ScanJob | None:
        return self._jobs.get(scan_id)

    def list(self) -> list[ScanJob]:
        return sorted(self._jobs.values(), key=lambda j: j.created_at, reverse=True)

    def delete(self, scan_id: str) -> bool:
        with _LOCK:
            existed = self._jobs.pop(scan_id, None) is not None
            self._events.pop(scan_id, None)
        self._dump()
        return existed

    # -- state machine (PRD §4.3: QUEUED -> RUNNING -> COMPLETED|FAILED) ----
    #
    # All state transitions are defensive: if the job was deleted mid-scan
    # (DELETE /scans/{id} while RUNNING), the transition is a no-op instead
    # of raising KeyError. Without this, a failing scan whose job vanished
    # would crash the worker loop (`_loop`'s except handler calls
    # mark_failed again → second KeyError kills the task permanently and
    # every future scan stays queued forever).

    async def mark_running(self, scan_id: str, stage: str) -> None:
        async with self._lock:
            job = self._jobs.get(scan_id)
            if job is None:
                return
            job.status = ScanStatus.RUNNING
            job.stage = stage
        self._dump()

    async def mark_stage(self, scan_id: str, stage: str, progress: int) -> None:
        async with self._lock:
            job = self._jobs.get(scan_id)
            if job is None:
                return
            job.stage = stage
            job.progress = max(job.progress, progress)
        self._dump()

    async def mark_completed(self, scan_id: str) -> None:
        async with self._lock:
            job = self._jobs.get(scan_id)
            if job is None:
                return
            job.status = ScanStatus.COMPLETED
            job.stage = None
            job.progress = 100
            job.finished_at = _now()
        self._dump()

    async def mark_failed(self, scan_id: str, error: str) -> None:
        async with self._lock:
            job = self._jobs.get(scan_id)
            if job is None:
                return
            job.status = ScanStatus.FAILED
            job.stage = None
            job.error = error
            job.finished_at = _now()
        self._dump()

    # -- log events (shown via GET /scans/{id}) -----------------------------

    async def log(self, scan_id: str, message: str) -> None:
        async with self._lock:
            self._events.setdefault(scan_id, []).append(f"{_now()} {message}")

    def events(self, scan_id: str) -> list[str]:
        return list(self._events.get(scan_id, []))

    # -- persistence ---------------------------------------------------------

    def _dump(self) -> None:
        try:
            payload = {
                "jobs": [j.model_dump(mode="json") for j in self.list()],
                "events": self._events,
            }
            (self._reports_dir / "store.json").write_text(json.dumps(payload, indent=2))
        except OSError:
            pass  # best effort
