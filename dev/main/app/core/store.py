"""In-memory job store with JSON dump to volume (PRD v2.0 §5.3).

MVP keeps everything in memory and mirrors it to ``reports_dir/store.json``
so a service restart can still list previous jobs (dump is best-effort).
"""

from __future__ import annotations

import json
import threading
import time
import uuid
from pathlib import Path

from app.core.models import ScanJob, ScanRequest, ScanStatus


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class JobStore:
    def __init__(self, reports_dir: Path) -> None:
        self._jobs: dict[str, ScanJob] = {}
        self._reports_dir = Path(reports_dir)
        self._reports_dir.mkdir(parents=True, exist_ok=True)
        self._events: dict[str, list[str]] = {}
        self._lock = threading.Lock()  # single lock for all access
        self._load()

    # -- lifecycle ----------------------------------------------------------

    def _load(self) -> None:
        """Restore persisted jobs/events from ``store.json`` on startup.

        Without this the dump in :meth:`_dump` was write-only: after a
        service restart the scan library (and the saved scanned-websites
        list) came back empty even though ``reports/<id>/report.json`` files
        still existed. Best-effort — a missing/corrupt dump yields an empty
        store instead of crashing startup.
        """
        path = self._reports_dir / "store.json"
        if not path.exists():
            return
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        if not isinstance(data, dict):
            return
        for raw in data.get("jobs") or []:
            try:
                job = ScanJob.model_validate(raw)
            except Exception:
                continue  # tolerate schema drift / partial dumps
            if job.scan_id not in self._jobs:
                self._jobs[job.scan_id] = job
        # Non-terminal jobs (QUEUED/RUNNING) cannot be re-enqueued after a
        # restart — the worker's asyncio queue is empty and the checkpoint
        # (if any) is gone. Mark them FAILED so the scan library shows an
        # accurate terminal state rather than perpetual "queued"/"running".
        stale = [
            sid
            for sid, j in self._jobs.items()
            if j.status in (ScanStatus.QUEUED, ScanStatus.RUNNING)
        ]
        stale_now = _now()
        for sid in stale:
            j = self._jobs[sid]
            j.status = ScanStatus.FAILED
            j.stage = None
            j.error = "scan lost during service restart — resubmit if needed"
            j.finished_at = stale_now
            self._events.setdefault(sid, []).append(
                f"{stale_now} status: failed — lost during restart"
            )
        events = data.get("events")
        if isinstance(events, dict):
            for scan_id, evs in events.items():
                if isinstance(evs, list):
                    self._events[scan_id] = [str(e) for e in evs]

    def create(self, request: ScanRequest) -> ScanJob:
        scan_id = uuid.uuid4().hex[:12]
        job = ScanJob(scan_id=scan_id, request=request, created_at=_now())
        with self._lock:
            self._jobs[scan_id] = job
            self._events[scan_id] = []
        self._dump()
        return job

    def get(self, scan_id: str) -> ScanJob | None:
        return self._jobs.get(scan_id)

    def list(self) -> list[ScanJob]:
        return sorted(self._jobs.values(), key=lambda j: j.created_at, reverse=True)

    def delete(self, scan_id: str) -> bool:
        with self._lock:
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
        with self._lock:
            job = self._jobs.get(scan_id)
            if job is None:
                return
            job.status = ScanStatus.RUNNING
            job.stage = stage
        self._dump()

    async def mark_stage(self, scan_id: str, stage: str, progress: int) -> None:
        with self._lock:
            job = self._jobs.get(scan_id)
            if job is None:
                return
            # Persist previous stage transitions as events so the web UI can
            # render a LIVE step-by-step feed (previously mark_stage silently
            # updated state but recorded nothing, so no per-stage history was
            # ever visible to the reviewer).
            if job.stage and job.stage != stage:
                self._events.setdefault(scan_id, []).append(
                    f"{_now()} stage: {job.stage} → {stage} ({job.progress}%)"
                )
            elif not job.stage:
                self._events.setdefault(scan_id, []).append(
                    f"{_now()} stage: {stage} ({progress}%)"
                )
            job.stage = stage
            job.progress = max(job.progress, progress)
        self._dump()

    async def mark_completed(self, scan_id: str) -> None:
        with self._lock:
            job = self._jobs.get(scan_id)
            if job is None:
                return
            job.status = ScanStatus.COMPLETED
            job.stage = None
            job.progress = 100
            job.finished_at = _now()
            self._events.setdefault(scan_id, []).append(
                f"{_now()} status: completed (100%)"
            )
        self._dump()

    async def mark_failed(self, scan_id: str, error: str) -> None:
        with self._lock:
            job = self._jobs.get(scan_id)
            if job is None:
                return
            job.status = ScanStatus.FAILED
            job.stage = None
            job.error = error
            job.finished_at = _now()
            self._events.setdefault(scan_id, []).append(
                f"{_now()} status: failed — {error}"
            )
        self._dump()

    # -- log events (shown via GET /scans/{id}) -----------------------------

    async def log(self, scan_id: str, message: str) -> None:
        with self._lock:
            self._events.setdefault(scan_id, []).append(f"{_now()} {message}")

    def events(self, scan_id: str) -> list[str]:
        return list(self._events.get(scan_id, []))

    # -- persistence ---------------------------------------------------------

    def _dump(self) -> None:
        import os
        import tempfile

        from app.utils.redact import redact_headers

        try:
            jobs = []
            for j in self.list():
                data = j.model_dump(mode="json")
                req = data.get("request") or {}
                # NEVER persist raw credentials: mask token-like fields and
                # redact sensitive headers/cookies before writing to disk.
                for key in ("github_token", "token", "password", "secret",
                            "api_key", "apikey"):
                    if req.get(key):
                        req[key] = "[REDACTED]"
                if isinstance(req.get("headers"), dict):
                    req["headers"] = redact_headers(req["headers"])
                if isinstance(req.get("cookies"), dict):
                    req["cookies"] = {k: "[REDACTED]" for k in req["cookies"]}
                data["request"] = req
                jobs.append(data)
            payload = {
                "jobs": jobs,
                "events": self._events,
            }
            # Atomic + 0o600 (file may hold request metadata).
            fd, tmp_name = tempfile.mkstemp(
                dir=str(self._reports_dir), prefix=".store-", suffix=".tmp",
            )
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    json.dump(payload, fh, indent=2)
                os.chmod(tmp_name, 0o600)
                os.replace(tmp_name, self._reports_dir / "store.json")
            except BaseException:
                try:
                    os.unlink(tmp_name)
                except OSError:
                    pass
                raise
        except OSError:
            pass  # best effort
