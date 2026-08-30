"""Background scan worker — asyncio queue (PRD v2.0 §5.4 design decision).

Keeps the API responsive: POST /scans only enqueues; the worker drains the
queue and updates the job store state machine.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from app.core.models import ScanJob
from app.core.store import JobStore
from app.engines.link_engine import run_link_scan
from app.engines.program_engine import resolve_source_dir, run_program_scan
from app.utils.logger import get_logger

log = get_logger("worker")


class ScanWorker:
    def __init__(self, store: JobStore, brain: Any, settings: Any) -> None:
        self.store = store
        self.brain = brain
        self.settings = settings
        self.queue: asyncio.Queue[str] = asyncio.Queue()
        self._task: asyncio.Task[None] | None = None
        self._results: dict[str, dict[str, Any]] = {}

    # -- lifecycle -------------------------------------------------------------

    def start(self) -> None:
        self._task = asyncio.get_running_loop().create_task(self._loop())

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    def enqueue(self, job: ScanJob) -> None:
        self.queue.put_nowait(job.scan_id)

    # -- main loop ---------------------------------------------------------------

    async def _loop(self) -> None:
        while True:
            scan_id = await self.queue.get()
            try:
                await self._process(scan_id)
            except Exception as exc:  # robustness: never crash the worker
                log.exception("scan %s crashed", scan_id)
                await self.store.mark_failed(scan_id, str(exc))
            finally:
                self.queue.task_done()

    async def _process(self, scan_id: str) -> None:
        job = self.store.get(scan_id)
        if job is None:
            return
        request = job.request
        request_dict = (
            request.model_dump(mode="json")
            if hasattr(request, "model_dump")
            else dict(request)
        )

        await self.store.mark_running(scan_id, stage="recon")
        started = time.monotonic()

        async def on_stage(stage: str) -> None:
            progress = {"recon": 25, "probe": 50, "verify": 75, "report": 90}.get(stage, 0)
            await self.store.mark_stage(scan_id, stage, progress)

        try:
            if request_dict["mode"] == "link":
                report = await run_link_scan(
                    scan_id=scan_id,
                    request_dict=request_dict,
                    brain=self.brain,
                    reports_dir=str(self.settings.reports_dir),
                    settings=self.settings,
                    on_stage=on_stage,
                )
            else:
                await self.store.mark_stage(scan_id, "recon", 25)
                source_dir = resolve_source_dir(
                    request_dict.get("source_type", "mounted"),
                    str(self.settings.workspace_dir),
                )
                await self.store.mark_stage(scan_id, "probe", 50)
                result = run_program_scan(
                    lang=request_dict.get("lang", "python"),
                    source_dir=source_dir,
                    scan_id=scan_id,
                )
                await self.store.mark_stage(scan_id, "report", 80)
                report = self._program_report(scan_id, result, started)

            self._results[scan_id] = report
            self._dump_report(scan_id, report)
            if report.get("meta", {}).get("error"):
                # recon-level controlled failure (e.g. no placeholder found):
                # surface as FAILED, not silently completed-empty
                await self.store.mark_failed(scan_id, report["meta"]["error"])
            else:
                await self.store.mark_completed(scan_id)
        except Exception as exc:
            await self.store.mark_failed(scan_id, str(exc))
            raise

    # -- helpers -----------------------------------------------------------------

    @staticmethod
    def _program_report(scan_id: str, result: dict[str, Any], started: float) -> dict[str, Any]:
        finding_models = result["findings"]
        findings = [
            f.model_dump(mode="json") if hasattr(f, "model_dump") else f
            for f in finding_models
        ]
        summary = {
            "critical": sum(1 for f in findings if f["severity"] == "critical"),
            "high": sum(1 for f in findings if f["severity"] == "high"),
            "medium": sum(1 for f in findings if f["severity"] == "medium"),
            "low": sum(1 for f in findings if f["severity"] == "low"),
            "info": sum(1 for f in findings if f["severity"] == "info"),
            "total": len(findings),
            "files_scanned": result["files_scanned"],
            "duration_ms": int((time.monotonic() - started) * 1000),
        }
        return {
            "meta": {"scan_id": scan_id, "mode": "program", "engine": "static-ast"},
            "summary": summary,
            "findings": findings,
        }

    def _dump_report(self, scan_id: str, report: dict[str, Any]) -> None:
        import json

        try:
            out_dir = self.settings.reports_dir / scan_id
            out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True))
        except OSError:
            log.warning("failed to dump report for %s", scan_id)

    # -- access --------------------------------------------------------------------

    def result(self, scan_id: str) -> dict[str, Any] | None:
        return self._results.get(scan_id)
