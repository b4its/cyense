"""Regression tests: deleting a scan mid-run must never kill the worker.

Bug: JobStore.mark_* used ``self._jobs[scan_id]`` directly. When a scan was
deleted while RUNNING, the worker's failure path called ``mark_failed`` which
raised KeyError *inside the except handler* — the exception escaped the loop
and the background worker task died silently. Every subsequent scan then
stayed ``queued`` forever.
"""

from __future__ import annotations

import asyncio
import time

import pytest


def test_store_transitions_tolerate_deleted_scan(tmp_path) -> None:
    """mark_* on an unknown scan_id must be a no-op, not KeyError."""
    from app.core.store import JobStore

    store = JobStore(tmp_path / "reports")


    async def scenario() -> None:
        await store.mark_running("ghost", "recon")
        await store.mark_stage("ghost", "probe", 50)
        await store.mark_completed("ghost")
        await store.mark_failed("ghost", "boom")

    asyncio.run(scenario())
    assert store.get("ghost") is None


def test_worker_survives_job_deleted_mid_processing(tmp_path, monkeypatch) -> None:
    """A scan that is deleted while being processed must not kill the loop.

    Pre-fix: run_link_scan raises after the job is deleted → _process's
    except calls mark_failed → KeyError → _loop's except calls mark_failed
    again → KeyError escapes the loop → worker task dead.
    """
    from app.core.models import LinkScanRequest
    from app.core.store import JobStore
    from app.worker import ScanWorker

    store = JobStore(tmp_path / "reports")


    class _Settings:
        reports_dir = tmp_path / "reports"
        workspace_dir = tmp_path / "workspace"

    async def exploding_link_scan(**_kwargs):
        # Simulate: job is deleted (by a concurrent DELETE request) while
        # the engine is still running, then the engine crashes.
        store.delete(job.scan_id)
        raise RuntimeError("engine exploded mid-scan")

    monkeypatch.setattr("app.worker.run_link_scan", exploding_link_scan)

    worker = ScanWorker(store, brain=None, settings=_Settings())


    async def scenario() -> None:
        worker.start()
        request = LinkScanRequest(
            mode="link",
            url="http://lab/invoice/{ID}",
            i_have_permission=True,
        )
        job = store.create(request)
        worker.enqueue(job)

        # queue.join() returns only after task_done() ran in the worker's
        # finally-block — i.e. after the whole crash-handling chain finished.
        # (Checking task.done() after a fixed sleep is racy: the pre-fix
        # KeyError chain contains awaits and may still be unwinding.)
        await asyncio.wait_for(worker.queue.join(), timeout=10)

        # The worker loop task must still be alive after the crash.
        assert worker._task is not None
        assert not worker._task.done(), (
            "worker loop died — subsequent scans would stay queued forever"
        )

        # And it can still process a follow-up scan end-to-end.

        async def healthy_link_scan(*, scan_id, **_kwargs):
            return {
                "meta": {"scan_id": scan_id, "mode": "link", "engine": "agentic"},
                "summary": {"total": 0},
                "findings": [],
            }

        monkeypatch.setattr("app.worker.run_link_scan", healthy_link_scan)
        job2 = store.create(request)
        worker.enqueue(job2)

        deadline = time.monotonic() + 10
        while store.get(job2.scan_id).status.value not in ("completed", "failed"):
            if time.monotonic() > deadline:
                pytest.fail("second scan never reached a terminal state")
            await asyncio.sleep(0.05)

        assert store.get(job2.scan_id).status.value == "completed"
        assert not worker._task.done()
        await worker.stop()

    asyncio.run(scenario())
