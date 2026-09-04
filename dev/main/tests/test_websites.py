"""Tests for the saved scanned-websites list (app/api/websites.py).

GET /websites aggregates all scanned targets into one entry per host/domain,
deduplicated, newest scan first, with the severity summary loaded from the
persisted report.json (disk fallback — the API must keep working after a
service restart when the worker's in-memory cache is empty).
"""

from __future__ import annotations

import asyncio
import json
import time
from types import SimpleNamespace

from fastapi.testclient import TestClient


def _host_of(target: str) -> str:
    from app.api.websites import _host_of as fn

    return fn(target)


def test_host_of_extraction() -> None:
    assert _host_of("http://app.example/invoice/1") == "app.example"
    assert _host_of("https://sub.example.com:8443/path?q=1") == "sub.example.com"
    assert _host_of("https://user:pass@app.example/x") == "app.example"
    assert _host_of("example.com") == "example.com"
    assert _host_of("") == ""


def _setup(app, reports_dir, brain_dir) -> None:
    """Swap app state so the /websites endpoint reads from a tmp store."""
    from app.core.store import JobStore

    app.state.store = JobStore(reports_dir)
    app.state.settings = SimpleNamespace(
        reports_dir=reports_dir,
        brain_dir=brain_dir,
    )


def test_websites_aggregates_scans_by_host_with_persisted_summary(tmp_path) -> None:
    from app.core.models import WebsiteScanRequest
    from app.main import create_app

    reports_dir = tmp_path / "reports"
    app = create_app()

    with TestClient(app) as client:
        _setup(app, reports_dir, tmp_path / "brain")
        store = app.state.store

        # Two scans against the same host (must dedupe, newest wins), one
        # against another host. Sleep between submits: created_at has second
        # precision, so ordering must not rely on wall-clock races.
        def _submit(url: str) -> str:
            job = store.create(
                WebsiteScanRequest(
                    mode="website", url=url, i_have_permission=True,
                )
            )
            asyncio.run(store.mark_completed(job.scan_id))
            return job.scan_id

        _submit("http://app.example/invoice")
        time.sleep(1.1)
        sid2 = _submit("http://app.example/orders")
        time.sleep(1.1)
        sid3 = _submit("http://other.example/login")

        # Persist reports on disk (as the worker would). The worker cache is
        # empty here — simulating a restart — so summaries must come from disk.
        for scan_id, summary in (
            (sid2, {"critical": 2, "high": 1, "medium": 0, "low": 0, "info": 0, "total": 3}),
            (sid3, {"critical": 0, "high": 0, "medium": 4, "low": 1, "info": 0, "total": 5}),
        ):
            rdir = reports_dir / scan_id
            rdir.mkdir(parents=True, exist_ok=True)
            (rdir / "report.json").write_text(json.dumps({
                "meta": {"scan_id": scan_id},
                "summary": summary,
                "findings": [],
            }))

        resp = client.get("/api/v1/websites")
        assert resp.status_code == 200
        sites = resp.json()

        hosts = {s["host"]: s for s in sites}
        assert set(hosts) == {"app.example", "other.example"}, hosts

        # newest scan per host wins; both persisted summaries loaded from disk
        app_site = hosts["app.example"]
        assert app_site["scan_id"] == sid2
        assert app_site["scan_count"] == 2
        assert app_site["summary"]["critical"] == 2
        assert app_site["summary"]["total"] == 3

        other = hosts["other.example"]
        assert other["scan_id"] == sid3
        assert other["scan_count"] == 1
        assert other["summary"]["medium"] == 4

        # newest first ordering — other.example was scanned last
        assert sites[0]["host"] == "other.example"
        assert sites[1]["host"] == "app.example"


def test_websites_empty_without_scans(tmp_path) -> None:
    from app.main import create_app

    app = create_app()
    with TestClient(app) as client:
        _setup(app, tmp_path / "reports", tmp_path / "brain")
        resp = client.get("/api/v1/websites")
        assert resp.status_code == 200
        assert resp.json() == []


def test_store_restores_persisted_jobs_on_startup(tmp_path) -> None:
    """JobStore must reload jobs/events from store.json on init — otherwise
    the saved scanned-websites list (and scan library) vanishes after a
    service restart even though report.json files still exist."""
    import asyncio

    from app.core.models import LinkScanRequest
    from app.core.store import JobStore

    reports_dir = tmp_path / "reports"
    store1 = JobStore(reports_dir)
    req = LinkScanRequest(
        mode="link", url="http://lab/invoice/{ID}", i_have_permission=True,
    )
    job = store1.create(req)
    asyncio.run(store1.mark_stage(job.scan_id, "recon", 10))
    asyncio.run(store1.mark_failed(job.scan_id, "boom"))

    # Simulate a restart: a fresh store reading the same persisted dump.
    store2 = JobStore(reports_dir)
    restored = store2.get(job.scan_id)
    assert restored is not None
    assert restored.request.mode == "link"
    assert restored.status.value == "failed"
    assert restored.error == "boom"
    events = store2.events(job.scan_id)
    assert any("stage: recon" in e for e in events)
    assert any("failed" in e and "boom" in e for e in events)
