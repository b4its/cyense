"""API tests: health, permission gate (422), scan lifecycle, reports.

Uses a pytest fixture (not a bare ``next(_client())`` helper): pytest keeps
the fixture generator alive for the whole test, which in turn keeps the
TestClient lifespan portal — and the background worker loop — running.
"""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client() -> TestClient:
    from app.main import create_app

    app = create_app()
    with TestClient(app) as test_client:
        yield test_client


def test_health_ok(client: TestClient) -> None:
    resp = client.get("/api/v1/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_permission_gate_returns_422(client: TestClient) -> None:
    resp = client.post(
        "/api/v1/scans",
        json={"mode": "link", "url": "http://lab/invoice/{ID}"},
    )
    assert resp.status_code == 422
    assert "i_have_permission" in resp.text


def test_url_with_control_chars_rejected(client: TestClient) -> None:
    """CRLF in url must be rejected 422 (header-injection hardening)."""
    resp = client.post(
        "/api/v1/scans",
        json={"mode": "link", "url": "http://lab/invoice/{ID}\r\nX-Evil: 1",
              "i_have_permission": True},
    )
    assert resp.status_code == 422


def test_program_permission_gate_returns_422(client: TestClient) -> None:
    resp = client.post("/api/v1/scans", json={"mode": "program"})
    assert resp.status_code == 422


def test_program_scan_lifecycle_completes_with_findings(client: TestClient) -> None:
    """Full lifecycle against the bundled sample package (mode=program)."""
    resp = client.post(
        "/api/v1/scans",
        json={"mode": "program", "lang": "python", "source_type": "sample",
              "i_have_permission": True},
    )
    assert resp.status_code == 202
    scan_id = resp.json()["scan_id"]

    detail: dict = {}
    for _ in range(200):
        detail = client.get(f"/api/v1/scans/{scan_id}").json()
        if detail["status"] in ("completed", "failed"):
            break
        time.sleep(0.05)

    assert detail["status"] == "completed", detail

    report = client.get(f"/api/v1/scans/{scan_id}/report").json()
    assert report["meta"]["mode"] == "program"
    assert report["summary"]["total"] >= 1
    rules = {f["rule"] for f in report["findings"]}
    # acceptance criterion #4: >= 4 of the 6 python rules detected in fixture
    assert {"CY001", "CY002", "CY005", "CY006"} <= rules

    html = client.get(f"/api/v1/scans/{scan_id}/report/html")
    assert html.status_code == 200
    assert "text/html" in html.headers["content-type"]
    assert "<!doctype html>" in html.text.lower()


def test_scan_not_found_returns_404(client: TestClient) -> None:
    assert client.get("/api/v1/scans/doesnotexist").status_code == 404
    assert client.get("/api/v1/scans/doesnotexist/report").status_code == 404


def test_link_scan_without_placeholder_fails_explicitly(client: TestClient) -> None:
    """A recon-level error (no placeholder) must end as FAILED, not completed."""
    resp = client.post(
        "/api/v1/scans",
        json={"mode": "link", "url": "http://lab/docs/plain",
              "i_have_permission": True},
    )
    assert resp.status_code == 202
    scan_id = resp.json()["scan_id"]

    detail: dict = {}
    for _ in range(200):
        detail = client.get(f"/api/v1/scans/{scan_id}").json()
        if detail["status"] in ("completed", "failed"):
            break
        time.sleep(0.05)

    assert detail["status"] == "failed", detail
    assert "placeholder" in (detail.get("error") or "").lower()


def test_delete_scan_removes_report_artifacts(client: TestClient) -> None:
    """DELETE must remove the report (PRD §4.3: hapus scan & artefak)."""
    resp = client.post(
        "/api/v1/scans",
        json={"mode": "program", "source_type": "sample", "i_have_permission": True},
    )
    scan_id = resp.json()["scan_id"]
    for _ in range(200):
        detail = client.get(f"/api/v1/scans/{scan_id}").json()
        if detail["status"] in ("completed", "failed"):
            break
        time.sleep(0.05)
    assert client.get(f"/api/v1/scans/{scan_id}/report").status_code == 200

    assert client.delete(f"/api/v1/scans/{scan_id}").status_code == 204
    assert client.get(f"/api/v1/scans/{scan_id}/report").status_code == 404
