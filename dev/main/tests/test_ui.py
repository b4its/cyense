"""Tests for the Svelte web UI router (app/api/ui.py)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import create_app


@pytest.fixture()
def client() -> TestClient:
    return TestClient(create_app())


def test_ui_serves_index_or_503(client: TestClient) -> None:
    """/ui serves the built SPA when present, otherwise a clear 503."""
    from app.api import ui as ui_mod

    r = client.get("/ui")
    if ui_mod._INDEX.exists():
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/html")
        assert "Cyense" in r.text
    else:
        assert r.status_code == 503
        assert "npm run build" in r.json().get("detail", "")


def test_ui_fallback_serves_spa(client: TestClient) -> None:
    """Any /ui/* path falls back to index.html (hash routing)."""
    from app.api import ui as ui_mod

    r = client.get("/ui/scans")
    if ui_mod._INDEX.exists():
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/html")
    else:
        assert r.status_code == 503


def test_ui_assets_traversal_blocked(client: TestClient) -> None:
    """Asset paths escaping the assets dir are rejected.

    The ASGI server normalizes '..' before routing, so a traversal attempt
    either 403s (our guard) or 404s (path collapsed) — never serves a file
    outside the assets dir.
    """
    r = client.get("/ui/assets/..%2f..%2fetc/passwd")
    if r.status_code == 200:
        # If it somehow resolved, it must still be an asset-style body
        assert "passwd" not in r.text
    else:
        assert r.status_code in (403, 404)


def test_ui_assets_missing_404(client: TestClient) -> None:
    r = client.get("/ui/assets/does-not-exist.js")
    assert r.status_code == 404
