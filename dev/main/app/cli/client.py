"""HTTP client wrapper — CLI berkomunikasi ke Cyense API lewat modul ini.

Hanya memanggil endpoint yang ada:
  POST   /api/v1/scans
  GET    /api/v1/scans/{id}
  GET    /api/v1/scans/{id}/report
  GET    /api/v1/scans
  GET    /api/v1/rules
  GET    /api/v1/health
  POST   /api/v1/scans/{id}/fixes
  GET    /api/v1/fixes/{session_id}

Polling adaptif (cli-experience.md §3.6):
  - 250 ms selama 10 detik pertama
  - 500 ms 10-60 detik
  - 1000 ms setelahnya
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import httpx

# ---------------------------------------------------------------------------
# Konstanta

_DEFAULT_BASE = "http://localhost:8000"
_API = "/api/v1"


# ---------------------------------------------------------------------------
# Helper interval polling

def _poll_interval(elapsed: float) -> float:
    if elapsed < 10:
        return 0.25
    if elapsed < 60:
        return 0.5
    return 1.0


# ---------------------------------------------------------------------------
# Client

class CyenseClient:
    """Thin httpx wrapper; semua call ke /api/v1/*."""

    def __init__(self, base_url: str = _DEFAULT_BASE, timeout: float = 30.0) -> None:
        self._base = base_url.rstrip("/")
        self._timeout = timeout
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> CyenseClient:
        self._client = httpx.AsyncClient(
            base_url=self._base,
            timeout=self._timeout,
            follow_redirects=True,
        )
        return self

    async def __aexit__(self, *_: Any) -> None:
        if self._client:
            await self._client.aclose()

    def _c(self) -> httpx.AsyncClient:
        if self._client is None:
            raise RuntimeError("CyenseClient used outside async context manager")
        return self._client

    # -- endpoints -----------------------------------------------------------

    async def health(self) -> dict[str, Any]:
        r = await self._c().get(f"{_API}/health")
        r.raise_for_status()
        return r.json()

    async def rules(self) -> dict[str, Any]:
        r = await self._c().get(f"{_API}/rules")
        r.raise_for_status()
        return r.json()

    async def submit_scan(self, payload: dict[str, Any]) -> dict[str, str]:
        """POST /scans → {"scan_id": "...", "status": "queued"}."""
        r = await self._c().post(f"{_API}/scans", json=payload)
        if r.status_code == 422:
            detail = r.json().get("detail", r.text)
            raise ValueError(f"422 Unprocessable: {detail}")
        r.raise_for_status()
        return r.json()

    async def get_scan(self, scan_id: str) -> dict[str, Any]:
        r = await self._c().get(f"{_API}/scans/{scan_id}")
        r.raise_for_status()
        return r.json()

    async def list_scans(self) -> list[dict[str, Any]]:
        r = await self._c().get(f"{_API}/scans")
        r.raise_for_status()
        return r.json()

    async def get_report(self, scan_id: str) -> dict[str, Any] | None:
        """Kembalikan report dict atau None bila 404."""
        r = await self._c().get(f"{_API}/scans/{scan_id}/report")
        if r.status_code == 404:
            return None
        r.raise_for_status()
        return r.json()

    async def get_csv_export(self, scan_id: str, include_remediation: bool = True) -> str:
        """Download CSV export (text)."""
        r = await self._c().get(
            f"{_API}/scans/{scan_id}/export/csv",
            params={"include_remediation": str(include_remediation).lower()},
        )
        r.raise_for_status()
        return r.text

    async def get_pdf_export(self, scan_id: str) -> bytes:
        """Download PDF export (binary)."""
        r = await self._c().get(f"{_API}/scans/{scan_id}/export/pdf")
        r.raise_for_status()
        return r.content

    async def propose_fixes(self, scan_id: str) -> dict[str, str]:
        r = await self._c().post(f"{_API}/scans/{scan_id}/fixes")
        r.raise_for_status()
        return r.json()

    async def get_fixes(self, session_id: str) -> dict[str, Any]:
        r = await self._c().get(f"{_API}/fixes/{session_id}")
        r.raise_for_status()
        return r.json()

    async def list_resumable(self) -> list[dict[str, Any]]:
        """GET /scans/resumable — list scans with checkpoints."""
        r = await self._c().get(f"{_API}/scans/resumable")
        r.raise_for_status()
        return r.json()

    # -- polling -------------------------------------------------------------

    async def poll_until_done(
        self,
        scan_id: str,
        total_timeout: float = 300.0,
    ) -> AsyncIterator[dict[str, Any]]:
        """Yield status dict secara berkala sampai status terminal atau timeout."""
        ...  # diimplementasikan di bawah sebagai generator terpisah


@asynccontextmanager
async def open_client(
    base_url: str = _DEFAULT_BASE,
    timeout: float = 30.0,
) -> AsyncIterator[CyenseClient]:
    async with CyenseClient(base_url=base_url, timeout=timeout) as client:
        yield client


async def poll_scan(
    client: CyenseClient,
    scan_id: str,
    total_timeout: float = 300.0,
) -> AsyncIterator[dict[str, Any]]:
    """
    Async generator: yield snapshot status setiap kali ada perubahan.
    Status terminal: completed | failed.
    Raise TimeoutError bila total_timeout terlampaui.
    """
    started = time.monotonic()
    prev_status: str | None = None
    prev_progress: int = -1
    prev_stage: str | None = None
    prev_event_count: int = 0

    while True:
        elapsed = time.monotonic() - started
        if elapsed > total_timeout:
            raise TimeoutError(
                f"Scan {scan_id} belum selesai setelah {total_timeout:.0f}s. "
                f"Cek service dengan `cyense version`."
            )

        data = await client.get_scan(scan_id)
        status = data.get("status", "queued")
        progress = data.get("progress", 0)
        stage = data.get("stage")
        events: list[str] = data.get("events", [])
        new_events = events[prev_event_count:]

        # Yield bila ada perubahan bermakna
        changed = (
            status != prev_status
            or progress != prev_progress
            or stage != prev_stage
            or new_events
        )
        if changed:
            data["_new_events"] = new_events
            data["_elapsed"] = elapsed
            yield data

        prev_status = status
        prev_progress = progress
        prev_stage = stage
        prev_event_count = len(events)

        if status in ("completed", "failed"):
            return

        await asyncio.sleep(_poll_interval(elapsed))


def load_report_from_disk(scan_id: str, reports_dir: str = "reports") -> dict[str, Any] | None:
    """
    Fallback: baca report.json dari disk bila GET /report → 404.
    (cli-experience.md §3.6 — report.json ditulis oleh worker._dump_report:184)
    """
    p = Path(reports_dir) / scan_id / "report.json"
    if p.exists():
        import json
        return json.loads(p.read_text())
    return None
