"""Launcher — pilih mode menjalankan Cyense: Website atau CLI.

Alur:
  * **Website** — menjalankan backend FastAPI + frontend Svelte, lalu
    menampilkan lokasi website (``http://<host>:<port>/ui``).
  * **CLI** — memastikan backend FastAPI berjalan (dijalankan di
    background bila belum), lalu mengarahkan ke client CLI berbasis
    command (``cyense scan …``).

Baik CLI maupun Website, backend-nya tetap FastAPI — perbedaannya hanya
client-side: CLI (perintah) vs Web UI (browser).
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

from app.utils.logger import get_logger

log = get_logger("launch")

_DEFAULT_HOST = "127.0.0.1"
_DEFAULT_PORT = 8000


def _find_venv_python() -> str | None:
    """Locate the interpreter inside the current virtualenv, if any."""
    if hasattr(sys, "real_prefix") or (
        hasattr(sys, "base_prefix") and sys.base_prefix != sys.prefix
    ):
        return sys.executable
    return None


def _backend_cmd(host: str, port: int) -> list[str]:
    """Build the uvicorn command for the FastAPI backend."""
    python = _find_venv_python() or sys.executable
    return [python, "-m", "uvicorn", "app.main:app", "--host", host, "--port", str(port)]


def is_backend_running(host: str, port: int) -> bool:
    """Return True if the FastAPI backend answers /api/v1/health."""
    url = f"http://{host}:{port}/api/v1/health"
    try:
        with urllib.request.urlopen(url, timeout=2) as resp:
            return resp.status == 200
    except Exception:
        return False


def start_background_backend(host: str, port: int) -> subprocess.Popen | None:
    """Start FastAPI in the background (detached). Returns the process.

    Callers must eventually ``proc.terminate()``/``wait()`` if the startup
    fails, to avoid an orphaned server process.
    """
    # Make sure the port is free first (TOCTOU-tolerant: caller re-checks
    # health after spawn, so a mid-boot backend is handled).
    try:
        sock = socket.socket()
        sock.bind((host, port))
        sock.close()
    except OSError:
        return None  # something already listening

    cmd = _backend_cmd(host, port)
    log_path = Path("backend.log")
    with open(log_path, "a", encoding="utf-8") as out, \
            open(os.devnull, "w", encoding="utf-8") as devnull:
        return subprocess.Popen(
            cmd,
            stdout=out,
            stderr=subprocess.STDOUT,
            stdin=devnull,
            start_new_session=True,
            cwd=str(Path.cwd()),
        )


def run_website_mode(host: str, port: int, *, open_browser: bool) -> int:
    """Run backend + frontend in the foreground; print the website URL.

    Blocks until Ctrl+C (returns 0) or the server exits.
    """
    if not is_backend_running(host, port):
        log.info("backend dijalankan di foreground (uvicorn)…")
        # Re-exec into uvicorn as the current process so Ctrl+C works cleanly.
        print()
        print("  ╭──────────────────────────────────────────────────────────╮")
        print("  │  Cyense — mode WEBSITE                                   │")
        print("  │                                                          │")
        print(f"  │  Backend API : http://{host}:{port}/api/v1/health       │")
        print(f"  │  Website UI  : http://{host}:{port}/ui                  │")
        print("  │                                                          │")
        print("  │  Ctrl+C untuk berhenti.                                  │")
        print("  ╰──────────────────────────────────────────────────────────╯", flush=True)
        print(flush=True)
        # Flush BEFORE os.execv — execv replaces the process image and would
        # otherwise discard buffered stdout, losing the URL display.
        sys.stdout.flush()
        if open_browser:
            _try_open_browser(f"http://{host}:{port}/ui")
        os.execv(sys.executable, [sys.executable, "-m", "uvicorn",
                                  "app.main:app", "--host", host,
                                  "--port", str(port)])
    else:
        print(f"  Backend sudah berjalan: http://{host}:{port}/ui")
    return 0


def _try_open_browser(url: str) -> None:
    try:
        if sys.platform.startswith("darwin"):
            subprocess.Popen(["open", url])
        elif os.name == "nt":
            os.startfile(url)  # type: ignore[attr-defined]
        else:
            shutil.which("xdg-open") and subprocess.Popen(["xdg-open", url])
    except Exception:  # noqa: BLE001 — browser opening is best-effort
        pass


def run_cli_mode(host: str, port: int) -> int:
    """Ensure the FastAPI backend is running (background), then point to the CLI.

    The CLI is the client-side: commands like ``cyense scan website URL``.
    """
    print()
    print("  ╭──────────────────────────────────────────────────────────╮")
    print("  │  Cyense — mode CLI (client berbasis command)              │")
    print("  ╰──────────────────────────────────────────────────────────╯")
    print()

    if is_backend_running(host, port):
        print(f"  ✓ Backend FastAPI sudah berjalan: http://{host}:{port}")
    else:
        proc = start_background_backend(host, port)
        if proc is None:
            # Could not bind — but the backend may be mid-boot (port bound,
            # /health not yet up). Re-check before giving up.
            if is_backend_running(host, port):
                print(f"  ✓ Backend FastAPI berjalan: http://{host}:{port}")
                return 0
            print(f"  ✗ Gagal menjalankan backend (port {port} mungkin terpakai).")
            return 1
        # Wait for health.
        deadline = time.monotonic() + 15
        ok = False
        while time.monotonic() < deadline:
            if is_backend_running(host, port):
                ok = True
                break
            time.sleep(0.5)
        if not ok:
            # Clean up the spawned process so it doesn't linger as an orphan.
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except Exception:  # noqa: BLE001 — best-effort cleanup
                pass
            print("  ✗ Backend tidak merespons dalam 15 detik. Cek backend.log")
            return 1
        print(f"  ✓ Backend FastAPI dijalankan di background: http://{host}:{port}")
        print("    (log: backend.log, stop: kill <pid> atau make down)")

    print()
    print("  Client-side: CLI berbasis command. Contoh:")
    print("    cyense scan website http://example.com --i-have-permission")
    print("    cyense recon http://example.com --i-have-permission   # + OSINT/RE/OWASP")
    print("    cyense crypt hash 'hello' --algo sha256               # toolbelt kriptografi")
    print("    cyense crypt aes encrypt 'rahasia' --key <k> -m gcm")
    print("    cyense coverage <scan_id>                             # cakupan coverage")
    print("    cyense export sarif <scan_id> -o out.sarif            # ekspor SARIF")
    print("    cyense list")
    print()
    return 0
