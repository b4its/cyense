"""Tests for the launcher (app/cli/launch.py) — CLI vs Website modes."""

from __future__ import annotations

import pytest


def test_is_backend_running_false_when_down(monkeypatch) -> None:
    from app.cli import launch

    # Backend down → False (no exception)
    assert launch.is_backend_running("127.0.0.1", 1) is False


def test_run_cli_mode_already_running(monkeypatch) -> None:
    """CLI mode with backend already up returns 0 and prints instructions."""
    from app.cli import launch

    monkeypatch.setattr(launch, "is_backend_running", lambda h, p: True)
    code = launch.run_cli_mode("127.0.0.1", 8000)
    assert code == 0


def test_run_cli_mode_starts_backend(monkeypatch) -> None:
    """CLI mode starts backend in background when down, returns 0."""
    from app.cli import launch

    state = {"running": False}

    def _fake_is_running(h, p):
        return state["running"]

    class _P:
        pass

    def _fake_start(h, p):
        state["running"] = True
        return _P()

    monkeypatch.setattr(launch, "is_backend_running", _fake_is_running)
    monkeypatch.setattr(launch, "start_background_backend", _fake_start)
    monkeypatch.setattr(launch, "time", _FakeTime())
    code = launch.run_cli_mode("127.0.0.1", 8000)
    assert code == 0


class _FakeTime:
    def __init__(self):
        self._t = 0

    def monotonic(self):
        self._t += 1
        return self._t

    def sleep(self, s):
        pass


def test_run_website_mode_prints_url_and_blocks(monkeypatch, capsys) -> None:
    """Website mode prints the UI URL then re-execs into uvicorn."""
    from app.cli import launch

    exec_called = []

    monkeypatch.setattr(launch, "is_backend_running", lambda h, p: False)
    monkeypatch.setattr(launch, "_try_open_browser", lambda u: None)

    def _fake_execv(python, argv):
        exec_called.append(argv)
        raise SystemExit(0)

    monkeypatch.setattr(launch.os, "execv", _fake_execv)

    with pytest.raises(SystemExit):
        launch.run_website_mode("127.0.0.1", 9000, open_browser=False)

    out = capsys.readouterr().out
    assert "http://127.0.0.1:9000/ui" in out
    assert "mode WEBSITE" in out
    assert exec_called and "app.main:app" in " ".join(exec_called[0])


def test_backend_cmd_uses_uvicorn_main() -> None:
    from app.cli import launch

    cmd = launch._backend_cmd("127.0.0.1", 8000)
    assert "-m" in cmd and "uvicorn" in cmd
    assert "app.main:app" in cmd
    assert "--port" in cmd and "8000" in cmd
