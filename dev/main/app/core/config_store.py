"""CLI configuration persistence (enhanced-reporting-viewer.md §3.6).

Stores user preferences in ``~/.cyense/config.json`` so flags don't have to be
repeated on every run. Follows the Strix secret-file discipline
(``strix/utils/secret_files.py``): atomic write (temp + ``os.replace``) with
``0o600`` permissions, because the file may hold a GitHub token.

Precedence (highest wins): CLI flags > environment variables > config file
> defaults — handled by callers; this module only loads/saves/merges.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

_DEFAULTS: dict[str, Any] = {
    "version": 1,
    "api_url": "http://localhost:8000",
    "default_scan_mode": "standard",
    "default_scope_mode": "auto",
    "viewer_port": 8080,
    "auto_open_viewer": True,
    "github_token": None,
    "telemetry_enabled": False,
}

CONFIG_DIR = Path.home() / ".cyense"
CONFIG_PATH = CONFIG_DIR / "config.json"

# Keys a plain ``config list`` may print; secrets are masked.
_SECRET_KEYS = {"github_token"}


def _mask(key: str, value: Any) -> Any:
    if key in _SECRET_KEYS and value:
        s = str(value)
        return "[REDACTED]" if len(s) < 16 else f"{s[:4]}...{s[-4:]}"
    return value


def load_config(path: Path | None = None) -> dict[str, Any]:
    """Load config, merged over defaults; never raises (falls back to defaults)."""
    target = Path(path) if path else CONFIG_PATH
    data: dict[str, Any] = {}
    try:
        if target.exists():
            loaded = json.loads(target.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                data = loaded
    except (OSError, json.JSONDecodeError):
        data = {}

    merged = {**_DEFAULTS, **data}
    # Forward-compatible migration hook: future schema bumps go here.
    if "version" not in data:
        merged["version"] = 1
    return merged


def save_config(config: dict[str, Any], path: Path | None = None) -> Path:
    """Atomically persist config with 0o600 permissions."""
    target = Path(path) if path else CONFIG_PATH
    target.parent.mkdir(parents=True, exist_ok=True)

    payload = {**_DEFAULTS, **config}

    fd, tmp_name = tempfile.mkstemp(dir=str(target.parent), prefix=".config-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        os.chmod(tmp_name, 0o600)
        os.replace(tmp_name, target)  # atomic on POSIX
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
    return target


def set_value(key: str, value: Any, path: Path | None = None) -> dict[str, Any]:
    """Set a single key and persist; returns the updated config."""
    if key not in _DEFAULTS:
        valid = ", ".join(sorted(k for k in _DEFAULTS if k != "version"))
        raise KeyError(f"unknown config key: {key!r} (valid: {valid})")
    config = load_config(path)
    config[key] = value
    save_config(config, path)
    return config


def reset_config(path: Path | None = None) -> dict[str, Any]:
    """Reset config to defaults."""
    target = Path(path) if path else CONFIG_PATH
    try:
        target.unlink(missing_ok=True)
    except OSError:
        pass
    return dict(_DEFAULTS)


def printable_config(config: dict[str, Any]) -> dict[str, Any]:
    """Config safe to print — secrets masked."""
    return {k: _mask(k, v) for k, v in sorted(config.items())}
