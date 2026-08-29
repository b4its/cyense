"""🧠 Brain agent — shared memory & knowledge base (PRD v2.0 §1.2, §5.2).

Backed by ``dev/brain/knowledge.json`` (mounted at ``/app/brain`` in Docker):

* framework fingerprints → probing strategy heuristics
* accumulated knowledge across scans (valid IDs, ID patterns, fingerprints)
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

from app.utils.logger import get_logger

log = get_logger("brain")

DEFAULT_KNOWLEDGE: dict[str, Any] = {
    "version": 1,
    "frameworks": {
        "django": {
            "hints": ["csrftoken", "django"],
            "id_pattern": "numeric",
            "strategy": "increment around baseline, expect 404 page for missing ids",
        },
        "laravel": {
            "hints": ["laravel_session", "xsrf-token"],
            "id_pattern": "numeric or uuid",
            "strategy": "try increment and uuid shapes",
        },
        "rails": {
            "hints": ["_session_id", "x-request-id", "rails"],
            "id_pattern": "numeric",
            "strategy": "increment around baseline",
        },
        "flask": {
            "hints": ["werkzeug", "flask"],
            "id_pattern": "numeric",
            "strategy": "increment around baseline",
        },
        "express": {
            "hints": ["x-powered-by: express"],
            "id_pattern": "unknown",
            "strategy": "use provided wordlist first",
        },
    },
    "memory": {},  # target host -> accumulated observations
}

_LOCK = threading.Lock()


class Brain:
    """Persistent memory. Reads/writes knowledge.json (best-effort)."""

    def __init__(self, brain_dir: Path | str) -> None:
        self.dir = Path(brain_dir)
        self.path = self.dir / "knowledge.json"
        self.data: dict[str, Any] = {}
        self.load()

    # -- persistence ---------------------------------------------------------

    def load(self) -> None:
        with _LOCK:
            try:
                if self.path.exists():
                    self.data = json.loads(self.path.read_text())
                else:
                    self.data = json.loads(json.dumps(DEFAULT_KNOWLEDGE))
                    self._save_locked()
            except (OSError, json.JSONDecodeError) as exc:
                log.warning("brain load failed (%s); using defaults", exc)
                self.data = json.loads(json.dumps(DEFAULT_KNOWLEDGE))

    def _save_locked(self) -> None:
        try:
            self.dir.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(self.data, indent=2, sort_keys=True))
        except OSError as exc:
            log.warning("brain save failed: %s", exc)

    def save(self) -> None:
        with _LOCK:
            self._save_locked()

    # -- knowledge queries (used by RECON) ------------------------------------

    def strategy_for(self, fingerprint: dict[str, Any]) -> dict[str, Any]:
        """Map a recon fingerprint to a probing strategy from knowledge base."""
        name = (fingerprint.get("framework") or "").lower()
        entry = self.data.get("frameworks", {}).get(name)
        if entry:
            return {
                "framework": name,
                "id_pattern": entry.get("id_pattern", "unknown"),
                "strategy": entry.get("strategy", ""),
            }
        return {
            "framework": name or "unknown",
            "id_pattern": "unknown",
            "strategy": "generic: increment around baseline then wordlist",
        }

    # -- memory updates (used by PROBER/VERIFIER) ------------------------------

    def remember_host(self, host: str, key: str, value: Any) -> None:
        memory: dict[str, Any] = self.data.setdefault("memory", {})
        entry: dict[str, Any] = memory.setdefault(host, {})
        entry[key] = value
        self.save()

    def recall_host(self, host: str) -> dict[str, Any]:
        return dict(self.data.get("memory", {}).get(host, {}))

    def remember_valid_ids(self, host: str, ids: list[str]) -> None:
        if not ids:
            return
        memory = self.data.setdefault("memory", {})
        entry = memory.setdefault(host, {})
        known: list[str] = entry.setdefault("valid_ids", [])
        merged = sorted(set(known) | set(ids))
        entry["valid_ids"] = merged[-200:]  # cap memory growth
        self.save()
