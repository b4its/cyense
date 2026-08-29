"""JSON report builder (PRD v2.0 §4.4).

The orchestrator/worker already emit report-shaped dicts; this module
normalizes and dumps them with sorted keys for determinism (PRD §9).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def dump_json_report(report: dict[str, Any], path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True))
    return path


def load_json_report(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())
