"""Link engine — dynamic IDOR probing pipeline entry (PRD v2.0 §4.1)."""

from __future__ import annotations

import re
from typing import Any

from app.agents.brain import Brain
from app.agents.orchestrator import Orchestrator


async def run_link_scan(
    scan_id: str,
    request_dict: dict[str, Any],
    brain: Brain,
    reports_dir: str,
    settings: Any,
) -> dict[str, Any]:
    """Run the full agentic pipeline for one link scan request.

    Returns report-shaped dict: {meta, summary, findings}.
    """
    orchestrator = Orchestrator(
        scan_id=scan_id,
        brain=brain,
        reports_dir=reports_dir,
        settings=settings,
    )
    return await orchestrator.run_link(request_dict)


PLACEHOLDER_RE = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")


def has_placeholder(url: str) -> bool:
    return bool(PLACEHOLDER_RE.search(url))
