"""Agent framework: base class, result container, trajectory recorder.

Every agent (PRD v2.0 §1.2) records its reasoning steps to
``reports/<scan_id>/trajectories/<agent>.json`` — hackathon deliverable #4.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.utils.logger import get_logger


@dataclass
class AgentResult:
    """Typed outcome of one agent run."""

    agent: str
    ok: bool
    data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    duration_ms: int = 0


@dataclass
class TrajectoryRecorder:
    """Append-only step log for one agent within one scan."""

    scan_id: str
    agent: str
    reports_dir: Path
    steps: list[dict[str, Any]] = field(default_factory=list)

    def step(self, action: str, detail: dict[str, Any] | None = None) -> None:
        self.steps.append(
            {
                "t": round(time.time(), 3),
                "action": action,
                "detail": detail or {},
            }
        )

    def save(self) -> Path | None:
        try:
            out_dir = Path(self.reports_dir) / self.scan_id / "trajectories"
            out_dir.mkdir(parents=True, exist_ok=True)
            path = out_dir / f"{self.agent}.json"
            path.write_text(
                json.dumps(
                    {"scan_id": self.scan_id, "agent": self.agent, "steps": self.steps},
                    indent=2,
                )
            )
            return path
        except OSError:
            return None


class BaseAgent:
    """Common plumbing: logging, trajectory, timing. Subclasses implement run()."""

    name = "base"

    def __init__(self, scan_id: str, reports_dir: Path | str) -> None:
        self.scan_id = scan_id
        self.reports_dir = Path(reports_dir)
        self.trajectory = TrajectoryRecorder(scan_id, self.name, self.reports_dir)
        self.log = get_logger(f"agent.{self.name}")

    async def run(self, ctx: dict[str, Any]) -> AgentResult:  # pragma: no cover
        raise NotImplementedError

    async def __call__(self, ctx: dict[str, Any]) -> AgentResult:
        start = time.monotonic()
        self.trajectory.step("start", {"agent": self.name})
        try:
            result = await self.run(ctx)
        except Exception as exc:  # keep the pipeline alive, record the failure
            self.log.error("agent %s failed: %s", self.name, exc)
            self.trajectory.step("error", {"error": str(exc)})
            self.trajectory.save()
            return AgentResult(
                agent=self.name,
                ok=False,
                error=str(exc),
                duration_ms=int((time.monotonic() - start) * 1000),
            )
        result.duration_ms = int((time.monotonic() - start) * 1000)
        self.trajectory.step("end", {"ok": result.ok, "ms": result.duration_ms})
        self.trajectory.save()  # deliverable #4: trajectory log per agent
        return result
