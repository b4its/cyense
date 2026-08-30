"""Base agent untuk remediasi IDOR (PRD §4 - 🔧 Fixer Agent).

Fixer: kumpulkan temuan → generate proposals → trajectory logging + brain memory.
Berikut strategi per rule (Phase 3-4 akan mengisi registri ini).
"""

from __future__ import annotations

import ast
from collections.abc import Callable
from pathlib import Path
from typing import Any

from app.agents.base import AgentResult, BaseAgent
from app.core.models import Finding
from app.remediation.store import FixSession, FixStore


class PatchStrategy:
    """Registry entry untuk transformasi kode per rule."""

    def __init__(self, name: str, risk: str):
        self.name = name
        self.risk = risk

    def generate_patch(
        self,
        finding: Finding,
        source: str,
        tree: ast.AST,
    ) -> dict[str, Any]:
        """Generate patch proposal dictionary."""
        raise NotImplementedError


# Registry: {rule_id -> PatchStrategy instance}
STRATEGY_REGISTRY: dict[str, PatchStrategy] = {}


def register_strategy(rule_id: str) -> Callable[[PatchStrategy], None]:
    """Decorator untuk mendaftarkan strategi ke registri."""
    def decorator(strategy: PatchStrategy) -> None:
        STRATEGY_REGISTRY[rule_id] = strategy

    return decorator


class FixerAgent(BaseAgent):
    """Agent yang menghasilkan patch proposals dari scan findings."""

    name = "fixer"

    def __init__(
        self,
        scan_id: str,
        reports_dir: str,
        store: FixStore,
        brain: Any = None,
        force: bool = False,
    ):
        super().__init__(scan_id, reports_dir)
        self.scan_id = scan_id
        self.store = store
        self.brain = brain
        self.force = force

    async def run(self, findings: list[Finding]) -> AgentResult:
        """Collect findings → generate proposals."""
        session = await self._create_session()

        proposals: list[Any] = []
        applied_count = 0
        failed_count = 0

        for finding in findings:
            try:
                proposal = await self._generate_proposal(session.session_id, finding)
                if proposal:
                    proposals.append(proposal)
                    applied_count += 1

            except Exception as exc:
                self.log.error("Failed to generate proposal for %s: %s", finding.finding_id, exc)
                failed_count += 1

        # Save all proposals to store
        for prop in proposals:
            self.store.add_proposal(session.session_id, prop)

        return AgentResult(
            agent=self.name,
            ok=True,
            data={
                "session_id": session.session_id,
                "proposals_count": len(proposals),
                "applied_count": applied_count,
                "failed_count": failed_count,
                "session_status": session.status,
            },
        )

    async def _create_session(self) -> FixSession:
        session = self.store.create_session(self.scan_id)
        self.trajectory.step("session_created", {"session_id": session.session_id})
        return session

    async def _generate_proposal(
        self, session_id: str, finding: Finding
    ) -> Any | None:
        """Generate single proposal using registered strategy."""
        rule_id = finding.rule
        if rule_id not in STRATEGY_REGISTRY:
            # Cannot auto-fix this rule; skip but note it
            return {
                "fix_id": f"{finding.finding_id}-manual",
                "session_id": session_id,
                "scan_id": self.scan_id,
                "finding_id": finding.finding_id,
                "rule": finding.rule,
                "risk": "HIGH",
                "notes": "No automatic fix available; requires manual review",
                "strategy": "manual_required",
                "status": "manual_required",
            }

        # Load source file
        location = finding.location or ""
        file_path = location.split(":")[0] if ":" in location else ""
        try:
            file_obj = Path(file_path)
            source = file_obj.read_text()
        except OSError:
            return {
                "fix_id": f"{finding.finding_id}-stale",
                "session_id": session_id,
                "scan_id": self.scan_id,
                "finding_id": finding.finding_id,
                "rule": finding.rule,
                "risk": "MEDIUM",
                "notes": "Source file not found or unreadable",
                "status": "manual_required",
            }

        # Parse AST
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return {
                "fix_id": f"{finding.finding_id}-syntax-error",
                "session_id": session_id,
                "scan_id": self.scan_id,
                "finding_id": finding.finding_id,
                "rule": finding.rule,
                "risk": "MEDIUM",
                "notes": "Syntax error in target file; cannot apply patch",
                "status": "manual_required",
            }

        # Get strategy
        strategy = STRATEGY_REGISTRY[rule_id]

        # Generate patch
        try:
            result = strategy.generate_patch(finding, source, tree)

            proposal = Finding.model_validate({
                **finding.model_dump(mode="json"),
                "session_id": session_id,
                **result,
            })

            self.trajectory.step(
                "proposal_generated",
                {"rule": finding.rule, "file": file_path, "line": finding.line},
            )

            return proposal

        except Exception as exc:
            self.log.warning("Strategy %s failed: %s", rule_id, exc)
            return None

    @staticmethod
    def find_auth_context(tree: ast.AST) -> str:
        """Find auth variable reference in scope (e.g., 'request.user', 'current_user')."""
        for node in ast.walk(tree):
            if isinstance(node, (ast.Attribute, ast.Name)):
                attrs = []
                current = node
                while hasattr(current, "id") or hasattr(current, "attr"):
                    if hasattr(current, "id"):
                        attrs.insert(0, current.id)
                    elif hasattr(current, "attr"):
                        attrs.insert(0, current.attr)

                combined = ".".join(attrs)
                if combined in ["request.user", "current_user", "g.user", "session.user"]:
                    return combined

        # Fallback: look for common patterns
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and node.id.lower() in {"user", "auth"}:
                return node.id

        return "unknown"
