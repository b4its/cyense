"""🔧 Fixer agent — generate patch proposals dari scan findings (PRD §4).

Flow: collect findings → strategy lookup → generate patch → FixProposal models.
Strategi didaftarkan dari python_strategies (AST) dan jsphp_strategies (regex).
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from app.agents.base import AgentResult, BaseAgent
from app.core.models import Finding
from app.remediation.models import FixProposal, FixRisk
from app.remediation.store import FixStore


def find_auth_context(tree: ast.AST) -> str:
    """Find auth variable reference in scope (e.g., 'request.user', 'current_user')."""
    known_patterns = frozenset([
        "request.user", "current_user", "g.user", "session.user",
    ])

    for node in ast.walk(tree):
        # Check Name nodes for bare auth variable names
        if isinstance(node, ast.Name) and node.id in {"current_user", "user"}:
            return node.id

        # Check Attribute chains like request.user
        if isinstance(node, ast.Attribute):
            try:
                expr = ast.unparse(node)
                if expr in known_patterns:
                    return expr
            except Exception:
                continue

    return "unknown"


# --- Strategy function registry (populated lazily) ---
# Maps rule_id -> callable(finding, source, tree) -> dict with keys:
#   diff, before_snippet, after_snippet, risk, notes
STRATEGY_REGISTRY: dict[str, Any] = {}


def _load_strategies() -> None:
    """Populate registry from strategy modules (idempotent)."""
    if STRATEGY_REGISTRY:
        return

    from app.remediation import jsphp_strategies, python_strategies

    for rule_id, entry in python_strategies.STRATEGIES.items():
        STRATEGY_REGISTRY[rule_id] = entry["strategy"]

    for rule_id, entry in jsphp_strategies.JS_PHP_STRATEGIES.items():
        STRATEGY_REGISTRY[rule_id] = entry["strategy"]


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
        """Collect findings → generate FixProposal models → save to store."""
        _load_strategies()
        session = self.store.create_session(self.scan_id)
        self.trajectory.step("session_created", {"session_id": session.session_id})

        proposals: list[FixProposal] = []
        failed_count = 0

        for finding in findings:
            try:
                proposal = self._generate_proposal(session.session_id, finding)
                if proposal:
                    proposals.append(proposal)
            except Exception as exc:
                self.log.error(
                    "Failed to generate proposal for %s: %s",
                    finding.finding_id, exc,
                )
                failed_count += 1

        # Save all proposals to store
        for prop in proposals:
            self.store.add_proposal(session.session_id, prop)

        self.trajectory.step(
            "proposals_done",
            {"count": len(proposals), "failed": failed_count},
        )
        self.trajectory.save()

        return AgentResult(
            agent=self.name,
            ok=True,
            data={
                "session_id": session.session_id,
                "proposals_count": len(proposals),
                "failed_count": failed_count,
                "session_status": session.status,
            },
        )

    # -- internals -------------------------------------------------------------

    def _generate_proposal(
        self, session_id: str, finding: Finding
    ) -> FixProposal | None:
        """Generate single FixProposal using registered strategy."""
        rule_id = finding.rule

        # Extract file/line from finding location ("path.py:42")
        location = finding.location or ""
        file_path = location.rsplit(":", 1)[0] if ":" in location else location
        line = 0
        if ":" in location:
            try:
                line = int(location.rsplit(":", 1)[1])
            except ValueError:
                line = finding.evidence.get("line", 0)

        # Helper to build a manual-required proposal
        def manual(notes: str, risk: str = "medium") -> FixProposal:
            return FixProposal(
                fix_id=f"{finding.finding_id}-manual",
                session_id=session_id,
                scan_id=self.scan_id,
                finding_id=finding.finding_id,
                rule=finding.rule,
                target_file=file_path,
                line=line,
                diff="",
                before_snippet="",
                after_snippet="",
                risk=FixRisk(risk),
                strategy="manual_required",
                notes=notes,
            )

        if rule_id not in STRATEGY_REGISTRY:
            return manual("No automatic fix available; requires manual review", "high")

        # Load source file
        if not file_path:
            return manual("Finding has no file location", "medium")

        try:
            source = Path(file_path).read_text()
        except OSError:
            return manual("Source file not found or unreadable", "medium")

        # Parse AST for python rules
        tree = None
        if file_path.endswith(".py"):
            try:
                tree = ast.parse(source)
            except SyntaxError:
                return manual("Syntax error in target file; cannot apply patch", "medium")

        # Invoke strategy
        strategy_fn = STRATEGY_REGISTRY[rule_id]
        try:
            if tree is not None:
                result = strategy_fn(finding, source, tree)
            else:
                result = strategy_fn(finding, source)
        except Exception as exc:
            self.log.warning("Strategy %s failed: %s", rule_id, exc)
            return manual(f"Strategy error: {exc}", "medium")

        if not isinstance(result, dict):
            return manual("Strategy returned unexpected result type", "medium")

        risk_raw = result.get("risk", "medium").lower()
        try:
            risk = FixRisk(risk_raw)
        except ValueError:
            risk = FixRisk.MEDIUM

        is_manual = "manual_required" in result.get("diff", "")

        proposal = FixProposal(
            fix_id=f"{finding.finding_id}-fix",
            session_id=session_id,
            scan_id=self.scan_id,
            finding_id=finding.finding_id,
            rule=finding.rule,
            target_file=file_path,
            line=line,
            diff=result.get("diff", ""),
            before_snippet=result.get("before_snippet", ""),
            after_snippet=result.get("after_snippet", ""),
            risk=risk,
            strategy=rule_id.lower(),
            notes=result.get("notes", ""),
        )

        if is_manual:
            proposal.notes = "Manual review required: " + result.get("notes", "")

        self.trajectory.step(
            "proposal_generated",
            {"rule": finding.rule, "file": file_path, "line": line,
             "risk": risk.value},
        )
        return proposal
