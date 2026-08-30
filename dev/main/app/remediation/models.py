"""Data models untuk fitur remediasi IDOR (PRD instruction/feature/idor-remediation.md)."""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


class FixStatus(str, Enum):
    PROPOSED = "proposed"
    APPLIED = "applied"
    VERIFIED = "verified"
    REVERTED = "reverted"
    REJECTED = "rejected"
    MANUAL_REQUIRED = "manual_required"


class FixRisk(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class PatchVerification(BaseModel):
    syntax_ok: bool = True
    original_resolved: bool = False
    new_findings: int = 0
    delta_summary: str = ""


class FixProposal(BaseModel):
    """Single patch proposal per temuan (PRD §3.2)."""
    
    fix_id: str
    session_id: str
    scan_id: str
    finding_id: str
    rule: str
    target_file: str
    line: int
    diff: str  # unified diff preview
    before_snippet: str
    after_snippet: str
    risk: FixRisk
    strategy: str
    backup_path: str | None = None
    verification: PatchVerification | None = None
    notes: str = ""
    
    def is_verified(self) -> bool:
        return self.verification is not None and self.verification.original_resolved


class FixSession(BaseModel):
    """Container for a batch of fix proposals."""
    
    session_id: str
    scan_id: str
    created_at: str = ""
    status: str = "proposed"  # active|completed|cancelled
    
    @staticmethod
    def generate_session_id() -> str:
        import uuid
        return f"fix_{uuid.uuid4().hex[:12]}"


# Union handling - actual union handled per-scenario like github mode
FixRequest = dict[str, Any]
