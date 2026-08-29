"""Pydantic data models (PRD v2.0 §6) and rule interface (§4.2)."""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal, Protocol

from pydantic import BaseModel, Field, HttpUrl, model_validator

# ---------------------------------------------------------------------------
# enums


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScanStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


# ---------------------------------------------------------------------------
# requests


class LinkScanRequest(BaseModel):
    mode: Literal["link"]
    url: HttpUrl
    headers: dict[str, str] = {}
    cookies: dict[str, str] = {}
    baseline_id: str | None = None
    probe_ids: list[str] | Literal["auto"] = "auto"
    method: Literal["GET", "HEAD"] = "GET"
    i_have_permission: bool = False

    @model_validator(mode="after")
    def _permission_gate(self) -> "LinkScanRequest":
        # PRD §2.2 ethics note + §4.1: 422 unless explicitly granted.
        if not self.i_have_permission:
            raise ValueError(
                "i_have_permission must be true: only scan targets you are "
                "authorized to test (read-only probing)"
            )
        return self


class ProgramScanRequest(BaseModel):
    mode: Literal["program"]
    lang: Literal["python", "js", "php"] = "python"
    source_type: Literal["mounted", "sample"] = "mounted"
    i_have_permission: bool = False

    @model_validator(mode="after")
    def _permission_gate(self) -> "ProgramScanRequest":
        if not self.i_have_permission:
            raise ValueError(
                "i_have_permission must be true: only analyze code you are "
                "authorized to audit"
            )
        return self


ScanRequest = LinkScanRequest | ProgramScanRequest


# ---------------------------------------------------------------------------
# findings


class VerificationEvidence(BaseModel):
    similarity: float | None = None
    pii_matches: list[str] = []
    retry_consistent: bool | None = None
    control_id_blocked: bool | None = None
    notes: str = ""


class Finding(BaseModel):
    finding_id: str
    rule: str
    severity: Severity
    confidence: float = Field(ge=0, le=1)
    title: str
    description: str = ""
    evidence: dict[str, Any] = {}
    verification: VerificationEvidence = VerificationEvidence()
    remediation: str = ""
    location: str | None = None


# ---------------------------------------------------------------------------
# scan job


class ScanJob(BaseModel):
    scan_id: str
    request: LinkScanRequest | ProgramScanRequest
    status: ScanStatus = ScanStatus.QUEUED
    stage: str | None = None  # recon | probe | verify | report
    progress: int = 0  # 0..100
    error: str | None = None
    created_at: str = ""
    finished_at: str | None = None


# ---------------------------------------------------------------------------
# static-analysis rule protocol (PRD §4.2)


class FileContext(BaseModel):
    path: str
    lang: str
    source: str


class IdorRule(Protocol):
    rule_id: str
    severity: Severity

    def check(self, node: Any, ctx: FileContext) -> list[Finding]: ...
