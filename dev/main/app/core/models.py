"""Pydantic data models (PRD v2.0 §6) and rule interface (§4.2)."""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Any, Literal, Protocol

from pydantic import BaseModel, Field, field_validator, model_validator

# Import GitHub models for union handling
from .models_github import GithubScanRequest, RepoMeta  # noqa: F401


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScanStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


# ---------------------------------------------------------------------------
# requests


class LinkScanRequest(BaseModel):
    mode: Literal["link"]
    # str instead of HttpUrl: pydantic's HttpUrl percent-encodes `{ID}`
    # placeholders (%7BID%7D) which would break placeholder detection.
    # Optional when resuming: the worker restores the original request from
    # the checkpoint (cyense scan resume 422 fix).
    url: str = ""
    headers: dict[str, str] = {}
    cookies: dict[str, str] = {}
    baseline_id: str | None = None
    probe_ids: list[str] | Literal["auto"] = "auto"
    method: Literal["GET", "HEAD"] = "GET"
    i_have_permission: bool = False
    # Strix-derived features (usestrix/strix cli_args.py):
    instruction: str | None = None
    scan_mode: str = "standard"
    scope_mode: str = "auto"
    resume_from: str | None = None

    @field_validator("url")
    @classmethod
    def _validate_url(cls, value: str) -> str:
        if not value:
            return value  # resume may omit url (restored from checkpoint)
        if not re.match(r"^https?://\S+$", value):
            raise ValueError("url must be a valid http(s) URL")
        # reject control characters (CRLF/header injection attempts)
        if any(ord(ch) < 0x20 or ch == "\x7f" for ch in value):
            raise ValueError("url must not contain control characters")
        return value

    @model_validator(mode="after")
    def _permission_gate(self) -> LinkScanRequest:
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
    # Optional explicit source directory (multi-target "local:" entries).
    # Overrides the workspace_dir default when present.
    source_dir: str | None = None
    i_have_permission: bool = False
    # Strix-derived features (usestrix/strix cli_args.py):
    instruction: str | None = None
    scan_mode: str = "standard"
    scope_mode: str = "auto"
    # Analysis depth level (low|medium|high|max) — controls how deeply each
    # rule analyzes source code; orthogonal to scan_mode/scope_mode.
    level: str = "medium"
    resume_from: str | None = None

    @model_validator(mode="after")
    def _permission_gate(self) -> ProgramScanRequest:
        if not self.i_have_permission:
            raise ValueError(
                "i_have_permission must be true: only analyze code you are "
                "authorized to audit"
            )
        return self

    @field_validator("level")
    @classmethod
    def _validate_level(cls, v: str) -> str:
        valid = ("low", "medium", "high", "max")
        if v not in valid:
            raise ValueError(f"level must be one of {valid}, got {v!r}")
        return v


class DomainScanRequest(BaseModel):
    """Scan seluruh domain: enumerasi subdomain lalu jalankan pipeline
    website scan (crawl, tech, port, CVE, discovery, probe, SQLi) ke
    setiap host yang hidup, dengan agregasi lintas subdomain.
    """

    mode: Literal["domain"]
    # Domain target (contoh: example.com). Hostname diambil darinya.
    domain: str = ""
    # Batas jumlah host yang di-scan (safety cap).
    max_hosts: int = Field(default=20, ge=1, le=100)
    max_depth: int = Field(default=1, ge=0, le=5)
    max_pages: int = Field(default=20, ge=1, le=500)
    rate_limit: int = Field(default=10, ge=1, le=100)
    headers: dict[str, str] = {}
    cookies: dict[str, str] = {}
    i_have_permission: bool = False
    instruction: str | None = None
    scan_mode: str = "standard"
    resume_from: str | None = None

    @field_validator("domain")
    @classmethod
    def _validate_domain(cls, value: str) -> str:
        if not value:
            return value  # resume may omit domain (restored from checkpoint)
        # Reject anything that isn't a plain hostname (no scheme/path/port).
        if any(ch in value for ch in ("/", ":", "@", " ", "\n", "\r")):
            raise ValueError("domain must be a bare hostname (e.g. example.com)")
        return value.strip().lower()

    @model_validator(mode="after")
    def _permission_gate(self) -> DomainScanRequest:
        if not self.i_have_permission:
            raise ValueError(
                "i_have_permission must be true: only scan domains "
                "you are authorized to test (read-only)"
            )
        return self


class WebsiteScanRequest(BaseModel):
    """Scan a public website for IDOR & XSS via crawler + live analysis.

    Unlike :class:`LinkScanRequest`, the URL does NOT need an ``{ID}``
    placeholder — the crawler discovers ID-bearing endpoints on its own.
    Scanning is strictly **same-domain** and **read-only** (HTTP GET).
    """

    mode: Literal["website"]
    # Optional when resuming (restored from checkpoint by the worker).
    url: str = ""
    max_depth: int = Field(default=2, ge=0, le=5)
    max_pages: int = Field(default=50, ge=1, le=500)
    rate_limit: int = Field(default=10, ge=1, le=100)
    headers: dict[str, str] = {}
    cookies: dict[str, str] = {}
    # Skip the open-port scan stage (nmap-style TCP connect) when the target
    # does not want the extra load; wired to the CLI --no-port-scan option.
    skip_port_scan: bool = False
    i_have_permission: bool = False
    instruction: str | None = None
    scan_mode: str = "standard"
    resume_from: str | None = None

    @field_validator("url")
    @classmethod
    def _validate_url(cls, value: str) -> str:
        if not value:
            return value  # resume may omit url (restored from checkpoint)
        if not re.match(r"^https?://\S+$", value):
            raise ValueError("url must be a valid http(s) URL")
        if any(ord(ch) < 0x20 or ch == "\x7f" for ch in value):
            raise ValueError("url must not contain control characters")
        return value

    @model_validator(mode="after")
    def _permission_gate(self) -> WebsiteScanRequest:
        if not self.i_have_permission:
            raise ValueError(
                "i_have_permission must be true: only scan websites "
                "you are authorized to test (read-only crawling)"
            )
        return self


ScanRequest = (
    LinkScanRequest
    | ProgramScanRequest
    | GithubScanRequest
    | WebsiteScanRequest
    | DomainScanRequest
)


# ---------------------------------------------------------------------------
# findings


class VerificationEvidence(BaseModel):
    similarity: float | None = None
    pii_matches: list[str] = []
    retry_consistent: bool | None = None
    control_id_blocked: bool | None = None
    similarity_to_control: float | None = None
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
    # New optional fields for compliance reporting (backward-compatible)
    cwe: str | None = None  # CWE identifier
    cvss_score: float | None = None  # CVSS v3.1 Base Score (0-10)
    cvss_vector: str | None = None  # Full CVSS vector string


# ---------------------------------------------------------------------------
# scan job


class ScanJob(BaseModel):
    scan_id: str
    request: (
        LinkScanRequest
        | ProgramScanRequest
        | GithubScanRequest
        | WebsiteScanRequest
        | DomainScanRequest
    )
    status: ScanStatus = ScanStatus.QUEUED
    stage: str | None = None  # recon | probe | verify | report | crawl
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
