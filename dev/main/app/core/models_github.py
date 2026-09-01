"""Pydantic models untuk mode github scan (PRD §4)."""

from __future__ import annotations

from typing import Any, Literal
from urllib.parse import urlparse

from pydantic import BaseModel, field_validator, model_validator


class GithubScanRequest(BaseModel):
    mode: Literal["github"] = "github"
    # Optional when resuming (restored from checkpoint by the worker).
    repo_url: str = ""
    ref: str | None = None
    subdir: str | None = None
    lang: Literal["python", "js", "php", "auto"] = "auto"
    github_token: str | None = None
    force: bool = False
    i_have_permission: bool = False
    # Strix-derived features (usestrix/strix cli_args.py):
    instruction: str | None = None          # custom testing focus (metadata, not LLM)
    diff_base: str | None = None            # override diff comparison base
    scan_mode: str = "standard"             # quick | standard | deep
    scope_mode: str = "auto"                # auto | full | diff
    # Analysis depth level (low|medium|high|max) — controls how deeply each
    # rule analyzes source code; orthogonal to scan_mode/scope_mode.
    level: str = "medium"
    resume_from: str | None = None          # scan_id to resume from

    @field_validator("repo_url")
    def _github_host_only(cls, v: str) -> str:
        """Validasi: hanya https://github.com/* yang diterima."""
        if not v:
            return v  # resume may omit repo_url (restored from checkpoint)
        parsed = urlparse(v)
        if parsed.scheme != "https" or parsed.hostname != "github.com":
            raise ValueError(
                "repo_url must be an https://github.com/... link "
                "(SSRF guard: non-github hosts rejected)"
            )
        # reject control characters
        if any(ord(c) < 0x20 or ord(c) == 0x7F for c in v):
            raise ValueError("repo_url must not contain control characters")
        return v

    @field_validator("level")
    @classmethod
    def _validate_level(cls, v: str) -> str:
        valid = ("low", "medium", "high", "max")
        if v not in valid:
            raise ValueError(f"level must be one of {valid}, got {v!r}")
        return v

    @model_validator(mode="after")
    def _permission_gate(self) -> GithubScanRequest:
        if not self.i_have_permission:
            raise ValueError(
                "i_have_permission must be true: only scan repositories "
                "you are authorized to audit (read-only static analysis)"
            )
        return self


class RepoMeta(BaseModel):
    owner: str
    repo: str
    ref: str
    commit_sha: str
    url: str
    size_kb: int | None = None
    lang_detected: str | None = None


# Union untuk semua mode (update dari program.py)
ScanRequest = Literal["github"] | dict[str, Any]  # simplified; real union handled per-scenario
