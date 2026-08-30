"""Pydantic models untuk mode github scan (PRD §4)."""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator
from urllib.parse import urlparse


class GithubScanRequest(BaseModel):
    mode: Literal["github"] = "github"
    repo_url: str
    ref: str | None = None
    subdir: str | None = None
    lang: Literal["python", "js", "php", "auto"] = "auto"
    github_token: str | None = None
    force: bool = False
    i_have_permission: bool = False

    @field_validator("repo_url")
    def _github_host_only(cls, v: str) -> str:
        """Validasi: hanya https://github.com/* yang diterima."""
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

    @model_validator(mode="after")
    def _permission_gate(self) -> "GithubScanRequest":
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
