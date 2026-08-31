"""Diff-scope engine for PR-based scanning (ci-compliance-reporting.md §3.3).

Determines which files changed between commits/branches, enabling targeted scans.
Two resolution strategies:
  * git-local   — ``git diff --name-only`` on a working tree that has a .git dir
  * github-api  — GitHub Compare API via :meth:`GithubClient.compare_refs`
    (host stays inside the SSRF allowlist; no git binary needed for tarballs)

Design notes:
  * Tarball sandboxes have no ``.git`` — that is why the Compare API path
    exists (github-repo-audit.md §3.2 chose tarball over git clone).
  * ``auto`` mode enables diff-scope only when a CI environment is detected
    (GITHUB_ACTIONS, GITLAB_CI, ...); otherwise it degrades to ``full``.
  * ``diff`` mode fails explicitly when the base cannot be resolved — never
    silently falls back to full scope (a partial scan must never look
    like a complete one; ci-compliance-reporting.md §6.4).
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any

# CI environment variables that switch ``auto`` scope into diff mode.
_CI_ENV_VARS = (
    "GITHUB_ACTIONS",
    "GITLAB_CI",
    "CIRCLECI",
    "TRAVIS",
    "JENKINS_URL",
    "BUILD_BUILDID",  # Azure Pipelines
    "CI",
)


def ci_detected() -> bool:
    """True bila proses berjalan di lingkungan CI yang dikenal."""
    return any(var in os.environ for var in _CI_ENV_VARS)


def _parse_owner_repo(repo_url: str) -> tuple[str, str] | None:
    """Extract (owner, repo) dari URL github.com/owner/repo[...]."""
    from urllib.parse import urlparse

    path = urlparse(repo_url).path.strip("/")
    parts = [p for p in path.split("/") if p]
    if len(parts) < 2:
        return None
    owner, repo = parts[0], parts[1]
    if repo.endswith(".git"):
        repo = repo[:-4]
    return owner, repo


class DiffScope:
    """Calculate file scope from git diff or GitHub Compare API."""

    def __init__(
        self,
        base_dir: Path,
        repo_url: str | None = None,
        token: str | None = None,
    ):
        self.base_dir = Path(base_dir)
        self.repo_url = repo_url
        self.token = token

    async def calculate_scope(
        self,
        mode: str,
        diff_base: str | None = None,
        head: str | None = None,
    ) -> dict[str, Any]:
        """Resolve scope; returns a dict consumed by program_engine."""
        result: dict[str, Any] = {
            "mode": mode,
            "base": diff_base,
            "resolved": False,
            "include_paths": set(),
            "excluded_count": 0,
            "reason": "",
        }

        if not mode or mode == "full":
            result["reason"] = "full_scope"
            return result

        effective_mode = mode
        if mode == "auto":
            effective_mode = "diff" if ci_detected() else "full"
            result["mode"] = effective_mode
            result["reason"] = "ci_detected" if effective_mode == "diff" else "no_ci_context"
            if effective_mode == "full":
                return result

        if effective_mode != "diff":
            return result

        # Strategy 1: local git working tree (mode=program with .git present)
        git_result = self._git_diff(diff_base)
        if git_result["success"]:
            files = git_result["files"]
            result["include_paths"] = set(files)
            result["resolved"] = True
            result["reason"] = "git_diff_success"
            result["excluded_count"] = self._count_excluded(files)
            return result

        # Strategy 2: GitHub Compare API (tarball sandboxes without .git)
        if self.repo_url:
            api_result = await self._github_compare(diff_base, head)
            if api_result["success"]:
                files = api_result["files"]
                result["include_paths"] = set(files)
                result["resolved"] = True
                result["reason"] = "github_compare_success"
                result["excluded_count"] = self._count_excluded(files)
                return result
            result["reason"] = f"base_unresolvable ({api_result.get('error', 'unknown')})"
        else:
            result["reason"] = "base_unresolvable (no repo_url for compare api)"

        # diff mode must fail loudly — never silently degrade to full
        return result

    # -- helpers --------------------------------------------------------------

    def _git_diff(self, base: str | None) -> dict[str, Any]:
        """``git diff --name-only <base>...HEAD`` against a local working tree."""
        if not (self.base_dir / ".git").exists():
            return {"success": False, "error": "no .git in base_dir"}

        ref = base or "HEAD^"
        cmd = ["git", "-C", str(self.base_dir), "diff", "--name-only", f"{ref}...HEAD"]
        try:
            proc = subprocess.run(  # noqa: S603 — fixed argv, no shell
                cmd, capture_output=True, text=True, timeout=30, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {"success": False, "error": str(exc)}

        if proc.returncode != 0:
            return {"success": False, "error": proc.stderr.strip()}

        files = [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]
        return {"success": True, "files": files}

    async def _github_compare(self, base: str | None, head: str | None) -> dict[str, Any]:
        """GitHub Compare API via GithubClient.compare_refs (allowlist-scoped)."""
        owner_repo = _parse_owner_repo(self.repo_url or "")
        if not owner_repo:
            return {"success": False, "error": "cannot parse owner/repo from repo_url"}

        owner, repo = owner_repo
        base_ref = base or "main"

        try:
            from app.utils.github_client import GithubClient

            client = GithubClient(token=self.token)
            data = await client.compare_refs(owner, repo, base_ref, head or "HEAD")
        except Exception as exc:  # rate limit, 404, network — all non-fatal here
            return {"success": False, "error": str(exc)}

        files = [f for f in data.get("files", []) if f]
        return {"success": True, "files": files}

    def _count_excluded(self, included: list[str] | set[str]) -> int:
        """Approximate excluded-file count: scannable files minus included."""
        included_set = set(included)
        scannable = 0
        try:
            for path in self.base_dir.rglob("*"):
                if not path.is_file():
                    continue
                parts = {p.lower() for p in path.parts}
                if parts & {"node_modules", ".git", "venv", ".venv", "__pycache__", "dist", "build"}:
                    continue
                rel = path.relative_to(self.base_dir).as_posix()
                if rel not in included_set:
                    scannable += 1
        except OSError:
            pass
        return scannable


def apply_include_filter(
    source_dir: Path,
    include_paths: set[str] | None,
) -> list[Path]:
    """Return scannable files under source_dir filtered by include_paths.

    Kept as a pure helper so it can be unit-tested without any network or
    git dependency (program_engine embeds the same logic inline for speed).
    """
    source_dir = Path(source_dir)
    if include_paths is None:
        return [p for p in sorted(source_dir.rglob("*")) if p.is_file()]

    out: list[Path] = []
    for path in sorted(source_dir.rglob("*")):
        if not path.is_file():
            continue
        try:
            rel = path.relative_to(source_dir).as_posix()
        except ValueError:
            continue
        if rel in include_paths:
            out.append(path)
    return out
