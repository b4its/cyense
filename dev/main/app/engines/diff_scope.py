"""Diff-scope engine for PR-based scanning (ci-compliance-reporting.md §3.3).

Determines which files changed between commits/branches, enabling targeted scans.
Uses git diff locally or GitHub Compare API remotely.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

from app.utils.github_client import GithubClient


class DiffScope:
    """Calculate file scope from git diff or GitHub Compare API."""
    
    def __init__(self, base_dir: Path, repo_url: str | None = None):
        self.base_dir = base_dir
        self.repo_url = repo_url
        self.git = None  # lazy init
    
    async def calculate_scope(
        self,
        mode: str,
        diff_base: str | None = None,
    ) -> dict[str, Any]:
        """Calculate scope based on mode and base branch."""
        
        result = {
            "mode": mode,
            "base": diff_base,
            "resolved": False,
            "include_paths": set(),
            "excluded_count": 0,
            "reason": "",
        }
        
        if mode == "full" or not mode:
            return result
        
        # Auto mode: enable diff if CI context detected
        if mode == "auto":
            mode = "diff" if self._ci_detected() else "full"
        
        if mode != "diff":
            return result
        
        # Try to resolve diff first via git
        git_diff = await self._git_diff(diff_base)
        if git_diff["success"]:
            result["include_paths"] = set(git_diff["files"])
            result["resolved"] = True
            result["reason"] = "git_diff_success"
            
            # Count excluded (approximate - total files minus included)
            all_files = len(list(self.base_dir.rglob("*")))
            result["excluded_count"] = max(0, all_files - len(result["include_paths"]))
            return result
        
        # Git failed or unavailable — try GitHub Compare API
        if self.repo_url and mode == "diff":
            api_diff = await self._github_compare(diff_base)
            if api_diff["success"]:
                result["include_paths"] = set(api_diff["files"])
                result["resolved"] = True
                result["reason"] = "github_compare_success"
                
                all_files = len(list(self.base_dir.rglob("*")))
                result["excluded_count"] = max(0, all_files - len(result["include_paths"]))
                return result
        
        # Both methods failed — fail fast for diff mode
        result["resolved"] = False
        result["error"] = "base_unresolvable"
        result["reason"] = "no_available_method"
        
        return result
    
    def _ci_detected(self) -> bool:
        """Detect if running in CI environment."""
        ci_envs = ["GITHUB_ACTIONS", "GITLAB_CI", "CIRCLECI", "TRAVIS"]
        return any(env.upper() in os.environ for env in ci_envs)
    
    async def _git_diff(self, base: str | None) -> dict[str, Any]:
        """Get diff files via git command."""
        try:
            ref = base or "HEAD^"
            cmd = ["git", "-C", str(self.base_dir), "diff", "--name-only", ref]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                return {"success": False, "error": result.stderr}
            
            files = [f.strip() for f in result.stdout.split("\n") if f.strip()]
            return {"success": True, "files": files}
        
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def _github_compare(self, base: str | None) -> dict[str, Any]:
        """Get diff files via GitHub Compare API."""
        if not self.repo_url:
            return {"success": False, "error": "no_repo_url"}
        
        try:
            from urllib.parse import urlparse
            
            parsed = urlparse(self.repo_url)
            owner, repo = parsed.path.strip("/").split("/")[:2]
            
            head = "HEAD"
            base_ref = base or "main"
            
            client = GithubClient()
            url = f"https://api.github.com/repos/{owner}/{repo}/compare/{base_ref}...{head}"
            
            headers = {"Accept": "application/vnd.github+json", "User-Agent": "cyense"}
            token = None  # should be passed in from config
            if token:
                headers["Authorization"] = f"Bearer {token}"
            
            async with httpx.AsyncClient(timeout=30.0) as c:
                resp = await c.get(url, headers=headers)
                
                if resp.status_code != 200:
                    return {"success": False, "error": f"HTTP {resp.status_code}"}
                
                data = resp.json()
                files = [f["filename"] for f in data.get("files", [])]
                return {"success": True, "files": files}
        
        except Exception as e:
            return {"success": False, "error": str(e)}


def calculate_scope_and_filter(
    source_dir: Path,
    include_paths: set[str] | None = None,
) -> tuple[set[str], list[Path]]:
    """Apply diff scope filter to files. Returns (filtered set, file list)."""
    
    if not include_paths:
        return set(source_dir.rglob("*")), list(source_dir.rglob("*"))
    
    filtered_paths = set()
    for path in source_dir.rglob("*"):
        if not path.is_file():
            continue
        
        rel = path.relative_to(source_dir)
        rel_str = str(rel)
        
        if rel_str in include_paths:
            filtered_paths.add(path)
    
    return filtered_paths, list(filtered_paths)
