"""🐙 Fetcher agent - resolves, fetches, extracts GitHub repos (PRD §3.2).

New agentic capability adding *better tools* to Cyense multi-agent pipeline:
- URL parsing & validation (owner/repo/ref extraction)
- GitHub API metadata resolution
- Secure tarball download + sandbox extraction
- Brain memory integration for same-sha skip
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from app.agents.base import AgentResult, BaseAgent
from app.core.config import settings
from app.utils.github_client import ALLOWED_HOSTS, GithubClient
from app.utils.sandbox import SafeTarExtractor, sanitize_sandbox

# Regex to parse common GitHub link formats (strictly balanced)
# Matches: owner/repo, owner/repo/tree/ref, owner/repo/blob/ref/path
GITHUB_URL_RE = re.compile(
    r"https://github\.com/"
    r"(?P<owner>[^/]+)"  # owner
    r"/(?P<repo>[^/\?#]+)"  # repo (stop at ? or # for query/hash)
    r"(?:/(?:(?:tree|blob)/(?P<ref>[^/\?#]+))?"  # optional tree/blob ref
    r"(?:/(?P<path>[^#\?]*))?)?"  # optional path segment
    r"[?\#]?.*"  # optional query/hash tail
)
TREE_RE = re.compile(r"https://github\.com/(?P<owner>[^/]+)/(?P<repo>[^]+)/tree/(?P<ref>[^/]+)")


def parse_github_url(url: str) -> dict[str, str | None]:
    """Parse GitHub URL variants to {owner, repo, ref, path}."""
    # Direct /owner/repo form
    if url.endswith(".git"):
        url = url[:-4]  # strip .git suffix

    # Ensure valid format (owner/repo required)
    if not url.strip("/").count("/") >= 1:
        raise ValueError(f"invalid github url format: {url}")

    match = GITHUB_URL_RE.match(url) or TREE_RE.match(url)
    if not match:
        raise ValueError(f"invalid github url format: {url}")

    return {
        "owner": match.group("owner"),
        "repo": match.group("repo"),
        "ref": match.group("ref"),
        "path": match.group("path"),
    }


class FetcherAgent(BaseAgent):
    """Fetch GitHub repository into secure sandbox."""

    name = "fetcher"

    def __init__(
        self,
        scan_id: str,
        reports_dir: str,
        brain: Any = None,
    ):
        super().__init__(scan_id, reports_dir)
        self.brain = brain

    async def run(self, ctx: dict[str, Any]) -> AgentResult:
        """Resolve→fetch→extract pipeline."""
        self.trajectory.step("start", {"action": "resolve_repo"})

        try:
            url = ctx["repo_url"]

            # Validate host first (SSRF guard)
            from urllib.parse import urlparse
            parsed = urlparse(url)
            if parsed.hostname not in ALLOWED_HOSTS:
                raise ValueError(f"non-github host rejected ({parsed.hostname})")

            # Parse URL components
            components = parse_github_url(url)
            owner = components["owner"]
            repo = components["repo"]

            self.trajectory.step(
                "parse",
                {"owner": owner, "repo": repo, "ref_hint": components["ref"]},
            )

            # Initialize client with token (redacted internally)
            token = ctx.get("github_token")
            self.trajectory.step(
                "token_check",
                {"present": bool(token), "masked": self._mask_token(token)},
            )

            client = GithubClient(
                token=token,
                timeout=settings.github_timeout,
            )

            # Determine ref (user-provided or resolve from API)
            ref = ctx.get("ref")
            if not ref:
                self.trajectory.step("api_resolve_ref")
                default_branch = await client.resolve_default_branch(owner, repo)
                ref = default_branch

            self.trajectory.step("ref_resolved", {"ref": ref})

            # Brain cache check (skip if already scanned at this sha)
            if not ctx.get("force", False) and self.brain:
                cached_data = self.brain.get_repo_cache(owner, repo, ref, "")
                if cached_data["hit"]:
                    self.trajectory.step("cache_hit", {"ref": ref})
                    # Return cached result info (sha from cache)
                    return AgentResult(agent=self.name, ok=True, data={
                        "cached": True,
                        "sha": cached_data["data"].get("sha", ""),
                        "url": url,
                        "owner": owner,
                        "repo": repo,
                    })

            # Get metadata first (check size before downloading)
            self.trajectory.step("get_metadata")
            meta_data = await client.get_repo_metadata(owner, repo)

            # Size guard before any download
            size_kb = meta_data.get("size", 0) * 1024
            max_bytes = settings.github_max_mb * 1024 * 1024
            if size_kb > max_bytes:
                raise RuntimeError(f"repo too large ({size_kb:,} bytes > {max_bytes:,})")

            self.trajectory.step(
                "metadata_ok",
                {"size_kb": size_kb, "default_branch": meta_data.get("default_branch")},
            )

            # Resolve the exact commit sha for the ref (reproducibility evidence)
            commit_sha = await client.resolve_commit_sha(owner, repo, ref)
            self.trajectory.step("sha_resolved", {"sha": commit_sha[:8] or "unknown"})

            # Download tarball
            self.trajectory.step("download_tarball")
            tar_content, etag = await client.download_tarball(owner, repo, ref)

            self.trajectory.step("tarball_downloaded", {"bytes": len(tar_content)})

            # Create sandbox directory
            sandbox_path = Path(self.reports_dir) / self.scan_id / "src"

            # Extract with guards (wrap bytes in BytesIO for tarfile)
            import io as _io
            extractor = SafeTarExtractor(
                dest=sandbox_path,
                max_bytes=max_bytes,
                max_files=settings.github_max_files,
            )

            try:
                extractor.extract_stream(_io.BytesIO(tar_content))
            except Exception:
                sanitize_sandbox(sandbox_path)
                raise  # re-raise with cleanup

            self.trajectory.step("extracted_ok", {"sandbox": str(sandbox_path)})

            # Collect file stats
            files_kept = list(sandbox_path.rglob("*"))
            files_kept = [f for f in files_kept if f.is_file()]
            bytes_total = sum(f.stat().st_size for f in files_kept)

            result = {
                "ok": True,
                "owner": owner,
                "repo": repo,
                "ref": ref,
                "sha": commit_sha or meta_data.get("sha", ""),
                "size_bytes": bytes_total,
                "files_count": len(files_kept),
                "tree_root": str(sandbox_path),
                "cached": False,
            }

            self.trajectory.step("complete", result)
            return AgentResult(agent=self.name, ok=True, data=result)

        except Exception as exc:
            self.log.error("fetcher failed: %s", exc)
            self.trajectory.step("error", {"exception": str(exc)})
            return AgentResult(agent=self.name, ok=False, error=str(exc))

    @staticmethod
    def _mask_token(token: str | None) -> str:
        """Mask token for trajectory logging."""
        if not token:
            return "[none]"
        if len(token) <= 8:
            return "[REDACTED]"
        return f"{token[:4]}...{token[-4:]}"
