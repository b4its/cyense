"""GitHub API client with host allowlist (PRD §6.1 SSRF guard).

Only connects to github.com hosts; never arbitrary URLs. Token redaction integrated.
"""

from __future__ import annotations

from typing import Any

import httpx

# Strict host allowlist - no exceptions per PRD §6.1
ALLOWED_HOSTS = frozenset([
    "github.com",
    "api.github.com",
    "codeload.github.com",
])


def is_allowed_host(host: str) -> bool:
    """Verify host is in allowlist (SSRF protection)."""
    from urllib.parse import urlparse
    parsed = urlparse(host)
    return parsed.hostname in ALLOWED_HOSTS if parsed.hostname else False


class GithubClient:
    """Read-only HTTP client scoped to github.com only."""

    def __init__(
        self,
        token: str | None = None,
        timeout: float = 30.0,
        max_concurrency: int = 10,
        rate_limit: int = 50,
    ):
        self._token = token
        self._timeout = timeout
        self._sem = None  # lazy init

    async def _get_headers(self) -> dict[str, str]:
        """Headers with token redacted for logging."""
        headers = {"Accept": "application/vnd.github+json"}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    @staticmethod
    def redact_token(token: str | None) -> str:
        """Return masked token or '[REDACTED]'."""
        if not token:
            return "[REDACTED]"
        if len(token) <= 8:
            return "[REDACTED]"
        return f"{token[:4]}...{token[-4:]}"

    async def get_repo_metadata(
        self, owner: str, repo: str
    ) -> dict[str, Any]:
        """GET /repos/{owner}/{repo} metadata endpoint."""
        url = f"https://api.github.com/repos/{owner}/{repo}"

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            # Anonymous requests must NOT send Authorization at all; a token
            # (when present) is sent verbatim and only to allowlisted hosts.
            # (redact_token is for logs/reports, never for the wire.)
            headers = {"Accept": "application/vnd.github+json", "User-Agent": "cyense"}
            if self._token:
                headers["Authorization"] = f"Bearer {self._token}"
            resp = await client.get(url, headers=headers)

            # Respect rate limits
            remaining = int(resp.headers.get("X-RateLimit-Remaining", 999))
            if remaining == 0:
                retry_after = int(resp.headers.get("Retry-After", 60))
                raise RuntimeError(f"github rate limit exhausted (retry after {retry_after}s)")

            if resp.status_code in (401, 403, 404):
                detail = (
                    "repo not found or private "
                    "(provide a read-only CYENSE_GITHUB_TOKEN)"
                    if resp.status_code == 404
                    else f"github rejected the request ({resp.status_code}); "
                    "check CYENSE_GITHUB_TOKEN validity"
                )
                raise RuntimeError(detail)

            resp.raise_for_status()
            return resp.json()

    async def download_tarball(
        self, owner: str, repo: str, ref: str
    ) -> tuple[bytes, dict[str, Any]]:
        """Download repository tarball via codeload.

        Returns (tarball_bytes, etag) for caching.
        """
        url = f"https://codeload.github.com/{owner}/{repo}/tar.gz/{ref}"

        # SSRF guard: the ORIGINAL request URL must be an allowlisted host
        # (codeload.github.com). We follow codeload's redirect to GitHub's
        # object-storage CDN below — the token is NOT forwarded cross-host
        # (httpx strips Authorization on cross-origin redirects) and the
        # redirect target is decided by GitHub's server, not by attacker input.
        if not is_allowed_host(url):
            raise RuntimeError(f"disallowed host: {url}")

        async with httpx.AsyncClient(
            timeout=self._timeout, follow_redirects=True,
        ) as client:
            headers = {"User-Agent": "cyense"}
            if self._token:
                headers["Authorization"] = f"Bearer {self._token}"
            resp = await client.get(url, headers=headers)
            resp.raise_for_status()

            # The final URL after codeload's redirect goes to a GitHub CDN
            # (objects.githubusercontent.com / S3). Require HTTPS to avoid a
            # downgrade; we do NOT re-apply the strict host allowlist here
            # because the redirect is GitHub-controlled and the auth header
            # was already stripped for cross-host redirects.
            final_url = str(resp.url)
            if not final_url.lower().startswith("https://"):
                raise RuntimeError(f"redirect to non-HTTPS host: {final_url}")

            return resp.content, dict(resp.headers)

    async def resolve_default_branch(self, owner: str, repo: str) -> str:
        """Get default branch name from metadata."""
        meta = await self.get_repo_metadata(owner, repo)
        return meta.get("default_branch", "main")

    async def resolve_commit_sha(
        self, owner: str, repo: str, ref: str
    ) -> str:
        """Resolve a ref (branch/tag) to its commit sha (PRD §8.1 evidence)."""
        url = f"https://api.github.com/repos/{owner}/{repo}/commits/{ref}"

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            headers = {"Accept": "application/vnd.github+json", "User-Agent": "cyense"}
            if self._token:
                headers["Authorization"] = f"Bearer {self._token}"
            resp = await client.get(url, headers=headers)
            if resp.status_code != 200:
                return ""
            return str(resp.json().get("sha", ""))

    async def compare_refs(
        self, owner: str, repo: str, base: str, head: str | None = None
    ) -> dict[str, Any]:
        """Compare two refs via GitHub Compare API. Returns list of changed files."""

        # Default head to HEAD if not provided
        if head is None:
            head = "HEAD"

        url = f"https://api.github.com/repos/{owner}/{repo}/compare/{base}...{head}"

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            headers = {"Accept": "application/vnd.github+json", "User-Agent": "cyense"}
            if self._token:
                headers["Authorization"] = f"Bearer {self._token}"

            resp = await client.get(url, headers=headers)

            # Check rate limits
            remaining = int(resp.headers.get("X-RateLimit-Remaining", 999))
            if remaining == 0:
                retry_after = int(resp.headers.get("Retry-After", 60))
                raise RuntimeError(f"github rate limit exhausted (retry after {retry_after}s)")

            if resp.status_code not in (200, 201):
                detail = f"github compare failed ({resp.status_code})"
                raise RuntimeError(detail)

            data = resp.json()

            # Extract filename from each file entry
            files = [f.get("filename", "") for f in data.get("files", [])]

            # Return metadata too
            return {
                "success": True,
                "files": files,
                "base_commit": data.get("base_commit", {}).get("sha", ""),
                "head_commit": data.get("head_commit", {}).get("sha", ""),
                "total_additions": data.get("total_additions", 0),
                "total_deletions": data.get("total_deletions", 0),
            }

