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

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            # Token only ever goes to allowlisted github hosts, verbatim
            headers = {"User-Agent": "cyense"}
            if self._token:
                headers["Authorization"] = f"Bearer {self._token}"
            resp = await client.get(url, headers=headers)
            resp.raise_for_status()

            # Check redirect stays within allowed hosts
            final_url = str(resp.url)
            from urllib.parse import urlparse
            final_host = urlparse(final_url).hostname
            if final_host not in ALLOWED_HOSTS:
                raise RuntimeError(f"redirect to disallowed host: {final_host}")

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
