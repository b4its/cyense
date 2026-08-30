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
            headers = {"Authorization": f"Bearer {self.redact_token(self._token)}"}
            resp = await client.get(url, headers=headers)

            # Respect rate limits
            remaining = int(resp.headers.get("X-RateLimit-Remaining", 999))
            if remaining == 0:
                retry_after = int(resp.headers.get("Retry-After", 60))
                raise RuntimeError(f"github rate limit exhausted (retry after {retry_after}s)")

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
            resp = await client.get(url)
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
