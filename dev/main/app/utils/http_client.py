"""httpx async client with rate limiting and retries (PRD v2.0 §5.2).

Read-only discipline: the client only issues GET/HEAD/OPTIONS/TRACE
(PRD §2.2 non-goals: no auto-exploit that mutates data). OPTIONS and TRACE are
non-mutating and are used only for HTTP-method auditing (A05) — e.g. detecting
TRACE (XST) and unexpected PUT/DELETE/PATCH verbs via the Allow header. POST,
PUT, PATCH and DELETE remain rejected.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field

import httpx

from app.utils.logger import get_logger
from app.utils.redact import redact_url_credentials

log = get_logger("http")


@dataclass
class Response:
    status: int
    headers: dict[str, str]
    body: str
    elapsed_ms: int
    url: str

    @property
    def blocked(self) -> bool:
        return self.status in (401, 403) or 300 <= self.status < 400


@dataclass
class HttpClient:
    timeout: float = 10.0
    rate_limit: int = 50
    max_concurrency: int = 10
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self._client: httpx.AsyncClient | None = None
        self._sem = asyncio.Semaphore(self.max_concurrency)
        self._min_interval = 1.0 / max(self.rate_limit, 1)
        self._last_request = 0.0
        # Serialize pacing so concurrent requests don't all fire at once:
        # without this, N concurrent _pace() calls computed the same wait and
        # stamped the same _last_request, delivering a burst instead of a
        # steady rate limit.
        self._pace_lock = asyncio.Lock()

    async def __aenter__(self) -> HttpClient:
        self._client = httpx.AsyncClient(
            timeout=self.timeout,
            headers=self.headers,
            cookies=self.cookies,
            follow_redirects=False,
        )
        return self

    async def __aexit__(self, *exc: object) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _pace(self) -> None:
        async with self._pace_lock:
            now = time.monotonic()
            wait = self._last_request + self._min_interval - now
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_request = time.monotonic()

    async def request(self, method: str, url: str) -> Response:
        """Issue a read-only request. Mutating methods are rejected.

        Allowed: GET, HEAD (standard read-only) plus OPTIONS, TRACE which are
        non-mutating and used for HTTP-method auditing (A05). POST/PUT/PATCH/
        DELETE are rejected (PRD §2.2 non-goals).
        """
        method = method.upper()
        if method not in ("GET", "HEAD", "OPTIONS", "TRACE"):
            raise ValueError(f"method {method} not allowed (read-only probing)")
        if self._client is None:
            raise RuntimeError("client not started; use 'async with'")
        async with self._sem:
            await self._pace()
            start = time.monotonic()
            try:
                resp = await self._client.request(method, url)
            except httpx.HTTPError as exc:
                # redact_url_credentials — wrapping the URL under a non-
                # sensitive key ("u") let embedded user:pass@ credentials
                # through verbatim (ground rule #8).
                log.warning("request failed %s: %s", redact_url_credentials(url), exc)
                return Response(
                    status=0,
                    headers={},
                    body="",
                    elapsed_ms=int((time.monotonic() - start) * 1000),
                    url=url,
                )
            body = "" if method == "HEAD" else resp.text
            return Response(
                status=resp.status_code,
                headers={k.lower(): v for k, v in resp.headers.items()},
                body=body,
                elapsed_ms=int((time.monotonic() - start) * 1000),
                url=str(resp.url),
            )

    async def get(self, url: str) -> Response:
        return await self.request("GET", url)

    async def head(self, url: str) -> Response:
        return await self.request("HEAD", url)
