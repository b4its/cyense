"""🕸️ Crawler agent — BFS website discovery for `scan website` mode.

Starting from a user-provided URL, the crawler fetches same-domain pages,
extracts hyperlinks (href/src/action), and identifies endpoints that carry
numeric ID-like parameters (candidates for IDOR probing).

Design constraints (PRD ethics + safety):
  * Same-domain only (never follows links to third-party hosts)
  * Bounded depth + page count (user-controlled, capped)
  * Rate-limited (respectful of the target)
  * Read-only: only HTTP GET, no form submissions, no mutations
  * Body size cap (100 KB per page) to avoid memory blow-ups
"""

from __future__ import annotations

import asyncio
import re
from typing import Any
from urllib.parse import parse_qs, urljoin, urlparse

import httpx

from app.agents.base import AgentResult, BaseAgent

# Patterns that identify a URL path segment or query value as a numeric ID.
# Restricted to 1..9 digits to avoid matching things like years, zip codes,
# or long hashes.
_ID_SEGMENT_RE = re.compile(r"^\d{1,9}$")
# Common query-param names that typically carry an object id.
_ID_QUERY_RE = re.compile(r"^(id|uid|guid|user_?id|account_?id|.*_id|id_.*)$", re.I)
# Elements we look for when extracting outbound links from HTML.
_HREF_RE = re.compile(r'\bhref\s*=\s*["\']([^"\'#?]+(?:\?[^"\']*)?)["\']', re.I)
_SRC_RE = re.compile(r'\bsrc\s*=\s*["\']([^"\']+)["\']', re.I)
_ACTION_RE = re.compile(r'\baction\s*=\s*["\']([^"\']+)["\']', re.I)

_USER_AGENT = "Cyense/2.1.0 (security scanner; +https://github.com/cyense)"
_BODY_CAP = 200_000  # bytes — keep enough for typical HTML pages


class CrawlerAgent(BaseAgent):
    """BFS crawler that discovers same-domain pages and ID-bearing endpoints."""

    name = "crawler"

    def __init__(
        self,
        scan_id: str,
        reports_dir: str,
        brain: Any = None,
    ) -> None:
        super().__init__(scan_id, reports_dir)
        self.brain = brain  # reserved for future cross-scan site memory

    async def run(self, ctx: dict[str, Any]) -> AgentResult:
        start_url: str = ctx["url"]
        max_depth: int = int(ctx.get("max_depth", 2))
        max_pages: int = int(ctx.get("max_pages", 50))
        rate_limit: int = max(1, int(ctx.get("rate_limit", 10)))
        headers: dict[str, str] = dict(ctx.get("headers") or {})
        cookies: dict[str, str] = dict(ctx.get("cookies") or {})

        parsed_start = urlparse(start_url)
        if parsed_start.scheme not in ("http", "https"):
            return AgentResult(
                agent=self.name, ok=False,
                error=f"unsupported scheme: {parsed_start.scheme!r}",
            )
        domain = parsed_start.netloc

        headers.setdefault("User-Agent", _USER_AGENT)
        headers.setdefault("Accept", "text/html,application/xhtml+xml,application/json,*/*;q=0.8")

        visited: set[str] = set()
        pages: list[dict[str, Any]] = []
        queue: list[tuple[str, int]] = [(start_url, 0)]

        # Rate limiter: cap concurrent in-flight requests AND minimum gap
        # between successive request starts.
        sem = asyncio.Semaphore(min(rate_limit, 8))
        min_interval = 1.0 / rate_limit

        timeout = httpx.Timeout(10.0, connect=5.0)
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            max_redirects=5,
        ) as client:
            last_request_at = 0.0
            while queue and len(pages) < max_pages:
                url, depth = queue.pop(0)
                url = _normalize(url)
                if not url or url in visited:
                    continue

                parsed = urlparse(url)
                if parsed.netloc != domain:
                    continue
                if parsed.scheme not in ("http", "https"):
                    continue

                visited.add(url)

                # Respect rate limit between requests
                async with sem:
                    now = asyncio.get_event_loop().time()
                    wait = last_request_at + min_interval - now
                    if wait > 0:
                        await asyncio.sleep(wait)
                    last_request_at = asyncio.get_event_loop().time()
                    try:
                        resp = await client.get(
                            url, headers=headers, cookies=cookies,
                        )
                    except httpx.HTTPError as exc:
                        self.trajectory.step(
                            "fetch_error", {"url": url, "error": str(exc)},
                        )
                        continue

                # Post-redirect domain check: follow_redirects can land on a
                # third-party host; content from there must not be recorded
                # or analyzed (same-domain-only guarantee).
                final_parsed = urlparse(str(resp.url))
                if final_parsed.netloc != domain:
                    self.trajectory.step(
                        "off_domain_redirect",
                        {"url": url, "final": str(resp.url)},
                    )
                    continue

                page = _record_page(resp, url)
                pages.append(page)
                self.trajectory.step(
                    "fetched",
                    {
                        "url": url,
                        "status": resp.status_code,
                        "bytes": len(page["body"]),
                        "content_type": page["content_type"],
                    },
                )

                # Expand frontier only for HTML pages and while depth allows
                if depth < max_depth and _is_html(page["content_type"]):
                    for link in _extract_links(page["body"]):
                        abs_link = urljoin(url, link)
                        abs_link = _normalize(abs_link)
                        if abs_link and abs_link not in visited:
                            queue.append((abs_link, depth + 1))

        id_endpoints = _find_id_endpoints([p["url"] for p in pages])

        return AgentResult(
            agent=self.name,
            ok=True,
            data={
                "pages": pages,
                "id_endpoints": id_endpoints,
                "domain": domain,
                "visited_count": len(visited),
            },
        )


# ---------------------------------------------------------------------------
# Helpers (module-private)
# ---------------------------------------------------------------------------

def _normalize(url: str) -> str:
    """Drop fragment, collapse redundant whitespace."""
    if not url:
        return ""
    # Remove fragment
    url = url.split("#", 1)[0]
    # Strip surrounding whitespace
    return url.strip()


def _is_html(content_type: str) -> bool:
    return "html" in content_type.lower()


def _record_page(resp: httpx.Response, url: str) -> dict[str, Any]:
    """Convert an httpx response into a bounded page dict."""
    body = resp.text[:_BODY_CAP]
    return {
        "url": str(resp.url) or url,
        "status": resp.status_code,
        "body": body,
        "content_type": resp.headers.get("content-type", ""),
        "headers": {k.lower(): v for k, v in resp.headers.items()},
    }


def _extract_links(html: str) -> list[str]:
    """Pull href/src/action values out of raw HTML (no parser dependency)."""
    links: list[str] = []
    for match in _HREF_RE.finditer(html):
        links.append(match.group(1))
    for match in _SRC_RE.finditer(html):
        links.append(match.group(1))
    for match in _ACTION_RE.finditer(html):
        links.append(match.group(1))
    return links


def _find_id_endpoints(urls: list[str]) -> list[dict[str, Any]]:
    """Identify URLs carrying numeric ID segments or id-like query params."""
    results: list[dict[str, Any]] = []
    seen_templates: set[str] = set()

    for url in urls:
        parsed = urlparse(url)
        path_parts = [p for p in parsed.path.strip("/").split("/") if p]

        # Path-based IDs — only the FIRST numeric segment becomes the {ID}
        # placeholder. Previously every numeric segment was replaced (e.g.
        # "/invoice/5/items/10" → "/invoice/{ID}/items/{ID}") and the prober
        # substituted the SAME id into both, probing a semantically wrong URL.
        id_segments: list[str] = []
        template_parts: list[str] = []
        id_placed = False
        for part in path_parts:
            if not id_placed and _ID_SEGMENT_RE.match(part):
                try:
                    n = int(part)
                    if 1 <= n <= 9_999_999:
                        id_segments.append(part)
                        template_parts.append("{ID}")
                        id_placed = True
                        continue
                except ValueError:
                    pass
            template_parts.append(part)

        # Query-based IDs — keep the ID params in the template with an {ID}
        # placeholder so active probing can target them too. Previously the
        # query was dropped (query="") and the "{ID}" not in template guard
        # silently skipped every query-string ID endpoint.
        query_ids: dict[str, str] = {}
        query_parts: list[str] = []
        for k, v in parse_qs(parsed.query).items():
            if _ID_QUERY_RE.match(k) and v and _ID_SEGMENT_RE.match(v[0]):
                query_ids[k] = v[0]
                query_parts.append(f"{k}={{ID}}")
            elif v:
                query_parts.append(f"{k}={v[0]}")
            else:
                query_parts.append(k)
        query_str = "&".join(query_parts)

        if not id_segments and not query_ids:
            continue

        template_path = "/" + "/".join(template_parts) if template_parts else "/"
        template = parsed._replace(path=template_path, query=query_str).geturl()
        if template in seen_templates:
            continue
        seen_templates.add(template)

        results.append({
            "url": url,
            "template": template,
            "id_segments": id_segments,
            "query_ids": query_ids,
        })

    return results
