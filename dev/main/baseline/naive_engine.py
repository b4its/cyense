"""Baseline naive engine (PRD v2.0 §7.2) — the comparison point.

Strategy: fire all candidate ids and report every 200 response whose body
resembles the baseline. NO fingerprinting, NO verification, NO control-id
check — exactly the false-positive-prone behaviour Cyense improves upon.
Same task, same eval cases, same rate limit / concurrency budget.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any

from app.utils.http_client import HttpClient
from app.utils.redact import redact_headers
from app.utils.similarity import similarity

PLACEHOLDER_RE = re.compile(r"\{[A-Za-z_][A-Za-z0-9_]*\}")


async def run_naive_scan(
    url_template: str,
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
    baseline_id: str | None = None,
    probe_ids: list[str] | None = None,
    timeout: float = 10.0,
    rate_limit: int = 50,
    max_concurrency: int = 10,
    similarity_threshold: float = 0.85,
) -> dict[str, Any]:
    headers = headers or {}
    cookies = cookies or {}

    async with HttpClient(
        timeout=timeout,
        headers=headers,
        cookies=cookies,
        rate_limit=rate_limit,
        max_concurrency=max_concurrency,
    ) as client:
        # reference shape from any reachable id (naive: no permission nuance)
        reference_body = ""
        seed = baseline_id or (probe_ids[0] if probe_ids else "1")
        resp0 = await client.get(PLACEHOLDER_RE.sub(seed, url_template))
        if resp0.status == 200:
            reference_body = resp0.body

        ids = probe_ids or [str(i) for i in range(1, 51)]
        tasks = [_fire(client, PLACEHOLDER_RE.sub(pid, url_template), pid, reference_body)
                 for pid in ids]
        results = await asyncio.gather(*tasks)

    # naive reporting: every 200 that looks like an object payload
    findings = []
    for pid, status, sim, body, resp_headers, url in results:
        if status != 200:
            continue
        if reference_body and sim < similarity_threshold:
            continue
        findings.append(
            {
                "probe_id": pid,
                "url": url,
                "status": status,
                "similarity": round(sim, 3),
                "severity": "high",  # naive: everything looks high
                "confidence": 0.5,
                "evidence_headers": redact_headers(resp_headers),
                "body_snippet": body[:400],
                "verification": {"notes": "naive engine: no verification performed"},
            }
        )
    return {
        "meta": {"mode": "link", "engine": "baseline"},
        "summary": {"total": len(findings)},
        "findings": findings,
    }


async def _fire(
    client: HttpClient, url: str, pid: str, reference_body: str
) -> tuple[str, int, float, str, dict[str, str], str]:
    resp = await client.get(url)
    sim = similarity(resp.body, reference_body) if reference_body else 0.0
    return pid, resp.status, sim, resp.body, resp.headers, url
