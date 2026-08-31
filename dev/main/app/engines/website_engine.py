"""Website scan engine — orchestrates crawl + IDOR discovery + live XSS analysis.

Pipeline (mode WEBSITE):  Crawl → Probe-IDOR → Analyze-XSS → Report

The engine is entirely **read-only** and deterministic (no LLM). It reuses:
  * :class:`app.agents.crawler.CrawlerAgent` for site discovery
  * :func:`app.engines.live_xss.analyze_page_xss` for live XSS surface checks
  * The existing Prober + Verifier stack for IDOR confirmation on endpoints
    the crawler flagged as ID-bearing (optional, capped per scan)

Findings are reported with rule ids:
  * ``IDOR-WEBSITE``     — ID-bearing endpoint discovered (low confidence probe)
  * ``IDOR-WEBSITE-HIT`` — Prober/Verifier confirmed cross-account IDOR
  * ``XS-LIVE-*``        — Live XSS surface findings (see live_xss.py)
"""

from __future__ import annotations

import time
from typing import Any

from app.agents.crawler import CrawlerAgent
from app.engines.live_xss import analyze_page_xss
from app.utils.logger import get_logger

log = get_logger("engine.website")

# Cap how many ID-bearing endpoints we actively probe per scan so a large
# site does not cause unbounded probing. Discovery-only findings (no probe)
# are still reported for ALL discovered endpoints.
_MAX_PROBED_ENDPOINTS = 10


class WebsiteEngine:
    """Orchestrate website-scan pipeline with brain + stage callbacks."""

    def __init__(
        self,
        scan_id: str,
        brain: Any,
        reports_dir: str,
        settings: Any,
        on_stage: Any | None = None,
    ) -> None:
        self.scan_id = scan_id
        self.brain = brain
        self.reports_dir = reports_dir
        self.settings = settings
        self._on_stage = on_stage

    async def _notify(self, stage: str) -> None:
        if self._on_stage is not None:
            try:
                await self._on_stage(stage)
            except Exception:  # stage reporting must never break a scan
                pass

    async def run(
        self,
        url: str,
        max_depth: int = 2,
        max_pages: int = 50,
        rate_limit: int = 10,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        started = time.monotonic()
        headers = dict(headers or {})
        cookies = dict(cookies or {})

        # ------------------------------------------------------------------
        # Stage 1: Crawl
        # ------------------------------------------------------------------
        await self._notify("crawl")
        crawler = CrawlerAgent(self.scan_id, self.reports_dir, brain=self.brain)
        crawl_result = await crawler({
            "url": url,
            "max_depth": max_depth,
            "max_pages": max_pages,
            "rate_limit": rate_limit,
            "headers": headers,
            "cookies": cookies,
        })
        if not crawl_result.ok:
            return self._empty_report(
                f"crawl failed: {crawl_result.error}", started, url,
            )

        pages = crawl_result.data.get("pages", [])
        id_endpoints = crawl_result.data.get("id_endpoints", [])
        domain = crawl_result.data.get("domain", "")

        # ------------------------------------------------------------------
        # Stage 2: IDOR probing on discovered ID-bearing endpoints
        # ------------------------------------------------------------------
        await self._notify("probe")
        idor_findings: list[dict[str, Any]] = []

        # Discovery-only findings for EVERY ID endpoint (cheap, informational).
        for i, ep in enumerate(id_endpoints, start=1):
            idor_findings.append({
                "finding_id": f"{self.scan_id}-WIDOR{i:03d}",
                "rule": "IDOR-WEBSITE",
                "severity": "medium",
                "confidence": 0.45,
                "title": (
                    f"ID-bearing endpoint discovered: {ep['template']}"
                ),
                "description": (
                    "Crawler found an endpoint with numeric ID parameter(s). "
                    "These are common IDOR surfaces and should be manually "
                    "verified or probed with cross-account credentials."
                ),
                "evidence": {
                    "url": ep["url"],
                    "template": ep["template"],
                    "path_ids": ep.get("id_segments", []),
                    "query_ids": ep.get("query_ids", {}),
                },
                "remediation": (
                    "Add server-side authorization checks that verify the "
                    "authenticated user owns the requested object before "
                    "returning it."
                ),
                "location": ep["url"],
            })

        # Optional active probing via Prober + Verifier (best-effort). If it
        # fails (no credentials, weird endpoint shape, etc.) we keep the
        # discovery-only findings without failing the whole scan.
        probed: list[dict[str, Any]] = []
        if id_endpoints:
            probed = await self._probe_id_endpoints(
                id_endpoints[:_MAX_PROBED_ENDPOINTS],
                headers=headers,
                cookies=cookies,
            )
            # Merge confirmed IDOR findings
            for j, f in enumerate(probed, start=len(idor_findings) + 1):
                f["finding_id"] = f"{self.scan_id}-WIDOR{j:03d}"
                f["rule"] = "IDOR-WEBSITE-HIT"
                idor_findings.append(f)

        # ------------------------------------------------------------------
        # Stage 3: XSS analysis on every fetched HTML page
        # ------------------------------------------------------------------
        await self._notify("analyze")
        xss_findings: list[dict[str, Any]] = []
        for page in pages:
            page_findings = analyze_page_xss(page)
            for k, f in enumerate(page_findings, start=len(xss_findings) + 1):
                f["finding_id"] = f"{self.scan_id}-WXSS{k:03d}"
                xss_findings.append(f)

        # ------------------------------------------------------------------
        # Stage 4: Report
        # ------------------------------------------------------------------
        await self._notify("report")
        all_findings = idor_findings + xss_findings
        all_findings.sort(
            key=lambda f: (
                _severity_rank(f.get("severity", "info")),
                -float(f.get("confidence", 0.0)),
            ),
        )

        summary = {
            "total": len(all_findings),
            "critical": sum(1 for f in all_findings if f.get("severity") == "critical"),
            "high": sum(1 for f in all_findings if f.get("severity") == "high"),
            "medium": sum(1 for f in all_findings if f.get("severity") == "medium"),
            "low": sum(1 for f in all_findings if f.get("severity") == "low"),
            "info": sum(1 for f in all_findings if f.get("severity") == "info"),
            "pages_crawled": len(pages),
            "id_endpoints_found": len(id_endpoints),
            "id_endpoints_probed": len(probed),
            "domain": domain,
            "duration_ms": int((time.monotonic() - started) * 1000),
        }

        return {
            "meta": {
                "scan_id": self.scan_id,
                "mode": "website",
                "engine": "website-crawler",
                "pipeline": ["crawl", "probe", "analyze", "report"],
                "url": url,
            },
            "summary": summary,
            "findings": all_findings,
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    async def _probe_id_endpoints(
        self,
        endpoints: list[dict[str, Any]],
        *,
        headers: dict[str, str],
        cookies: dict[str, str],
    ) -> list[dict[str, Any]]:
        """Best-effort active probing of ID-bearing endpoints.

        We synthesize a link-mode probe for each endpoint by substituting a
        baseline ID (the one the crawler observed) with 2–3 sibling IDs and
        running the standard Prober + Verifier stack. Any confirmed cross-
        account hit is returned as a finding dict.

        Failures on individual endpoints are logged and skipped — they do
        NOT fail the whole scan.
        """
        from app.agents.prober import ProberAgent
        from app.agents.recon import ReconAgent
        from app.agents.verifier import VerifierAgent

        confirmed: list[dict[str, Any]] = []
        for ep in endpoints:
            template = ep.get("template", "")
            baseline = None
            # Pick the first path-based ID as the baseline
            for seg in ep.get("id_segments", []):
                if seg:
                    baseline = seg
                    break
            if baseline is None:
                # Fall back to the first query ID value
                for v in ep.get("query_ids", {}).values():
                    if v:
                        baseline = v
                        break
            if not baseline or not template or "{ID}" not in template:
                continue

            try:
                url = template.replace("{ID}", baseline)
                base_ctx = {
                    "url": url,
                    "headers": headers,
                    "cookies": cookies,
                    "timeout": self.settings.request_timeout,
                    "rate_limit": self.settings.rate_limit,
                    "max_concurrency": self.settings.max_concurrency,
                    "probe_max": min(self.settings.probe_max, 5),
                    "similarity_threshold": self.settings.similarity_threshold,
                    "verify_retries": self.settings.verify_retries,
                    "control_id": self.settings.control_id,
                    "method": "GET",
                    "probe_ids": None,
                }

                recon = ReconAgent(self.scan_id, self.reports_dir, brain=self.brain)
                recon_res = await recon(base_ctx)
                if not recon_res.ok:
                    continue

                probe_ctx = dict(base_ctx)
                probe_ctx["profile"] = recon_res.data["profile"]
                probe_ctx["baseline_body"] = recon_res.data.get("baseline_body", "")
                prober = ProberAgent(self.scan_id, self.reports_dir, brain=self.brain)
                probe_res = await prober(probe_ctx)
                if not probe_res.ok:
                    continue

                verify_ctx = dict(base_ctx)
                verify_ctx["profile"] = recon_res.data["profile"]
                verify_ctx["baseline_body"] = recon_res.data.get("baseline_body", "")
                verify_ctx["hits_internal"] = probe_res.data.get("hits_internal", [])
                verifier = VerifierAgent(self.scan_id, self.reports_dir)
                verify_res = await verifier(verify_ctx)
                if not verify_res.ok:
                    continue

                for hit in verify_res.data.get("findings", []):
                    confirmed.append({
                        "severity": hit.get("severity", "high"),
                        "confidence": hit.get("confidence", 0.8),
                        "title": (
                            f"IDOR on {ep['template']} via probe "
                            f"id '{hit.get('probe_id', '?')}'"
                        ),
                        "description": (
                            f"Endpoint returned object data for foreign id "
                            f"'{hit.get('probe_id', '?')}' (HTTP "
                            f"{hit.get('status', '?')})."
                        ),
                        "evidence": {
                            "request": {
                                "method": "GET",
                                "url": hit.get("url", ""),
                            },
                            "response": {
                                "status": hit.get("status"),
                                "body_snippet": hit.get("body_snippet", ""),
                            },
                        },
                        "verification": hit.get("verification", {}),
                        "remediation": (
                            "Add server-side authorization checks that verify "
                            "the authenticated user owns the requested object."
                        ),
                        "location": hit.get("url", ep["url"]),
                    })
            except Exception as exc:  # noqa: BLE001 — defensive
                log.warning("probe failed for %s: %s", ep.get("url"), exc)
                continue

        return confirmed

    @staticmethod
    def _empty_report(
        error: str, started: float, url: str,
    ) -> dict[str, Any]:
        return {
            "meta": {
                "scan_id": "",
                "mode": "website",
                "engine": "website-crawler",
                "pipeline": ["crawl"],
                "url": url,
                "error": error,
            },
            "summary": {
                "total": 0,
                "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
                "pages_crawled": 0,
                "id_endpoints_found": 0,
                "id_endpoints_probed": 0,
                "duration_ms": int((time.monotonic() - started) * 1000),
            },
            "findings": [],
        }


_SEV_RANK = {
    "critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4,
}


def _severity_rank(sev: str) -> int:
    return _SEV_RANK.get(str(sev).lower(), 5)
