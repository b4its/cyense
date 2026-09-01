"""Domain scan engine — enumerate subdomains then scan every live host.

Orchestrates a full-domain assessment:
  1. Normalize the target domain (strip scheme/www, lowercase).
  2. Enumerate subdomains passively (Wayback Machine corpus) and actively
     (common prefixes via DNS).
  3. For each live host (capped by ``max_hosts``), run the standard website
     pipeline (crawl → tech → port → CVE → discovery → probe → SQLi) by
     delegating to :class:`WebsiteEngine`.
  4. Aggregate all findings across hosts, each tagged with the ``host`` in
     evidence, plus a per-host summary table.

Read-only throughout; failures on individual hosts never fail the whole
domain scan.
"""

from __future__ import annotations

import time
from typing import Any
from urllib.parse import urlparse

from app.engines.website_engine import WebsiteEngine
from app.utils.discovery import (
    COMMON_SUBDOMAINS,
    discover_subdomains,
    extract_subdomains_from_urls,
    fetch_wayback_urls,
)
from app.utils.logger import get_logger

log = get_logger("engine.domain")

# Well-known registrable-domain suffixes — "example.co.uk" → base "example.co.uk".
_PUBLIC_SUFFIXES = (
    "co.uk", "org.uk", "ac.uk", "gov.uk", "co.id", "or.id", "go.id",
    "ac.id", "co.jp", "ne.jp", "or.jp", "com.au", "net.au", "org.au",
    "co.nz", "net.nz", "org.nz", "com.br", "com.mx", "com.sg", "com.hk",
    "com.tr", "co.in", "co.za", "co.kr", "com.cn", "com.tw", "com.my",
)


def normalize_domain(domain: str) -> str:
    """Return the registrable base domain for a hostname/URL input.

    ``https://www.example.com/path`` → ``example.com``
    ``sub.example.co.uk`` → ``example.co.uk``
    """
    domain = domain.strip().lower()
    if "://" in domain:
        domain = urlparse(domain).hostname or domain
    domain = domain.split("/")[0].split(":")[0].rstrip(".")
    if domain.startswith("www."):
        domain = domain[4:]
    parts = domain.split(".")
    if len(parts) <= 2:
        return domain
    # Keep the longest public suffix + one label before it.
    for suffix in _PUBLIC_SUFFIXES:
        sfx = suffix.split(".")
        if parts[-len(sfx):] == sfx and len(parts) > len(sfx):
            return ".".join(parts[-(len(sfx) + 1):])
    return ".".join(parts[-2:])


class DomainEngine:
    """Scan an entire domain: enumerate subdomains + per-host website scans."""

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
            except Exception:  # noqa: BLE001
                pass

    async def run(
        self,
        domain: str,
        max_hosts: int = 20,
        max_depth: int = 1,
        max_pages: int = 20,
        rate_limit: int = 10,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        started = time.monotonic()
        base_domain = normalize_domain(domain)
        headers = dict(headers or {})
        cookies = dict(cookies or {})

        if not base_domain or "." not in base_domain:
            return _empty_report(
                self.scan_id, started, domain,
                f"domain tidak valid: {domain!r}",
            )

        # ------------------------------------------------------------------
        # 1. Enumerate subdomains (passive wayback + active DNS prefixes).
        # ------------------------------------------------------------------
        await self._notify("enumerate")
        hosts: set[str] = {base_domain}
        try:
            wb_urls = await fetch_wayback_urls(base_domain)
            for sub in extract_subdomains_from_urls(wb_urls, base_domain):
                hosts.add(sub)
        except Exception as exc:  # noqa: BLE001
            log.warning("wayback enumeration failed: %s", exc)

        try:
            for sub in await discover_subdomains(base_domain, COMMON_SUBDOMAINS):
                hosts.add(sub)
        except Exception as exc:  # noqa: BLE001
            log.warning("DNS enumeration failed: %s", exc)

        host_list = sorted(hosts)[: max_hosts]
        log.info(
            "domain scan: %s → %d hosts discovered (cap %d)",
            base_domain, len(hosts), max_hosts,
        )

        # ------------------------------------------------------------------
        # 2. Scan each live host with the full website pipeline.
        # ------------------------------------------------------------------
        per_host: list[dict[str, Any]] = []
        all_findings: list[dict[str, Any]] = []
        await self._notify("hosts")
        for i, host in enumerate(host_list, start=1):
            await self._notify("host")
            log.info("scanning host %d/%d: %s", i, len(host_list), host)
            try:
                engine = WebsiteEngine(
                    scan_id=f"{self.scan_id}-h{i}",
                    brain=self.brain,
                    reports_dir=self.reports_dir,
                    settings=self.settings,
                )
                host_report = await engine.run(
                    url=f"http://{host}",
                    max_depth=max_depth,
                    max_pages=max_pages,
                    rate_limit=rate_limit,
                    headers=headers,
                    cookies=cookies,
                )
                host_error = (host_report.get("meta") or {}).get("error")
            except Exception as exc:  # noqa: BLE001 — one host must not fail all
                log.warning("host scan failed for %s: %s", host, exc)
                per_host.append({
                    "host": host,
                    "status": "failed",
                    "error": str(exc),
                    "findings_count": 0,
                })
                continue

            findings = host_report.get("findings", [])
            for f in findings:
                f = dict(f)
                f["evidence"] = dict(f.get("evidence") or {})
                f["evidence"]["host"] = host
                f["host"] = host
                all_findings.append(f)

            summary = host_report.get("summary", {})
            per_host.append({
                "host": host,
                "status": "failed" if host_error else "completed",
                "error": host_error,
                "findings_count": len(findings),
                "summary": summary,
            })

        # ------------------------------------------------------------------
        # 3. Aggregate.
        # ------------------------------------------------------------------
        await self._notify("report")
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in all_findings:
            sev = f.get("severity", "info")
            if sev in sev_counts:
                sev_counts[sev] += 1

        summary = {
            "total": len(all_findings),
            **sev_counts,
            "domain": base_domain,
            "hosts_discovered": len(hosts),
            "hosts_scanned": len(host_list),
            "hosts_completed": sum(
                1 for h in per_host if h.get("status") == "completed"
            ),
            "duration_ms": int((time.monotonic() - started) * 1000),
        }

        all_findings.sort(key=lambda f: (
            _sev_rank(f.get("severity", "info")),
            -(f.get("confidence") or 0.0),
        ))
        return {
            "meta": {
                "scan_id": self.scan_id,
                "mode": "domain",
                "engine": "domain-orchestrator",
                "pipeline": ["enumerate", "hosts", "host", "report"],
                "domain": base_domain,
            },
            "summary": summary,
            "findings": all_findings,
            "hosts": per_host,
        }


_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _sev_rank(sev: str) -> int:
    return _SEV_ORDER.get(str(sev).lower(), 5)


def _empty_report(
    scan_id: str,
    started: float,
    domain: str,
    error: str,
) -> dict[str, Any]:
    return {
        "meta": {
            "scan_id": scan_id,
            "mode": "domain",
            "engine": "domain-orchestrator",
            "pipeline": ["enumerate"],
            "domain": domain,
            "error": error,
        },
        "summary": {
            "total": 0, "critical": 0, "high": 0, "medium": 0,
            "low": 0, "info": 0,
            "hosts_discovered": 0, "hosts_scanned": 0,
            "hosts_completed": 0,
            "duration_ms": int((time.monotonic() - started) * 1000),
        },
        "findings": [],
        "hosts": [],
    }
