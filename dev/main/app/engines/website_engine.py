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

import asyncio
import re
import time
from typing import Any

from app.agents.crawler import CrawlerAgent
from app.engines.live_sqli import SQLI_PAYLOADS, detect_sql_errors, is_boolean_differential
from app.engines.live_xss import analyze_page_xss
from app.utils.cve_lookup import (
    cves_trigger_idor,
    cves_trigger_xss,
    lookup_cves,
    techs_trigger_idor,
    techs_trigger_xss,
)
from app.utils.cve_search import merge_cves, search_cves_online
from app.utils.framework_detection import detect_technologies
from app.utils.http_client import HttpClient
from app.utils.logger import get_logger
from app.utils.port_scanner import host_from_url, scan_ports

log = get_logger("engine.website")

# Cap how many ID-bearing endpoints we actively probe per scan so a large
# site does not cause unbounded probing. Discovery-only findings (no probe)
# are still reported for ALL discovered endpoints.
_MAX_PROBED_ENDPOINTS = 10
# Safety caps for XSS payload probe requests.
_MAX_XSS_PROBE_REQUESTS = 100


def _evidence_sample(body: str, marker: str, radius: int = 40, limit: int = 200) -> str:
    """Slice a short evidence window from an HTTP body around `marker`.

    Error-based SQLi responses usually dump a DB error that echoes the query,
    not the payload itself, so ``body.find(payload)`` returns -1 and the naive
    ``body[-1+160:...]`` slice capture was actually the page header boilerplate.
    Prefer the marker; when absent, sample from the start capped at `limit`.
    """
    idx = body.find(marker)
    if idx == -1:
        return body[:limit]
    start = max(idx - radius, 0)
    return body[start : idx + radius + limit][:limit]

# XSS payload vectors for active reflection confirmation.
# (payload, context_label, severity)
_XSS_PAYLOADS: list[tuple[str, str, str]] = [
    ("<img src=x onerror=alert(1)>",     "html-img-onerror", "high"),
    ("<svg onload=alert(1)>",            "html-svg-onload",  "high"),
    ("\"><script>alert(1)</script>",     "attr-script",      "critical"),
    ("'onfocus=alert(1) autofocus=",     "attr-singlequote", "high"),
    ("<script>alert(1)</script>",        "raw-script",       "critical"),
    ("'-alert(1)-'",                     "script-breakout",  "high"),
    ("\"><img src=x onerror=alert(1)>",  "attr-img-onerror", "critical"),
    ("'><script>alert(1)</script>",      "sq-attr-script",   "high"),
    ("</script><script>alert(1)</script>","script-close",    "high"),
    ("/\"'<>CyenseXSS",                  "universal-marker", "medium"),
]


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
        skip_port_scan: bool = False,
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
        # Stage 2: Technology/Framework Detection
        # ------------------------------------------------------------------
        await self._notify("analyze")
        tech_findings: list[dict[str, Any]] = []
        for page in pages:
            header_dict = dict(page.get("headers", {}))
            page_technologies = detect_technologies(
                url=page.get("url", ""),
                headers=header_dict,
                body=page.get("body"),
            )
            for k, f in enumerate(page_technologies, start=len(tech_findings) + 1):
                f["finding_id"] = f"{self.scan_id}-WTECH{k:03d}"
                tech_findings.append(f)

        # ------------------------------------------------------------------
        # Stage 2b: Open port scan (nmap-style TCP connect) on the target host
        # ------------------------------------------------------------------
        await self._notify("port-scan")
        port_findings: list[dict[str, Any]] = []
        open_ports_data: list[dict[str, Any]] = []
        if not skip_port_scan:
            try:
                target_host = host_from_url(url)
                port_scan = await scan_ports(
                    target_host,
                    timeout=float(getattr(self.settings, "port_scan_timeout", 1.5)),
                    max_concurrency=int(getattr(self.settings, "port_scan_concurrency", 50)),
                    banner=True,
                )
                open_ports_data = port_scan.open_ports
                port_findings = self._port_scan_findings(port_scan, url)
                for k, f in enumerate(port_findings, start=1):
                    f["finding_id"] = f"{self.scan_id}-PPORT{k:03d}"
            except Exception as exc:  # noqa: BLE001 — port scan must never fail scan
                log.warning("port scan failed for %s: %s", url, exc)

        # ------------------------------------------------------------------
        # Stage 2c: CVE lookup — match detected tech + open ports to known CVEs,
        # and decide whether to activate the XSS / IDOR scanners.
        # ------------------------------------------------------------------
        await self._notify("cve")
        cve_findings, xss_relevant, idor_relevant = await self._cve_lookup_stage(
            self.scan_id, tech_findings, open_ports_data, url,
        )
        log.info(
            "cve stage: %d tech, %d ports → %d CVEs; xss_relevant=%s idor_relevant=%s",
            len(tech_findings), len(open_ports_data), len(cve_findings),
            xss_relevant, idor_relevant,
        )

        # ------------------------------------------------------------------
        # Stage 2d: Discovery (adaptation of HackerOne 104 tools)
        #   * TruffleHog/Shhgit → secret scanning on crawled content
        #   * Jsluice/js-link-finder → URL extraction from JS
        #   * Nikto/Dirsearch → sensitive path checks
        #   * Arjun → hidden parameter discovery (capped)
        # ------------------------------------------------------------------
        await self._notify("discovery")
        discovery_findings = await self._discovery_stage(
            pages, url, headers, cookies,
        )
        log.info(
            "discovery stage: %d findings",
            len(discovery_findings),
        )

        # ------------------------------------------------------------------
        # Stage 3: IDOR probing (active, gated on endpoints or IDOR signals)
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

        # Active probing via Prober + Verifier — only when the crawler found
        # ID-bearing endpoints to probe. (idor_relevant still reflects the
        # tech/CVE IDOR signal, but probing needs concrete endpoints; the old
        # fallback re-derived id_endpoints from the same pages and always
        # returned [] — dead code.)
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
        # Stage 4: XSS analysis — passive always; active probes gated on
        # XSS-prone technology / XSS CVE signal.
        # ------------------------------------------------------------------
        has_html = any(
            "html" in (p.get("content_type") or "").lower() for p in pages
        )
        xss_findings: list[dict[str, Any]] = []
        for page in pages:
            page_findings = analyze_page_xss(page)
            for k, f in enumerate(page_findings, start=len(xss_findings) + 1):
                f["finding_id"] = f"{self.scan_id}-WXSS{k:03d}"
                xss_findings.append(f)

        if has_html and (xss_relevant or _pages_have_query_params(pages)):
            # Active (read-only + benign) reflection check.
            reflected = await self._probe_reflected_xss(
                pages, headers=headers, cookies=cookies,
            )
            for k, f in enumerate(reflected, start=len(xss_findings) + 1):
                f["finding_id"] = f"{self.scan_id}-WXSS{k:03d}"
                xss_findings.append(f)

            # Active XSS payload injection probe (read-only, non-destructive).
            xss_payload_findings = await self._probe_xss_payloads(
                pages, headers=headers, cookies=cookies,
            )
            for k, f in enumerate(xss_payload_findings, start=len(xss_findings) + 1):
                f["finding_id"] = f"{self.scan_id}-WXSS{k:03d}"
                xss_findings.append(f)

            # Active SSTI/EL + CRLF injection-signature probe (read-only).
            inj_findings = await self._probe_injection_signatures(
                pages, headers=headers, cookies=cookies,
            )
            for k, f in enumerate(inj_findings, start=len(xss_findings) + 1):
                f["finding_id"] = f"{self.scan_id}-WINJ{k:03d}"
                xss_findings.append(f)

        # ------------------------------------------------------------------
        # Stage 5: SQL injection probing (error-based + boolean differential)
        # ------------------------------------------------------------------
        await self._notify("sqli")
        sqli_findings = await self._probe_sqli(
            pages, headers=headers, cookies=cookies,
        )
        for k, f in enumerate(sqli_findings, start=1):
            f["finding_id"] = f"{self.scan_id}-WSQLI{k:03d}"

        # ------------------------------------------------------------------
        # Stage 6: Report
        # ------------------------------------------------------------------
        await self._notify("report")
        all_findings = (
            idor_findings + tech_findings + port_findings
            + cve_findings + discovery_findings + xss_findings
            + sqli_findings
        )
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
            "open_ports": len(open_ports_data),
            "cves_matched": len(cve_findings),
            "secrets_found": sum(
                1 for f in discovery_findings if f.get("rule") == "SECRET-LEAK"
            ),
            "exposed_files": sum(
                1 for f in discovery_findings if f.get("rule") == "EXPOSED-FILE"
            ),
            "routes_discovered": sum(
                (f.get("evidence") or {}).get("count", 0)
                for f in discovery_findings if f.get("rule") == "DISC-ROUTE"
            ),
            "xss_scan_activated": has_html and (xss_relevant or _pages_have_query_params(pages)),
            "idor_scan_activated": bool(id_endpoints),
            "domain": domain,
            "duration_ms": int((time.monotonic() - started) * 1000),
        }

        return {
            "meta": {
                "scan_id": self.scan_id,
                "mode": "website",
                "engine": "website-crawler",
                "pipeline": [
                    "crawl", "analyze", "framework", "port-scan",
                    "cve", "discovery", "probe", "sqli", "report",
                ],
                "url": url,
            },
            "summary": summary,
            "findings": all_findings,
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    async def _cve_lookup_stage(
        self,
        scan_id: str,
        tech_findings: list[dict[str, Any]],
        open_ports: list[dict[str, Any]],
        url: str,
    ) -> tuple[list[dict[str, Any]], bool, bool]:
        """Match detected technologies + open ports against known CVEs.

        Combines the deterministic local database with a live lookup against
        public CVE-reporting sources (NVD / MITRE) when enabled — each
        finding records its ``source``. Returns (cve_findings,
        xss_relevant, idor_relevant); the relevance flags gate the active
        XSS / IDOR scanners.
        """
        local_cves = lookup_cves(tech_findings, open_ports)

        # Live CVE search (optional, fail-safe offline).
        online_cves: list[dict[str, Any]] = []
        if getattr(self.settings, "cve_online_enabled", True):
            try:
                online_cves = await search_cves_online(
                    tech_findings,
                    open_ports,
                    timeout=float(
                        getattr(self.settings, "cve_search_timeout", 12.0)
                    ),
                )
            except Exception as exc:  # noqa: BLE001 — never fail scan on CVE search
                log.warning("online CVE search failed: %s", exc)

        cves = merge_cves(local_cves, online_cves)
        cve_findings: list[dict[str, Any]] = []
        for i, cve in enumerate(cves, start=1):
            # Version-aware: local matches whose detected version falls in the
            # affected range are CONFIRMED (full severity + confidence);
            # version-blind local matches are conservative (medium). Online
            # (NVD/MITRE) results keep their authoritative severity but with
            # reduced confidence since version applicability is unverified.
            verified = cve.get("verified", False)
            source = cve.get("source", "local")
            confidence = cve.get("confidence", 0.9 if verified else 0.5)
            if source == "local" and not verified:
                severity = "medium"  # conservative for version-blind local
            else:
                severity = cve.get("severity", "medium")
            detected_version = cve.get("detected_version")
            source = cve.get("source", "local")
            description = (
                f"{cve['cve']}: {cve['description']} "
                f"(source: {source})."
            )
            if detected_version:
                description += (
                    f" Detected version {detected_version} "
                    + ("IS in the affected range (confirmed)."
                       if verified else "could not be confirmed — verify.")
                )
            elif not verified:
                description += " Version not confirmed — treat as potential."
            cve_findings.append({
                "finding_id": f"{scan_id}-WCVE{i:03d}",
                "rule": "CVE-MATCH",
                "severity": severity,
                "confidence": confidence,
                "cwe": "CWE-1035",  # "using components with known vulnerabilities"
                "title": f"{cve['cve']} — {cve['title']}",
                "description": description,
                "evidence": {
                    "cve": cve["cve"],
                    "component": cve.get("component", cve["cve"]),
                    "affected": cve.get("affected", "unknown"),
                    "verified": verified,
                    "detected_version": detected_version,
                    "cvss_score": cve.get("cvss_score"),
                    "type": cve.get("type", "other"),
                    "source": source,
                    "ref": cve.get("ref", ""),
                    "url": url,
                },
                "remediation": (
                    f"Review advisory {cve.get('ref', '')} and upgrade the "
                    "affected component to a patched version."
                ),
                "location": url,
            })

        xss_relevant = cves_trigger_xss(cves) or techs_trigger_xss(tech_findings)
        idor_relevant = cves_trigger_idor(cves) or techs_trigger_idor(tech_findings)
        return cve_findings, xss_relevant, idor_relevant

    @staticmethod
    def _port_scan_findings(
        scan_result: Any, url: str,
    ) -> list[dict[str, Any]]:
        """Convert a PortScanResult into finding-shaped dicts.

        One finding per open port (rule PORT-OPEN) plus one summary finding
        (PORT-SCAN-SUMMARY) describing the scan extent.
        """
        findings: list[dict[str, Any]] = []
        host = scan_result.host
        ports = scan_result.open_ports

        if ports:
            findings.append({
                "rule": "PORT-SCAN-SUMMARY",
                "severity": "info",
                "confidence": 1.0,
                "title": f"{len(ports)} open port(s) found on {host}",
                "description": (
                    f"TCP connect scan of {scan_result.scanned} common ports "
                    f"on {host} found {len(ports)} open: "
                    + ", ".join(f"{p['port']}/{p.get('service','?')}" for p in ports)
                    + "."
                ),
                "evidence": {
                    "host": host,
                    "ports_scanned": scan_result.scanned,
                    "open_ports": [p["port"] for p in ports],
                    "duration_ms": scan_result.duration_ms,
                    "url": url,
                },
                "remediation": (
                    "Close unused ports and restrict exposure with a firewall; "
                    "move management interfaces (SSH, DB, admin) behind a VPN "
                    "or allowlist."
                ),
                "location": url,
            })

        for p in ports:
            port = p["port"]
            service = p.get("service", "unknown")
            findings.append({
                "rule": "PORT-OPEN",
                "severity": "low" if service in ("http", "https", "domain") else "medium",
                "confidence": 0.9,
                "cwe": "CWE-200",
                "title": f"Open TCP port {port} ({service}) on {host}",
                "description": (
                    f"Port {port}/{service} on {host} accepts TCP connections "
                    "(TCP connect scan)."
                ),
                "evidence": {
                    "host": host,
                    "port": port,
                    "service": service,
                    "state": "open",
                    **({"banner": p["banner"]} if p.get("banner") else {}),
                    "url": url,
                },
                "remediation": (
                    f"Ensure the service on port {port} ({service}) is "
                    "required, patched, and not exposed unnecessarily; apply "
                    "network access controls where possible."
                ),
                "location": url,
            })

        return findings

    async def _discovery_stage(
        self,
        pages: list[dict[str, Any]],
        url: str,
        headers: dict[str, str],
        cookies: dict[str, str],
    ) -> list[dict[str, Any]]:
        """Discovery (HackerOne-tools adaptation): secrets, exposed files,
        JS URLs, hidden params, wayback URLs.

        Returns finding-shaped dicts with rules SECRET-LEAK, EXPOSED-FILE,
        DISC-JS-URL, DISC-HIDDEN-PARAM, DISC-WAYBACK. Fully best-effort —
        any failure yields fewer findings, never a failed scan.
        """
        from app.utils.discovery import (
            SENSITIVE_PATHS,
            check_sensitive_paths,
            discover_hidden_params,
            extract_js_urls,
            fetch_wayback_urls,
        )
        from app.utils.secrets import scan_secrets

        findings: list[dict[str, Any]] = []
        rate = int(getattr(self.settings, "rate_limit", 10))
        from urllib.parse import urlparse as _up
        host = _up(url).hostname or ""

        # The whole stage honours the discovery switch (no partial gating).
        if not getattr(self.settings, "discovery_enabled", True):
            return findings

        # 1. Secret scanning on all crawled content (TruffleHog-style).
        for page in pages:
            page_url = page.get("url", "") or ""
            body = page.get("body") or ""
            for secret in scan_secrets(body):
                findings.append({
                    "rule": "SECRET-LEAK",
                    "severity": secret["severity"],
                    "confidence": 0.7,
                    "cwe": "CWE-200",
                    "title": f"Secret ter-expose: {secret['secret_type']}",
                    "description": (
                        f"{secret['description']} ({secret['count']}x ditemukan; "
                        f"nilai di-redaksi — samples: {', '.join(secret['samples'][:3])})"
                    ),
                    "evidence": {
                        "secret_type": secret["secret_type"],
                        "count": secret["count"],
                        "url": page_url,
                    },
                    "remediation": (
                        "Putar (rotate) kredensial yang bocor; jangan pernah "
                        "menyematkan secret di respons HTTP/JS client-side; "
                        "gunakan secret manager."
                    ),
                    "location": page_url,
                })

        # 2. JS URL extraction (Jsluice-style) — deduped summary finding.
        js_urls: list[str] = []
        for page in pages:
            if "javascript" in (page.get("content_type") or "").lower():
                js_urls.extend(extract_js_urls(page.get("body") or ""))
        js_urls = list(dict.fromkeys(js_urls))[:200]
        if js_urls:
            findings.append({
                "rule": "DISC-JS-URL",
                "severity": "info",
                "confidence": 0.6,
                "cwe": "CWE-200",
                "title": f"{len(js_urls)} endpoint/URL diekstrak dari JavaScript",
                "description": (
                    "URL dan path yang ditemukan di bundle JS (adaptasi "
                    "Jsluice/js-link-finder). Contoh: "
                    + ", ".join(js_urls[:8])
                ),
                "evidence": {"js_urls": js_urls[:50], "count": len(js_urls), "url": url},
                "remediation": (
                    "Tinjau endpoint yang ter-embed di JS client-side; sembunyikan "
                    "jalur internal yang tidak perlu diekspos."
                ),
                "location": url,
            })

        # 3. Sensitive path checks (Nikto/Dirsearch-style) — capped requests.
        if getattr(self.settings, "discovery_enabled", True):
            async with HttpClient(
                timeout=self.settings.request_timeout,
                headers=headers,
                cookies=cookies,
                rate_limit=rate,
                max_concurrency=int(getattr(self.settings, "max_concurrency", 10)),
            ) as client:
                async def _get(url: str, extra_headers=None):
                    resp = await client.get(url)
                    return resp.status, resp.body

                try:
                    exposed = await check_sensitive_paths(
                        url, _get, paths=SENSITIVE_PATHS[:20],
                    )
                except Exception as exc:  # noqa: BLE001
                    log.warning("sensitive path check failed: %s", exc)
                    exposed = []
                for exp in exposed:
                    findings.append({
                        "rule": "EXPOSED-FILE",
                        "severity": exp["severity"],
                        "confidence": 0.85,
                        "cwe": "CWE-200",
                        "title": f"File sensitif ter-expose: {exp['path']}",
                        "description": (
                            f"{exp['description']} HTTP {exp['status']} "
                            "(isi file di-redaksi — tidak pernah ditampilkan)."
                        ),
                        "evidence": {
                            "path": exp["path"],
                            "status": exp["status"],
                            "url": exp["url"],
                        },
                        "remediation": (
                            "Blokir akses publik ke file konfigurasi/backup "
                            "(web server deny rules); hapus file yang tidak perlu."
                        ),
                        "location": exp["url"],
                    })

                # 4. Hidden parameter discovery (Arjun-style) — capped.
                param_candidates: list[str] = []
                html_pages = [
                    p for p in pages
                    if "html" in (p.get("content_type") or "").lower()
                ][:3]
                for page in html_pages:
                    try:
                        found_params = await discover_hidden_params(
                            page.get("url", ""), _get,
                        )
                    except Exception:  # noqa: BLE001
                        continue
                    param_candidates.extend(found_params)
                    if len(param_candidates) >= 5:
                        break
                param_candidates = list(dict.fromkeys(param_candidates))
                for param in param_candidates[:5]:
                    findings.append({
                        "rule": "DISC-HIDDEN-PARAM",
                        "severity": "medium",
                        "confidence": 0.5,
                        "cwe": "CWE-200",
                        "title": f"Parameter tersembunyi ditemukan: {param!r}",
                        "description": (
                            f"Menambahkan {param!r} mengubah respons (adaptasi "
                            "Arjun) — parameter tak terdokumentasi dapat menjadi "
                            "permukaan serangan (IDOR/filter bypass)."
                        ),
                        "evidence": {"param": param, "url": url},
                        "remediation": (
                            "Dokumentasikan atau hapus parameter tersembunyi; "
                            "validasi input untuk parameter tak dikenal."
                        ),
                        "location": url,
                    })

        # 5. Wayback passive URL discovery (waybackurls-style).
        try:
            from urllib.parse import urlparse as _up
            host = _up(url).hostname or ""
            wb_urls = await fetch_wayback_urls(host)
        except Exception:  # noqa: BLE001
            wb_urls = []
        if wb_urls:
            findings.append({
                "rule": "DISC-WAYBACK",
                "severity": "info",
                "confidence": 0.6,
                "cwe": "CWE-200",
                "title": f"{len(wb_urls)} URL historis dari Wayback Machine",
                "description": (
                    "URL lama yang diarsipkan (adaptasi waybackurls/gau) — "
                    "sering memuat endpoint usang/rentan. Contoh: "
                    + ", ".join(wb_urls[:8])
                ),
                "evidence": {"wayback_urls": wb_urls[:30], "count": len(wb_urls), "url": url},
                "remediation": (
                    "Audit URL historis untuk kode usang yang masih aktif."
                ),
                "location": url,
            })

            # 5b. Passive subdomains from wayback corpus (Subfinder-style).
            from app.utils.discovery import extract_subdomains_from_urls
            subdomains = extract_subdomains_from_urls(wb_urls, host)
            if subdomains:
                findings.append({
                    "rule": "DISC-SUBDOMAIN",
                    "severity": "info",
                    "confidence": 0.65,
                    "cwe": "CWE-200",
                    "title": f"{len(subdomains)} subdomain ditemukan (pasif)",
                    "description": (
                        "Subdomain dari arsip URL (adaptasi Subfinder/Amass): "
                        + ", ".join(subdomains[:10])
                    ),
                    "evidence": {"subdomains": subdomains[:20],
                                 "count": len(subdomains), "url": url},
                    "remediation": (
                        "Audit subdomain untuk aset lama/terlupakan; pastikan "
                        "semua masuk scope keamanan."
                    ),
                    "location": url,
                })

        # 6. Active subdomain enumeration (Dnscan/Shuffledns-style, DNS only).
        if getattr(self.settings, "discovery_enabled", True) and host:
            try:
                from app.utils.discovery import discover_subdomains
                active_subs = await discover_subdomains(host)
            except Exception:  # noqa: BLE001
                active_subs = []
            if active_subs:
                findings.append({
                    "rule": "DISC-SUBDOMAIN",
                    "severity": "info",
                    "confidence": 0.7,
                    "cwe": "CWE-200",
                    "title": f"{len(active_subs)} subdomain aktif (DNS)",
                    "description": (
                        "Subdomain yang resolve via DNS: "
                        + ", ".join(active_subs[:10])
                    ),
                    "evidence": {"subdomains": active_subs[:20],
                                 "count": len(active_subs), "url": url},
                    "remediation": (
                        "Perluas permukaan serangan yang dipantau ke subdomain "
                        "aktif ini."
                    ),
                    "location": url,
                })

        # 7. API endpoint discovery (Kiterunner-style).
        # Fresh HttpClient: the first block (sections 3-4) has exited, so its
        # _get closure would hit a closed client (RuntimeError) — sections
        # 7-10 were silently no-ops before this fix.
        from app.utils.discovery import check_api_endpoints
        async with HttpClient(
            timeout=self.settings.request_timeout,
            headers=headers,
            cookies=cookies,
            rate_limit=rate,
            max_concurrency=int(getattr(self.settings, "max_concurrency", 10)),
        ) as client2:
            async def _get2(url: str, extra_headers=None):
                resp = await client2.get(url)
                return resp.status, resp.body

            try:
                api_hits = await check_api_endpoints(url, _get2)
            except Exception:  # noqa: BLE001
                api_hits = []
            if api_hits:
                findings.append({
                    "rule": "DISC-API-ENDPOINT",
                    "severity": "info",
                    "confidence": 0.6,
                    "cwe": "CWE-200",
                    "title": f"{len(api_hits)} endpoint API terdeteksi",
                    "description": (
                        "Endpoint API yang merespons (adaptasi Kiterunner): "
                        + ", ".join(api_hits[:10])
                    ),
                    "evidence": {"endpoints": api_hits, "count": len(api_hits), "url": url},
                    "remediation": (
                        "Audit setiap endpoint API; pastikan auth + rate limit "
                        "pada jalur yang tidak perlu publik."
                    ),
                    "location": url,
                })

            # 8. Admin panel / management interface checks (Nuclei-style).
            from app.utils.discovery import ADMIN_PATHS
            try:
                admin_hits = await check_sensitive_paths(
                    url, _get2, paths=ADMIN_PATHS,
                )
            except Exception:  # noqa: BLE001
                admin_hits = []
            for hit in admin_hits:
                findings.append({
                    "rule": "EXPOSED-FILE",
                    "severity": hit["severity"],
                    "confidence": 0.85,
                    "cwe": "CWE-200",
                    "title": f"Interface admin ter-expose: {hit['path']}",
                    "description": (
                        f"{hit['description']} HTTP {hit['status']}."
                    ),
                    "evidence": {"path": hit["path"], "status": hit["status"],
                                 "url": hit["url"]},
                    "remediation": (
                        "Batasi akses admin dengan IP allowlist/VPN; nonaktifkan "
                        "panel yang tidak diperlukan."
                    ),
                    "location": hit["url"],
                })

            # 9. WordPress-specific checks (Wpscan-style).
            from app.utils.discovery import WP_PATHS
            try:
                wp_hits = await check_sensitive_paths(url, _get2, paths=WP_PATHS)
            except Exception:  # noqa: BLE001
                wp_hits = []
            for hit in wp_hits:
                findings.append({
                    "rule": "WP-EXPOSED",
                    "severity": hit["severity"],
                    "confidence": 0.8,
                    "cwe": "CWE-200",
                    "title": f"WordPress ter-expose: {hit['path']}",
                    "description": (
                        f"{hit['description']} HTTP {hit['status']}."
                    ),
                    "evidence": {"path": hit["path"], "status": hit["status"],
                                 "url": hit["url"]},
                    "remediation": (
                        "Sembunyikan enumerasi user/plugin (disable REST users, "
                        "blokir readme, nonaktifkan xmlrpc bila tidak perlu)."
                    ),
                    "location": hit["url"],
                })

            # 10. Common directory fuzzing (Ffuf/Dirsearch-style, capped).
            from app.utils.discovery import COMMON_DIR_PATHS
            dir_targets = [
                (p, f"Direktori {p} dapat diakses.", "low")
                for p in COMMON_DIR_PATHS[:25]
            ]
            try:
                dir_hits = await check_sensitive_paths(url, _get2, paths=dir_targets)
            except Exception:  # noqa: BLE001
                dir_hits = []
            for hit in dir_hits:
                findings.append({
                    "rule": "DISC-PATH",
                    "severity": hit["severity"],
                    "confidence": 0.6,
                    "cwe": "CWE-200",
                    "title": f"Direktori ditemukan: {hit['path']}",
                    "description": (
                        f"{hit['description']} HTTP {hit['status']} "
                        "(adaptasi Ffuf/Dirsearch)."
                    ),
                    "evidence": {"path": hit["path"], "status": hit["status"],
                                 "url": hit["url"]},
                    "remediation": (
                        "Hapus/blokir direktori yang tidak perlu publik."
                    ),
                    "location": hit["url"],
                })

        # 11. SSRF sink detection (SSRFTest-style, passive).
        from app.utils.discovery import detect_ssrf_params
        ssrf_params: list[str] = []
        for page in pages:
            try:
                ssrf_params.extend(
                    detect_ssrf_params(page.get("url", ""), page.get("body"))
                )
            except Exception:  # noqa: BLE001
                continue
        ssrf_params = list(dict.fromkeys(ssrf_params))
        if ssrf_params:
            findings.append({
                "rule": "SSRF-SINK",
                "severity": "medium",
                "confidence": 0.45,
                "cwe": "CWE-918",
                "title": "Parameter SSRF-sink ditemukan (pasif)",
                "description": (
                    "Parameter dengan nama mirip sink SSRF (url/redirect/"
                    "callback/…): " + ", ".join(ssrf_params[:10])
                    + " — uji manual dengan target internal."
                ),
                "evidence": {"params": ssrf_params, "url": url},
                "remediation": (
                    "Validasi scheme+host URL yang di-fetch server; blokir "
                    "alamat internal (169.254.169.254, localhost, RFC1918)."
                ),
                "location": url,
            })

        # 12. Virtual-host discovery (virtual-host-discovery).
        if getattr(self.settings, "discovery_enabled", True) and host:
            import httpx as _httpx

            from app.utils.discovery import COMMON_VHOSTS
            parsed0 = _up(url)
            port_part = f":{parsed0.port}" if parsed0.port else ""
            base_body_len = None
            vhost_hits: list[str] = []
            try:
                async with _httpx.AsyncClient(
                    timeout=float(self.settings.request_timeout),
                    follow_redirects=False,
                ) as vc:
                    r0 = await vc.get(url)
                    base_body_len = len(r0.text or "")
                    for vh in COMMON_VHOSTS:
                        try:
                            rv = await vc.get(
                                url,
                                headers={"Host": f"{vh}.{host}{port_part}"},
                            )
                        except _httpx.HTTPError:
                            continue
                        if (200 <= rv.status_code < 300
                                and abs(len(rv.text or "") - (base_body_len or 0)) > 100):
                            vhost_hits.append(f"{vh}.{host}")
            except _httpx.HTTPError:
                pass
            if vhost_hits:
                findings.append({
                    "rule": "DISC-VHOST",
                    "severity": "info",
                    "confidence": 0.5,
                    "cwe": "CWE-200",
                    "title": f"{len(vhost_hits)} virtual host terdeteksi",
                    "description": (
                        "Virtual host dengan respons berbeda: "
                        + ", ".join(vhost_hits[:10])
                    ),
                    "evidence": {"vhosts": vhost_hits, "url": url},
                    "remediation": (
                        "Audit vhost lama/tersembunyi; pastikan tidak ada "
                        "kode usang yang ter-expose."
                    ),
                    "location": url,
                })

        # 13. GraphQL introspection (Altair-style, read-only POST).
        if getattr(self.settings, "discovery_enabled", True):
            from urllib.parse import urljoin as _urljoin

            from app.utils.discovery import check_graphql_introspection
            try:
                introspectable = await check_graphql_introspection(url)
            except Exception:  # noqa: BLE001
                introspectable = False
            if introspectable:
                findings.append({
                    "rule": "GRAPHQL-INTROSPECTION",
                    "severity": "medium",
                    "confidence": 0.8,
                    "cwe": "CWE-200",
                    "title": "GraphQL introspection aktif",
                    "description": (
                        "Endpoint /graphql merespons query __schema — skema "
                        "aplikasi dapat di-enumerasi penuh."
                    ),
                    "evidence": {"url": _urljoin(url.rstrip('/') + '/', 'graphql')},
                    "remediation": (
                        "Nonaktifkan introspection di production."
                    ),
                    "location": url,
                })

        # 14. Route discovery — comprehensive routing enumeration
        # (robots.txt + sitemap + OpenAPI + crawl/JS/Wayback corpus).
        from app.utils.route_discovery import discover_routes
        try:
            # Reuse the client2 getter when available; sections 7-10 close
            # it, so probe with a fresh short-lived client here.
            async with HttpClient(
                timeout=self.settings.request_timeout,
                headers=headers,
                cookies=cookies,
                rate_limit=rate,
                max_concurrency=int(getattr(self.settings, "max_concurrency", 10)),
            ) as route_client:

                async def _get_route(u: str, extra_headers=None):
                    resp = await route_client.get(u)
                    return resp.status, resp.body

                # Combine the crawled/JS/wayback corpora into extra_paths —
                # normalize through extract_paths_from_urls with the target
                # hostname so off-domain wayback noise never pollutes routes.
                target_host = _up(url).hostname or ""

                from app.utils.route_discovery import extract_paths_from_urls

                corpus_urls: list[str] = []
                for page in pages:
                    corpus_urls.append(page.get("url", "") or "")
                for u in js_urls:
                    corpus_urls.append(u)
                for wb in wb_urls[:30]:
                    corpus_urls.append(wb)
                extra_paths = extract_paths_from_urls(corpus_urls, target_host)

                route_result = await discover_routes(
                    url, _get_route, extra_paths=extra_paths,
                )
        except Exception as exc:  # noqa: BLE001
            log.warning("route discovery failed: %s", exc)
            route_result = {"routes": [], "count": 0}

        route_list = route_result.get("routes", [])
        if route_list:
            findings.append({
                "rule": "DISC-ROUTE",
                "severity": "info",
                "confidence": 0.65,
                "cwe": "CWE-200",
                "title": f"{len(route_list)} route/endpoint ditemukan",
                "description": (
                    "Permukaan routing target (adaptasi Kiterunner/gau): "
                    + ", ".join(r["path"] for r in route_list[:12])
                ),
                "evidence": {
                    "routes": [
                        {"path": r["path"], "source": r["source"],
                         "classification": r["classification"]}
                        for r in route_list[:50]
                    ],
                    "count": len(route_list),
                    "url": url,
                },
                "remediation": (
                    "Audit seluruh route; pastikan auth pada jalur admin/api "
                    "dan hapus endpoint yang tidak perlu publik."
                ),
                "location": url,
            })
            # Sensitive routes get their own elevated finding.
            sensitive_routes = [
                r for r in route_list if r["classification"] == "sensitive"
            ]
            for sr in sensitive_routes[:5]:
                findings.append({
                    "rule": "API-ROUTE",
                    "severity": "medium",
                    "confidence": 0.55,
                    "cwe": "CWE-200",
                    "title": f"Route sensitif ditemukan: {sr['path']}",
                    "description": (
                        f"Path {sr['path']} terlihat sensitif (sumber: "
                        f"{sr['source']}) — periksa akses dan autentikasi."
                    ),
                    "evidence": {"path": sr["path"], "source": sr["source"],
                                 "url": url},
                    "remediation": (
                        "Batasi akses ke route sensitif (auth/allowlist); "
                        "hapus jika tidak diperlukan."
                    ),
                    "location": url,
                })

        # 15. Harvester-style passive OSINT gathering (subdomains,
        # emails, IPs, technology fingerprints from headers/body).
        await self._notify("harvest")
        harvest_findings: list[dict[str, Any]] = []
        host = _up(url).hostname or ""
        try:
            from app.utils.discovery import (
                harvest_emails,
                harvest_ips,
                harvest_subdomains_crtsh,
                harvest_tech_fingerprints,
                harvest_tech_from_headers,
            )

            # 15a. Subdomain enumeration via crt.sh.
            async def _fetch_crtsh():
                try:
                    subs = await harvest_subdomains_crtsh(host)
                    return subs
                except Exception:  # noqa: BLE001
                    return []

            subs_crtsh = await _fetch_crtsh()
            if subs_crtsh:
                harvest_findings.append({
                    "rule": "HARVEST-SUBDOMAIN-CRTSH",
                    "severity": "info",
                    "confidence": 0.7,
                    "cwe": "CWE-200",
                    "title": f"{len(subs_crtsh)} subdomain ditemukan (crt.sh)",
                    "description": (
                        "Subdomain ditemukan via crt.sh (Harvester-style): "
                        + ", ".join(subs_crtsh[:10])
                    ),
                    "evidence": {
                        "subdomains": subs_crtsh[:20],
                        "count": len(subs_crtsh),
                        "url": url,
                    },
                    "remediation": (
                        "Audit semua subdomain; pastikan tidak ada "
                        "aset lama/terlupakan."
                    ),
                    "location": url,
                })

            # 15b. Subdomain enumeration via Wayback Machine.
            try:
                from app.utils.discovery import fetch_wayback_urls
                wb_urls = await fetch_wayback_urls(host)
            except Exception:  # noqa: BLE001
                wb_urls = []
            subs_wayback = set()
            for u in wb_urls:
                try:
                    h = _up(u).hostname or ""
                    if h.endswith("." + host) and h != host:
                        subs_wayback.add(h)
                except ValueError:
                    continue
            subs_wayback = sorted(subs_wayback)
            if subs_wayback:
                harvest_findings.append({
                    "rule": "HARVEST-SUBDOMAIN-WAYBACK",
                    "severity": "info",
                    "confidence": 0.65,
                    "cwe": "CWE-200",
                    "title": (
                        f"{len(subs_wayback)} subdomain dari Wayback Machine"
                    ),
                    "description": (
                        "Subdomain ditemukan dari arsip URL "
                        "(Harvester-style): "
                        + ", ".join(subs_wayback[:10])
                    ),
                    "evidence": {
                        "subdomains": subs_wayback[:20],
                        "count": len(subs_wayback),
                        "url": url,
                    },
                    "remediation": (
                        "Audit subdomain Wayback untuk aset lama."
                    ),
                    "location": url,
                })

            # 15c. Technology fingerprint from headers (all crawled pages).
            tech_header_findings: list[dict[str, Any]] = []
            tech_header_names: list[str] = []
            for page in pages:
                header_dict = dict(page.get("headers", {}))
                techs = harvest_tech_from_headers(header_dict)
                for t in techs:
                    tech_header_names.append(t.get("category", t.get("rule", "")))
                    tech_header_findings.append(t)
            tech_header_names = list(dict.fromkeys(tech_header_names))
            if tech_header_findings:
                harvest_findings.append({
                    "rule": "HARVEST-TECH-HEADER",
                    "severity": "info",
                    "confidence": 0.8,
                    "cwe": "CWE-200",
                    "title": (
                        f"{len(tech_header_findings)} fingerprint teknologi "
                        "dari header HTTP"
                    ),
                    "description": (
                        "Teknologi terdeteksi dari header response: "
                        + ", ".join(tech_header_names[:15])
                    ),
                    "evidence": {
                        "technologies": tech_header_names[:20],
                        "count": len(tech_header_findings),
                        "url": url,
                    },
                    "remediation": (
                        "Sembunyikan atau ubah header server "
                        "untuk mengurangi informasi yang bocor."
                    ),
                    "location": url,
                })

            # 15d. Technology fingerprint from HTML body.
            tech_body_findings: list[dict[str, Any]] = []
            tech_body_names: list[str] = []
            for page in pages:
                body = page.get("body") or ""
                if not body:
                    continue
                techs = harvest_tech_fingerprints(body)
                for t in techs:
                    tech_body_names.append(t.get("value", ""))
                    tech_body_findings.append(t)
            tech_body_names = list(dict.fromkeys(tech_body_names))
            if tech_body_findings:
                harvest_findings.append({
                    "rule": "HARVEST-TECH-BODY",
                    "severity": "info",
                    "confidence": 0.75,
                    "cwe": "CWE-200",
                    "title": (
                        f"{len(tech_body_findings)} fingerprint teknologi "
                        "dari body HTML"
                    ),
                    "description": (
                        "Teknologi terdeteksi dari isi HTML: "
                        + ", ".join(tech_body_names[:15])
                    ),
                    "evidence": {
                        "technologies": tech_body_names[:20],
                        "count": len(tech_body_findings),
                        "url": url,
                    },
                    "remediation": (
                        "Pastikan library/framework di-update ke "
                        "versi terbaru."
                    ),
                    "location": url,
                })

            # 15e. Harvest emails and IPs from crawled content.
            all_emails: list[str] = []
            all_ips: list[str] = []
            for page in pages:
                all_emails.extend(harvest_emails(page.get("body") or ""))
                all_ips.extend(harvest_ips(page.get("body") or ""))
            all_emails = list(dict.fromkeys(all_emails))[:50]
            all_ips = list(dict.fromkeys(all_ips))[:50]
            if all_emails:
                harvest_findings.append({
                    "rule": "HARVEST-EMAIL",
                    "severity": "low",
                    "confidence": 0.7,
                    "cwe": "CWE-200",
                    "title": f"{len(all_emails)} email ditemukan di content",
                    "description": (
                        "Email address ditemukan di response "
                        "(Harvester-style): "
                        + ", ".join(all_emails[:10])
                    ),
                    "evidence": {
                        "emails": all_emails[:20],
                        "count": len(all_emails),
                        "url": url,
                    },
                    "remediation": (
                        "Hapus email dari response publik; "
                        "gunakan form kontak."
                    ),
                    "location": url,
                })
            if all_ips:
                harvest_findings.append({
                    "rule": "HARVEST-IP",
                    "severity": "info",
                    "confidence": 0.7,
                    "cwe": "CWE-200",
                    "title": f"{len(all_ips)} IP address ditemukan di content",
                    "description": (
                        "IP address ditemukan di response body: "
                        + ", ".join(all_ips[:10])
                    ),
                    "evidence": {"ips": all_ips[:20], "count": len(all_ips)},
                    "remediation": (
                        "Pastikan IP internal tidak ter-expose "
                        "di response client-side."
                    ),
                    "location": url,
                })

        except Exception as exc:  # noqa: BLE001
            log.warning("Harvester stage failed: %s", exc)
        findings.extend(harvest_findings)

        # 15f. OSINT recon — RDAP/whois, DNS-over-HTTPS records, ASN netblock.
        # Famous-tool adaptation: ``whois`/RDAP bootstrap, dnsrecon/dnsx (DoH),
        # Team-Cymru ASN lookup. Fully best-effort; public datasources only.
        await self._notify("osint")
        osint_findings: list[dict[str, Any]] = []
        try:
            from app.utils.osint import osint_passive_gather

            # Best-effort IP resolution for the ASN/netblock lookup.
            resolved_ip: str | None = None
            if host:
                try:
                    resolved_ip = (await asyncio.get_event_loop().getaddrinfo(
                        host, None,
                    ))[0][4][0]
                except Exception:  # noqa: BLE001 — DNS failure just skips ASN
                    resolved_ip = None

            osint_data = await osint_passive_gather(
                url,
                ip=resolved_ip,
            )
            rdap = osint_data.get("rdap") or {}
            dnsm = osint_data.get("dns") or {}
            asn = osint_data.get("asn") or {}

            if rdap.get("expiry_date") or rdap.get("registrar"):
                osint_findings.append({
                    "rule": "OSINT-RDAP",
                    "severity": "info",
                    "confidence": 0.8,
                    "cwe": "CWE-200",
                    "title": f"Registrasi domain: {osint_data.get('domain', '')}",
                    "description": (
                        "Data registrasi RDAP (adaptasi whois). Registrar: "
                        + str(rdap.get("registrar") or "-")
                        + "; kedaluwarsa: " + str(rdap.get("expiry_date") or "-")
                        + "; NS: " + ", ".join((rdap.get("nameservers") or [])[:4] or ["-"])
                        + ". Domain yang mendekati kedaluwarsa memperbesar "
                        "risiko take-over (OWASP: allowing domains to expire)."
                    ),
                    "evidence": {
                        "domain": osint_data.get("domain"),
                        "registrar": rdap.get("registrar"),
                        "expiry_date": rdap.get("expiry_date"),
                        "created_date": rdap.get("created_date"),
                        "nameservers": (rdap.get("nameservers") or [])[:10],
                        "registrant_org": rdap.get("registrant_org"),
                        "url": url,
                    },
                    "remediation": (
                        "Pantau tanggal kedaluwarsa domain; pertahankan "
                        "registrar/kontak yang valid."
                    ),
                    "location": url,
                })
                if rdap.get("expiry_date"):
                    try:
                        rp = rdap.get("created_date") or ""
                        expiry = str(rdap.get("expiry_date"))
                        osint_findings.append({
                            "rule": "OSINT-DOMAIN-EXPIRY",
                            "severity": "low",
                            "confidence": 0.6,
                            "cwe": "CWE-200",
                            "title": "Domain mendekati/melewati kedaluwarsa",
                            "description": (
                                "RDAP melaporkan tanggal kedaluwarsa "
                                f"{expiry}. Domain yang kedaluwarsa dapat "
                                "diambil alih oleh pihak lain (OWASP: allowing "
                                "domains or accounts to expire)."
                            ),
                            "evidence": {"expiry_date": expiry, "url": url},
                            "remediation": (
                                "Perpanjang registrasi dan set auto-renew."
                            ),
                            "location": url,
                        })
                        del rp
                    except Exception:  # noqa: BLE001
                        pass

            if dnsm:
                dns_line = ", ".join(
                    f"{k}={' '.join(v[:3])}" for k, v in dnsm.items() if v
                )
                osint_findings.append({
                    "rule": "OSINT-DNS",
                    "severity": "info",
                    "confidence": 0.75,
                    "cwe": "CWE-200",
                    "title": f"Record DNS ter-enumerasi: {osint_data.get('domain', '')}",
                    "description": (
                        "Record DNS via DNS-over-HTTPS (adaptasi dnsrecon/dnsx): "
                        + dns_line[:400]
                        + ". TXT/SPF/DMARC dapat membocorkan string verifikasi "
                        "kepemilikan/3rd-party yang membantu pemetaan infra."
                    ),
                    "evidence": {"records": dnsm, "url": url},
                    "remediation": (
                        "Audit catatan DNS publik; jangan taruh rahasia "
                        "verifikasi yang dapat disalahgunakan di TXT."
                    ),
                    "location": url,
                })

            if asn.get("asn"):
                osint_findings.append({
                    "rule": "OSINT-ASN",
                    "severity": "info",
                    "confidence": 0.7,
                    "cwe": "CWE-200",
                    "title": (
                        f"Netblock ASN: {asn.get('asn')} / "
                        f"{asn.get('registrant') or '?'}"
                    ),
                    "description": (
                        "Pemetaan netblock/ASN (adaptasi Team-Cymru asnmap): "
                        f"AS{asn.get('asn')}, CIDR {asn.get('cidr') or '?'}, "
                        f"negara {asn.get('country') or '?'}. Memetakan "
                        "kepemilikan infra target."
                    ),
                    "evidence": {"asn": asn, "url": url},
                    "remediation": (
                        "Pastikan seluruh CIDR dalam scope audit; awasi "
                        "shadow-asset di netblock yang sama."
                    ),
                    "location": url,
                })
        except Exception as exc:  # noqa: BLE001
            log.warning("OSINT stage failed: %s", exc)
        findings.extend(osint_findings)

        # 15g. Client-side reverse engineering — exposed source maps + known
        # vulnerable / obsolete JS libraries (web source-map exposer +
        # Retire.js adaptation). Bounded: fetch up to 12 same-origin JS assets
        # referenced from crawled HTML and re-analyse their bodies.
        await self._notify("re")
        re_findings: list[dict[str, Any]] = []
        try:
            from urllib.parse import urljoin as _urljoin_re

            from app.utils.re_analysis import run_re_passive

            js_candidates: list[str] = []
            for page in pages:
                body = page.get("body") or ""
                for m in re.finditer(
                    r"<script\b[^>]*\bsrc\s*=\s*[\"']([^\"']+\.js(?:[?\"'#][^\"']*)?)"
                    r"[\"']", body, re.I,
                ):
                    js_candidates.append(_urljoin_re(url, m.group(1)))
            js_candidates = [
                u for u in dict.fromkeys(js_candidates)
                if (_up(u).hostname or "").endswith(host) or _up(u).hostname == host
            ][:12]

            js_bodies: list[tuple[str, str]] = [
                (p["url"], p["body"] or "")
                for p in pages
                if "javascript" in (p.get("content_type") or "").lower()
            ]
            if js_candidates:
                async with HttpClient(
                    timeout=self.settings.request_timeout,
                    headers=headers,
                    cookies=cookies,
                    rate_limit=rate,
                    max_concurrency=int(getattr(self.settings, "max_concurrency", 10)),
                ) as js_client:
                    _js_resp = await asyncio.gather(
                        *[js_client.get(u) for u in js_candidates],
                        return_exceptions=True,
                    )
                    for u, r in zip(js_candidates, _js_resp, strict=False):
                        if isinstance(r, Exception):
                            continue
                        if r.status == 200 and "javascript" in (
                            r.headers.get("content-type", "")
                        ).lower():
                            js_bodies.append((u, r.body or ""))

            # Dedupe by URL, keep first body.
            seen_js: set[str] = set()
            js_body_uniq: list[tuple[str, str]] = []
            for u, b in js_bodies:
                if u in seen_js:
                    continue
                seen_js.add(u)
                js_body_uniq.append((u, b))

            html_body_uniq = [
                (p.get("url", ""), p.get("body") or "")
                for p in pages
            ]
            re_findings.extend(run_re_passive(js_body_uniq, html_body_uniq))
        except Exception as exc:  # noqa: BLE001
            log.warning("RE stage failed: %s", exc)
        findings.extend(re_findings)

        # 16. Nikto-style web server security checks.
        await self._notify("nikto")
        nikto_findings: list[dict[str, Any]] = []
        try:
            from app.utils.discovery import (
                nikto_check_directory_listing,
                nikto_check_info_disclosure,
                nikto_check_outdated_software,
                nikto_check_server_headers,
                nikto_check_sql_errors,
            )

            # 16a. Header checks on all crawled pages.
            for page in pages:
                header_dict = dict(page.get("headers", {}))
                body = page.get("body") or ""

                # Nikto header analysis.
                header_results = nikto_check_server_headers(header_dict)
                for r in header_results:
                    r["location"] = page.get("url", url)
                    nikto_findings.append(r)

                # Nikto SQL error detection.
                sql_results = nikto_check_sql_errors(body)
                for r in sql_results:
                    r["location"] = page.get("url", url)
                    nikto_findings.append(r)

                # Nikto directory listing detection.
                dir_results = nikto_check_directory_listing(
                    body, page.get("url", url),
                )
                for r in dir_results:
                    nikto_findings.append(r)

                # Nikto info disclosure detection.
                disc_results = nikto_check_info_disclosure(body)
                for r in disc_results:
                    r["location"] = page.get("url", url)
                    nikto_findings.append(r)

            # 16b. Outdated software detection from technology findings.
            tech_evidence: list[dict[str, Any]] = []
            for page in pages:
                header_dict = dict(page.get("headers", {}))
                from app.utils.discovery import harvest_tech_from_headers
                tech_evidence.extend(harvest_tech_from_headers(header_dict))
            outdated = nikto_check_outdated_software(tech_evidence)
            for r in outdated:
                nikto_findings.append(r)

        except Exception as exc:  # noqa: BLE001
            log.warning("Nikto stage failed: %s", exc)
        findings.extend(nikto_findings)

        # 17. Nuclei-style template-based vulnerability checks.
        await self._notify("nuclei")
        nuclei_findings: list[dict[str, Any]] = []
        try:
            from app.utils.discovery import (
                nuclei_check_cors_misconfig,
                nuclei_check_crlf_injection,
                nuclei_check_sensitive_files,
                nuclei_check_template_matches,
                nuclei_check_xss_protection,
            )

            for page in pages:
                header_dict = dict(page.get("headers", {}))
                body = page.get("body") or ""
                page_url = page.get("url", url)

                # Nuclei CORS misconfig.
                cors_results = nuclei_check_cors_misconfig(header_dict)
                for r in cors_results:
                    r["location"] = page_url
                    nuclei_findings.append(r)

                # Nuclei XSS protection check.
                xss_results = nuclei_check_xss_protection(header_dict)
                for r in xss_results:
                    r["location"] = page_url
                    nuclei_findings.append(r)

                # Nuclei sensitive files/data.
                sensitive_results = nuclei_check_sensitive_files(
                    body, page_url,
                )
                for r in sensitive_results:
                    nuclei_findings.append(r)

                # Nuclei template pattern matches.
                template_results = nuclei_check_template_matches(
                    body, page_url,
                )
                for r in template_results:
                    r["location"] = page_url
                    nuclei_findings.append(r)

                # Nuclei CRLF injection in headers.
                crlf_results = nuclei_check_crlf_injection(header_dict)
                for r in crlf_results:
                    r["location"] = page_url
                    nuclei_findings.append(r)

        except Exception as exc:  # noqa: BLE001
            log.warning("Nuclei stage failed: %s", exc)
        findings.extend(nuclei_findings)

        # 18. Live CWE sec checks — response-passive over crawled pages
        # (verbose errors, cookie flags, transport/HSTS, methods, disclosures).
        await self._notify("sec-live")
        sec_findings: list[dict[str, Any]] = []
        try:
            from app.utils.live_checks import (
                check_allow_methods,
                check_cookie_security,
                check_csv_exposure,
                check_follina,
                check_platform_exposure,
                check_sensitive_query_params,
                check_serialized_endpoint,
                check_tls_certificate,
                check_transport_security,
                check_upload_form,
                check_verbose_errors,
                check_x_powered_by,
                check_xml_endpoint,
            )

            # OWASP community-vulnerability live checks (passive).
            from app.utils.owasp_live import run_owasp_passive_checks

            for page in pages:
                header_dict = dict(page.get("headers", {}))
                body = page.get("body") or ""
                page_url = page.get("url", url)

                for r in check_verbose_errors(body, page_url):
                    r.setdefault("location", page_url)
                    sec_findings.append(r)
                for r in check_cookie_security(header_dict):
                    r["location"] = page_url
                    sec_findings.append(r)
                for r in check_allow_methods(header_dict):
                    r["location"] = page_url
                    sec_findings.append(r)
                for r in check_x_powered_by(header_dict):
                    r["location"] = page_url
                    sec_findings.append(r)
                for r in check_platform_exposure(header_dict, body):
                    r["location"] = page_url
                    sec_findings.append(r)
                for r in check_follina(body, page_url):
                    r["location"] = page_url
                    sec_findings.append(r)
                # Attack-surface classification from OWASP taxonomy.
                for r in check_sensitive_query_params(page_url):
                    r["location"] = page_url
                    sec_findings.append(r)
                for r in check_csv_exposure(header_dict, page_url):
                    r["location"] = page_url
                    sec_findings.append(r)
                for r in check_upload_form(body, page_url):
                    r["location"] = page_url
                    sec_findings.append(r)
                for r in check_serialized_endpoint(header_dict, page_url):
                    r["location"] = page_url
                    sec_findings.append(r)
                for r in check_xml_endpoint(header_dict, page_url):
                    r["location"] = page_url
                    sec_findings.append(r)

                # OWASP community-vulnerability passive checks (GET-login,
                # mixed content / third-party SRI, deserialization magic,
                # session-id entropy).
                for r in run_owasp_passive_checks(header_dict, body, page_url):
                    r["location"] = page_url
                    sec_findings.append(r)

            # Transport/HSTS is a whole-target property — check once.
            combined_headers: dict[str, str] = {}
            for page in pages:
                combined_headers.update(page.get("headers", {}))
            for r in check_transport_security(url, combined_headers):
                r["location"] = url
                sec_findings.append(r)
            # TLS cert expiry is observed directly on the target connection.
            for r in await check_tls_certificate(url):
                r["location"] = url
                sec_findings.append(r)
        except Exception as exc:  # noqa: BLE001
            log.warning("sec-live stage failed: %s", exc)
        findings.extend(sec_findings)

        # Assign finding_ids
        for k, f in enumerate(findings, start=1):
            f["finding_id"] = f"{self.scan_id}-WDISC{k:03d}"
        return findings

    async def _probe_xss_payloads(
        self,
        pages: list[dict[str, Any]],
        *,
        headers: dict[str, str],
        cookies: dict[str, str],
    ) -> list[dict[str, Any]]:
        """Active XSS payload injection — confirms reflected XSS via GET.

        For each 2xx HTML page with query parameters, sends **actual XSS
        vectors** as param values (via GET, read-only, non-destructive) and
        checks whether the payload string appears **raw** (un-encoded) in
        the response body. If so, the param is a confirmed reflected-XSS
        sink with the specific working payload.

        The payloads are standard non-destructive XSS probes:
        ``<img onerror>``, ``<svg onload>``, ``<script>alert(1)</script>``,
        attribute-breakout variants, and a universal marker. All are safe
        (no state mutation, no side effects) and well-known industry
        test vectors.

        Returns XS-LIVE-032 findings with the working payload and evidence.
        """
        import html as _html
        from urllib.parse import parse_qs, urlencode, urlparse, urlunparse


        findings: list[dict[str, Any]] = []

        html_pages = [
            p for p in pages
            if "html" in (p.get("content_type") or "").lower()
            and 200 <= int(p.get("status") or 0) < 300
        ]
        if not html_pages:
            return findings

        async with HttpClient(
            timeout=self.settings.request_timeout,
            headers=headers,
            cookies=cookies,
            rate_limit=int(getattr(self.settings, "rate_limit", 10)),
            max_concurrency=int(getattr(self.settings, "max_concurrency", 5)),
        ) as client:
            requests_made = 0
            for page in html_pages:
                url = page.get("url", "") or ""
                parsed = urlparse(url)
                qs = parse_qs(parsed.query, keep_blank_values=True)
                if not qs:
                    continue
                for name, values in qs.items():
                    if requests_made >= _MAX_XSS_PROBE_REQUESTS:
                        return findings
                    for payload, ctx, sev in _XSS_PAYLOADS:
                        if requests_made >= _MAX_XSS_PROBE_REQUESTS:
                            return findings
                        for orig in values:
                            probe_val = payload if not orig else f"{orig}{payload}"
                            probe_qs = dict(qs)
                            probe_qs[name] = [probe_val]
                            probe_url = urlunparse(
                                parsed._replace(
                                    query=urlencode(probe_qs, doseq=True)
                                )
                            )
                            try:
                                resp = await client.get(probe_url)
                            except Exception as exc:  # noqa: BLE001
                                log.warning(
                                    "xss payload probe failed %s: %s",
                                    probe_url, exc,
                                )
                                continue
                            requests_made += 1
                            if resp.status != 200:
                                continue
                            body = resp.body or ""
                            # Check if the payload string appears RAW (un-encoded)
                            # in the response body. If the server HTML-encodes it,
                            # the raw payload won't match (e.g. "<" → "&lt;").
                            if payload not in body:
                                continue
                            # Ensure the raw appearance is not just the HTML-encoded
                            # form happening to contain the payload substring
                            # (only relevant for payloads without special chars).
                            encoded_payload = _html.escape(payload)
                            if encoded_payload != payload and encoded_payload in body:
                                continue
                            findings.append({
                                "rule": "XS-LIVE-032",
                                "severity": sev,
                                "confidence": 0.9,
                                "title": (
                                    f"Confirmed reflected XSS via payload "
                                    f"on param {name!r}"
                                ),
                                "description": (
                                    f"Parameter {name!r} reflects the XSS vector "
                                    f"{payload!r} verbatim without encoding — "
                                    f"confirmed {ctx} reflected XSS. "
                                    "An attacker can execute arbitrary JS by "
                                    "crafting a malicious link."
                                ),
                                "evidence": {
                                    "payload": payload,
                                    "context": ctx,
                                    "param": name,
                                    "probe_url": probe_url,
                                    "sample": (
                                        body[
                                            max(body.find(payload) - 60, 0):
                                            body.find(payload) + 120
                                        ][:200]
                                    ),
                                },
                                "remediation": (
                                    "HTML-escape ALL user input before writing "
                                    "into the response; prefer parameterized "
                                    "templates; validate input types and lengths; "
                                    "deploy a strict Content-Security-Policy."
                                ),
                                "location": probe_url,
                            })
                            # Finding found — stop checking payloads for this param.
                            break
                        else:
                            # `for orig` exhausted without finding → try next payload
                            continue
                        # `for orig` break fires here → finding found, stop payloads
                        break
                    else:
                        continue  # no payload matched → next payload
                    # Payload matched for this param — continue to the next
                    # param (the earlier `break`s already stopped payload/orig
                    # loops; do NOT break the outer param loop).
        return findings

    async def _probe_injection_signatures(
        self,
        pages: list[dict[str, Any]],
        *,
        headers: dict[str, str],
        cookies: dict[str, str],
        max_requests: int = 10,
    ) -> list[dict[str, Any]]:
        """Active, benign injection-signature probing (SSTI/EL + CRLF).

        Sends a tiny set of arithmetic/CRLF markers to the first parameter of
        a few query-bearing pages and, if the expression is *evaluated* (the
        marker ``49`` leaks back) or a raw CR/LF is reflected, reports it.
        Read-only and non-destructive.
        """
        from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

        from app.utils.live_checks import (
            _CRLF_PAYLOAD,
            _SSTI_PAYLOADS,
            classify_injection_reflection,
        )

        findings: list[dict[str, Any]] = []
        html_pages = [
            p for p in pages
            if "html" in (p.get("content_type") or "").lower()
            and 200 <= int(p.get("status") or 0) < 300
        ]
        if not html_pages:
            return findings

        async with HttpClient(
            timeout=self.settings.request_timeout,
            headers=headers,
            cookies=cookies,
            rate_limit=int(getattr(self.settings, "rate_limit", 10)),
            max_concurrency=int(getattr(self.settings, "max_concurrency", 5)),
        ) as client:
            requests_made = 0
            for page in html_pages:
                if requests_made >= max_requests:
                    break
                page_url = page.get("url", "") or ""
                parsed = urlparse(page_url)
                qs = parse_qs(parsed.query, keep_blank_values=True)
                params = [(n, v[0]) for n, v in qs.items() if v]
                if not params:
                    continue
                name, orig = params[0]
                for payload in _SSTI_PAYLOADS + (_CRLF_PAYLOAD,):
                    if requests_made >= max_requests:
                        break
                    probe_qs = dict(qs)
                    probe_qs[name] = [orig + payload]
                    probe_url = urlunparse(
                        parsed._replace(query=urlencode(probe_qs, doseq=True))
                    )
                    try:
                        resp = await client.get(probe_url)
                    except Exception as exc:  # noqa: BLE001
                        log.warning("injection probe failed %s: %s", probe_url, exc)
                        continue
                    requests_made += 1
                    if resp.status != 200:
                        continue
                    rule = classify_injection_reflection(resp.body or "", payload)
                    if rule is None:
                        continue
                    severity = "high" if rule == "INJ-LIVE-SSTI" else "medium"
                    findings.append({
                        "rule": rule,
                        "severity": severity,
                        "confidence": 0.85,
                        "cwe": "CWE-917" if rule == "INJ-LIVE-SSTI" else "CWE-93",
                        "title": (
                            "Template/EL injection terkonfirmasi (SSTI)"
                            if rule == "INJ-LIVE-SSTI"
                            else "CRLF injection terkonfirmasi (response splitting)"
                        ),
                        "description": (
                            f"Parameter {name!r} mengevaluasi/merefleksikan marker "
                            f"injeksi {payload!r} — Expression Language injection "
                            "atau CRLF/response-splitting terkonfirmasi."
                        ),
                        "evidence": {
                            "payload": payload, "param": name, "probe_url": probe_url,
                        },
                        "remediation": (
                            "Jangan gabungkan input user ke expression/template "
                            "engine; nonaktifkan external/CRLF dan parameterisasi."
                        ),
                        "location": probe_url,
                    })
                    break
        return findings

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
                # Keep the {ID} placeholder in the URL: ReconAgent requires
                # it to build a TargetProfile, and the Prober substitutes
                # candidates into it. (The old code replaced {ID} with the
                # baseline value, so recon always failed with "no
                # placeholder found" and active probing never ran.)
                base_ctx = {
                    "url": template,
                    "baseline_id": baseline,
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

    async def _probe_reflected_xss(
        self,
        pages: list[dict[str, Any]],
        *,
        headers: dict[str, str],
        cookies: dict[str, str],
    ) -> list[dict[str, Any]]:
        """Benign, read-only reflected-XSS probe for HTML pages with query params.

        For each 2xx HTML page that carries query parameters, re-request the
        URL with a unique marker appended to each param value and check whether
        the marker is echoed back WITHOUT HTML encoding. The marker is a benign
        string ending in a single ``>`` — alphanumeric plus one ``>`` cannot
        open a tag or execute script on its own, so nothing malicious is ever
        injected (the scan stays in the PRD's read-only ethical envelope) —
        this only *observes* whether user input reflects unencoded.

        Returns findings of rule ``XS-LIVE-017`` with higher confidence than
        the passive crawl-time heuristic.
        """
        import html as _html
        from urllib.parse import parse_qs, urlencode, urlparse, urlunparse


        marker = f"Cyense{self.scan_id[:6].upper()}7>"
        encoded_marker = _html.escape(marker)
        findings: list[dict[str, Any]] = []

        html_pages = [
            p for p in pages
            if "html" in (p.get("content_type") or "").lower()
            and 200 <= int(p.get("status") or 0) < 300
        ]

        async with HttpClient(
            timeout=self.settings.request_timeout,
            headers=headers,
            cookies=cookies,
            rate_limit=int(getattr(self.settings, "rate_limit", 10)),
            max_concurrency=int(getattr(self.settings, "max_concurrency", 5)),
        ) as client:
            requests_made = 0
            for page in html_pages:
                url = page.get("url", "") or ""
                parsed = urlparse(url)
                qs = parse_qs(parsed.query, keep_blank_values=True)
                if not qs:
                    continue
                for name, values in qs.items():
                    if requests_made >= 50:  # safety cap on probe requests
                        return findings
                    for orig in values:
                        probe_val = marker if not orig else f"{orig}{marker}"
                        probe_qs = dict(qs)
                        probe_qs[name] = [probe_val]
                        probe_url = urlunparse(
                            parsed._replace(query=urlencode(probe_qs, doseq=True))
                        )
                        try:
                            resp = await client.get(probe_url)
                        except Exception as exc:  # noqa: BLE001 — best effort
                            log.warning("reflection probe failed %s: %s", probe_url, exc)
                            continue
                        requests_made += 1
                        if resp.status != 200:
                            continue
                        body = resp.body or ""
                        # Marker reflected raw AND not HTML-encoded → sink.
                        if marker in body and encoded_marker not in body:
                            findings.append({
                                "rule": "XS-LIVE-017",
                                "severity": "high",
                                "confidence": 0.8,
                                "title": f"Reflected parameter confirmed: {name!r}",
                                "description": (
                                    f"Parameter {name!r} reflects the benign probe "
                                    f"marker {marker!r} verbatim without HTML "
                                    "encoding — a confirmed reflected-XSS sink."
                                ),
                                "evidence": {
                                    "param": name,
                                    "marker": marker,
                                    "probe_url": probe_url,
                                    "sample": body[
                                        max(body.find(marker) - 40, 0):
                                        body.find(marker) + 80
                                    ][:200],
                                },
                                "remediation": (
                                    "HTML-encode the reflected value (or reject/"
                                    "validate it) before inserting into the response."
                                ),
                                "location": probe_url,
                            })
                            break  # one finding per param
        return findings

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

    async def _probe_sqli(
        self,
        pages: list[dict[str, Any]],
        *,
        headers: dict[str, str],
        cookies: dict[str, str],
    ) -> list[dict[str, Any]]:
        """Active SQL injection probing (error-based + boolean-differential).

        For each 2xx HTML page with query parameters, sends SQLi probe
        payloads via GET (read-only, non-destructive) and checks:

          1. **Error-based**: the response body contains a database error
             signature (MySQL / PostgreSQL / Oracle / SQLite / MSSQL / DB2).
          2. **Boolean-differential**: ``' AND 1=1`` vs ``' AND 1=2``
             produce materially different 200 responses — a blind SQLi
             signal.

        Returns findings with rule ``SQLI-LIVE``.
        """
        from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

        from app.utils.http_client import HttpClient

        findings: list[dict[str, Any]] = []

        html_pages = [
            p for p in pages
            if "html" in (p.get("content_type") or "").lower()
            and 200 <= int(p.get("status") or 0) < 300
        ]
        if not html_pages:
            return findings

        # Map payload name → actual payload string for boolean comparison.
        bool_true = next((p for p, n in SQLI_PAYLOADS if n == "and-true"), None)
        bool_false = next((p for p, n in SQLI_PAYLOADS if n == "and-false"), None)
        if not bool_true or not bool_false:
            return findings

        async with HttpClient(
            timeout=self.settings.request_timeout,
            headers=headers,
            cookies=cookies,
            rate_limit=int(getattr(self.settings, "rate_limit", 10)),
            max_concurrency=int(getattr(self.settings, "max_concurrency", 5)),
        ) as client:
            requests_made = 0
            for page in html_pages:
                url = page.get("url", "") or ""
                parsed = urlparse(url)
                qs = parse_qs(parsed.query, keep_blank_values=True)
                if not qs:
                    continue
                for name, values in qs.items():
                    if requests_made >= _MAX_XSS_PROBE_REQUESTS:
                        return findings
                    for orig in values:
                        if requests_made >= _MAX_XSS_PROBE_REQUESTS:
                            return findings
                        # --- error-based probes (only once per param) ---
                        _sqli_error_probed = False
                        for payload, payload_name in SQLI_PAYLOADS:
                            if _sqli_error_probed:
                                break
                            if requests_made >= _MAX_XSS_PROBE_REQUESTS:
                                return findings
                            probe_qs = dict(qs)
                            probe_val = payload if not orig else f"{orig}{payload}"
                            probe_qs[name] = [probe_val]
                            probe_url = urlunparse(
                                parsed._replace(
                                    query=urlencode(probe_qs, doseq=True)
                                )
                            )
                            try:
                                resp = await client.get(probe_url)
                            except Exception as exc:  # noqa: BLE001
                                log.warning("sqli probe failed %s: %s", probe_url, exc)
                                continue
                            requests_made += 1
                            # Error-based SQLi often returns a 500 (server
                            # error with the DB error dumped) — do NOT skip
                            # non-200 responses here; check the body for a
                            # database error signature regardless of status.
                            body = resp.body or ""
                            engines = detect_sql_errors(body)
                            if not engines:
                                continue
                            findings.append({
                                "rule": "SQLI-LIVE",
                                "severity": "critical",
                                "confidence": 0.85,
                                "title": (
                                    f"SQL injection error-based detected on "
                                    f"param {name!r}"
                                ),
                                "description": (
                                    f"Sending {payload_name!r} payload to "
                                    f"{name!r} triggered a database error "
                                    f"signature ({', '.join(engines)}) in the "
                                    "response — error-based SQL injection."
                                ),
                                "evidence": {
                                    "payload": payload,
                                    "payload_name": payload_name,
                                    "param": name,
                                    "engine": engines,
                                    "probe_url": probe_url,
                                    "sample": _evidence_sample(body, payload),
                                },
                                "remediation": (
                                    "Use parameterized queries / prepared "
                                    "statements; never concatenate user input "
                                    "into SQL text; suppress database error "
                                    "output in production."
                                ),
                                "location": probe_url,
                            })
                            _sqli_error_probed = True
                            break  # one finding per param is enough

                        # --- boolean-differential probes --------------------
                        # Send ' AND 1=1 and ' AND 1=2, compare responses.
                        # Skip when error-based SQLi was already confirmed for
                        # this param (one finding per vulnerability is enough).
                        # NOTE: _sqli_error_probed is only set when a finding
                        # was actually appended above — the previous
                        # unconditional assignment made this guard always-true
                        # and the boolean probe dead code.
                        if _sqli_error_probed:
                            continue
                        if requests_made >= _MAX_XSS_PROBE_REQUESTS:
                            return findings
                        true_qs = dict(qs)
                        true_val = bool_true if not orig else f"{orig} {bool_true}"
                        true_qs[name] = [true_val]
                        false_qs = dict(qs)
                        false_val = bool_false if not orig else f"{orig} {bool_false}"
                        false_qs[name] = [false_val]
                        true_url = urlunparse(
                            parsed._replace(query=urlencode(true_qs, doseq=True))
                        )
                        false_url = urlunparse(
                            parsed._replace(query=urlencode(false_qs, doseq=True))
                        )
                        try:
                            resp_true = await client.get(true_url)
                            resp_false = await client.get(false_url)
                        except Exception as exc:  # noqa: BLE001
                            log.warning("sqli bool probe failed: %s", exc)
                            continue
                        requests_made += 2
                        if resp_true.status != 200 or resp_false.status != 200:
                            continue
                        if is_boolean_differential(
                            resp_true.body or "", resp_false.body or ""
                        ):
                            findings.append({
                                "rule": "SQLI-LIVE",
                                "severity": "high",
                                "confidence": 0.6,
                                "title": (
                                    f"Blind SQL injection (boolean) suspected "
                                    f"on param {name!r}"
                                ),
                                "description": (
                                    f"Probing {name!r} with ' AND 1=1 vs "
                                    "' AND 1=2 produces materially different "
                                    "responses — classic boolean-based blind "
                                    "SQLi signal."
                                ),
                                "evidence": {
                                    "param": name,
                                    "and_true_url": true_url,
                                    "and_false_url": false_url,
                                    "true_size": len(resp_true.body or ""),
                                    "false_size": len(resp_false.body or ""),
                                },
                                "remediation": (
                                    "Use parameterized queries; treat all "
                                    "boolean behaviour as user-controllable "
                                    "and validate input types strictly."
                                ),
                                "location": true_url,
                            })
                        break  # one value per param is enough
        return findings


def _pages_have_query_params(pages: list[dict[str, Any]]) -> bool:
    """True if any page URL carries query parameters (a reflection surface)."""
    from urllib.parse import parse_qs, urlparse

    for page in pages:
        if parse_qs(urlparse(page.get("url", "")).query):
            return True
    return False


_SEV_RANK = {
    "critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4,
}


def _severity_rank(sev: str) -> int:
    return _SEV_RANK.get(str(sev).lower(), 5)
