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
        port_findings: list[dict[str, Any]] = []
        open_ports_data: list[dict[str, Any]] = []
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

        # ------------------------------------------------------------------
        # Stage 5: SQL injection probing (error-based + boolean differential)
        # ------------------------------------------------------------------
        await self._notify("sqli")
        sqli_findings = await self._probe_sqli(
            pages, headers=headers, cookies=cookies,
        )
        for k, f in enumerate(sqli_findings, start=len(xss_findings) + 1):
            f["finding_id"] = f"{self.scan_id}-WSQLI{k:03d}"
            xss_findings.append(f)

        # ------------------------------------------------------------------
        # Stage 6: Report
        # ------------------------------------------------------------------
        await self._notify("report")
        all_findings = (
            idor_findings + tech_findings + port_findings
            + cve_findings + xss_findings
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
                    "cve", "probe", "sqli", "report",
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
        bool_true = next(p for p, n in SQLI_PAYLOADS if n == "and-true")
        bool_false = next(p for p, n in SQLI_PAYLOADS if n == "and-false")

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
                                    "sample": body[
                                        max(body.find(payload) - 40, 0):
                                        body.find(payload) + 160
                                    ][:200],
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

                        _sqli_error_probed = True

                        # --- boolean-differential probes --------------------
                        # Send ' AND 1=1 and ' AND 1=2, compare responses.
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
