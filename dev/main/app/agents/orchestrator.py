"""Orchestrator — runs the agentic pipeline (PRD v2.0 §1.2, §4.1).

Pipeline (mode LINK):  Recon → Prober → Verifier → Report
The 🧠 Brain is consulted at every stage.
"""

from __future__ import annotations

import time
from typing import Any

from app.agents.brain import Brain
from app.agents.prober import ProberAgent
from app.agents.recon import ReconAgent
from app.agents.verifier import VerifierAgent
from app.core.models import Finding, Severity, VerificationEvidence
from app.utils.redact import redact_cookies, redact_headers

SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

REMEDIATION = {
    "critical": (
        "Return object ownership immediately: scope every DB lookup by the "
        "authenticated user (e.g. filter by user_id), deny cross-account access, "
        "and avoid sequential/enumerable identifiers for sensitive objects."
    ),
    "high": (
        "Add server-side authorization checks per object (not per role), and "
        "prefer indirect references (opaque ids) for sensitive resources."
    ),
    "medium": (
        "Investigate manually: endpoint behaved inconsistently during probing; "
        "add explicit ownership checks and deterministic error responses."
    ),
}


class Orchestrator:
    def __init__(
        self,
        scan_id: str,
        brain: Brain,
        reports_dir: str,
        settings: Any,
    ) -> None:
        self.scan_id = scan_id
        self.brain = brain
        self.reports_dir = reports_dir
        self.settings = settings

    async def run_link(self, request_dict: dict[str, Any]) -> dict[str, Any]:
        started = time.monotonic()
        headers = request_dict.get("headers", {}) or {}
        cookies = request_dict.get("cookies", {}) or {}
        self._method = request_dict.get("method", "GET")

        recon = ReconAgent(self.scan_id, self.reports_dir, brain=self.brain)
        prober = ProberAgent(self.scan_id, self.reports_dir, brain=self.brain)
        verifier = VerifierAgent(self.scan_id, self.reports_dir)

        base_ctx = {
            "url": str(request_dict["url"]),
            "headers": headers,
            "cookies": cookies,
            "baseline_id": request_dict.get("baseline_id"),
            "timeout": self.settings.request_timeout,
            "rate_limit": self.settings.rate_limit,
            "max_concurrency": self.settings.max_concurrency,
            "probe_max": self.settings.probe_max,
            "similarity_threshold": self.settings.similarity_threshold,
            "verify_retries": self.settings.verify_retries,
            "control_id": self.settings.control_id,
            "method": request_dict.get("method", "GET"),
            "probe_ids": request_dict.get("probe_ids", "auto"),
        }

        # stage 1 — recon
        recon_result = await recon(base_ctx)
        if not recon_result.ok:
            return self._empty_report(recon_result.error, started)

        # stage 2 — probe
        probe_ctx = dict(base_ctx)
        probe_ctx["profile"] = recon_result.data["profile"]
        probe_ctx["baseline_body"] = recon_result.data.get("baseline_body", "")
        if isinstance(base_ctx["probe_ids"], list):
            probe_ctx["probe_ids"] = base_ctx["probe_ids"]
        else:
            probe_ctx["probe_ids"] = None
        probe_result = await prober(probe_ctx)
        if not probe_result.ok:
            return self._empty_report(probe_result.error, started)

        # stage 3 — verify
        verify_ctx = dict(base_ctx)
        verify_ctx["profile"] = recon_result.data["profile"]
        verify_ctx["baseline_body"] = recon_result.data.get("baseline_body", "")
        verify_ctx["hits_internal"] = probe_result.data.get("hits_internal", [])
        verify_result = await verifier(verify_ctx)

        # stage 4 — report
        findings = self._build_findings(verify_result.data, headers, cookies)
        findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], -f.confidence))

        summary = {
            "critical": sum(1 for f in findings if f.severity == Severity.CRITICAL),
            "high": sum(1 for f in findings if f.severity == Severity.HIGH),
            "medium": sum(1 for f in findings if f.severity == Severity.MEDIUM),
            "low": sum(1 for f in findings if f.severity == Severity.LOW),
            "info": sum(1 for f in findings if f.severity == Severity.INFO),
            "total": len(findings),
            "rejected_false_positives": len(verify_result.data.get("rejected", [])),
            "duration_ms": int((time.monotonic() - started) * 1000),
        }
        return {
            "meta": {
                "scan_id": self.scan_id,
                "mode": "link",
                "engine": "agentic",
                "pipeline": ["recon", "probe", "verify", "report"],
            },
            "summary": summary,
            "findings": [f.model_dump(mode="json") for f in findings],
        }

    # -- helpers ---------------------------------------------------------------

    def _build_findings(
        self,
        data: dict[str, Any],
        headers: dict[str, str],
        cookies: dict[str, str],
    ) -> list[Finding]:
        findings: list[Finding] = []
        for i, item in enumerate(data.get("findings", []), start=1):
            verification = dict(item.get("verification", {}))
            finding = Finding(
                finding_id=f"{self.scan_id}-L{i:03d}",
                rule="IDOR-LINK",
                severity=Severity(item["severity"]),
                confidence=item["confidence"],
                title=f"IDOR via object id '{item['probe_id']}' on {self._path_of(item['url'])}",
                description=(
                    f"Endpoint returned object data for foreign id '{item['probe_id']}' "
                    f"with HTTP {item['status']}."
                ),
                evidence={
                    "request": {
                        "method": self._method,
                        "url": item["url"],
                        "headers": redact_headers(headers),
                        "cookies": redact_cookies(cookies),
                    },
                    "response": {
                        "status": item["status"],
                        "headers": item.get("evidence_headers", {}),
                        "body_snippet": item.get("body_snippet", ""),
                    },
                },
                verification=VerificationEvidence(**verification),
                remediation=REMEDIATION.get(item["severity"], REMEDIATION["high"]),
            )
            findings.append(finding)
        return findings

    @staticmethod
    def _path_of(url: str) -> str:
        from urllib.parse import urlparse

        return urlparse(url).path

    @staticmethod
    def _empty_report(error: str, started: float) -> dict[str, Any]:
        return {
            "meta": {
                "scan_id": "",
                "mode": "link",
                "engine": "agentic",
                "pipeline": ["recon"],
                "error": error,
            },
            "summary": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
                "total": 0,
                "rejected_false_positives": 0,
                "duration_ms": int((time.monotonic() - started) * 1000),
            },
            "findings": [],
        }
