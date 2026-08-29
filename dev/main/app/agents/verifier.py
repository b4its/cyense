"""⚖️ VERIFIER agent — 4-step verification with control-ID check (PRD §4.1 stage 3).

For each prober candidate (200 + baseline-like shape):
1. similarity vs baseline (>= threshold)
2. cross-account PII (emails/phones belonging to another user)
3. consistency: repeat the request, result must be stable
4. CONTROL-ID: a request with a definitely-nonexistent id must be
   blocked (401/403/404/redirect). If it also returns 200 the endpoint is
   "generic-200" → false positive → rejected.

This is the innovation that separates Cyense from naive scanners.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from app.agents.base import AgentResult, BaseAgent
from app.agents.prober import ProbeHit
from app.agents.recon import TargetProfile
from app.utils.http_client import HttpClient
from app.utils.pii import extract_pii, pii_diff
from app.utils.redact import redact_headers, redact_url_credentials
from app.utils.similarity import similarity


class VerifierAgent(BaseAgent):
    name = "verifier"

    async def run(self, ctx: dict[str, Any]) -> AgentResult:
        profile = TargetProfile.from_dict(ctx["profile"])
        baseline_body: str = ctx.get("baseline_body", "")
        hits = [ProbeHit(**h) for h in ctx.get("hits_internal", [])
                if isinstance(h, dict)]
        headers: dict[str, str] = ctx.get("headers", {}) or {}
        cookies: dict[str, str] = ctx.get("cookies", {}) or {}
        control_id: str = str(ctx.get("control_id", "99999999"))
        threshold: float = float(ctx.get("similarity_threshold", 0.85))
        retries: int = int(ctx.get("verify_retries", 2))

        baseline_pii = extract_pii(baseline_body)

        async with HttpClient(
            timeout=ctx.get("timeout", 10.0),
            headers=headers,
            cookies=cookies,
            rate_limit=int(ctx.get("rate_limit", 50)),
            max_concurrency=int(ctx.get("max_concurrency", 10)),
        ) as client:
            control = await client.get(self._render(profile, control_id))
            control_blocked = control.blocked or control.status == 404
            self.trajectory.step(
                "control_id",
                {"id": control_id, "status": control.status, "blocked": control_blocked},
            )
            if not control_blocked:
                self.trajectory.step("generic_200_detected", {"note": "control id also 200"})

            verified: list[dict[str, Any]] = []
            for hit in hits:
                verdict = await self._verify_one(
                    client, profile, hit, baseline_pii, baseline_body, threshold, retries
                )
                verdict["verification"]["control_id_blocked"] = control_blocked
                # step 4 — control-id comparison (negative control):
                # a candidate whose body is indistinguishable from the
                # control-id response is a placeholder page, not an object.
                sim_to_control = (
                    similarity(hit.body, control.body) if not control_blocked and control.body else None
                )
                verdict["verification"]["similarity_to_control"] = (
                    round(sim_to_control, 3) if sim_to_control is not None else None
                )
                generic = (
                    not control_blocked
                    and not verdict["verification"]["pii_matches"]
                    and self._same_shape(hit.body, control.body)
                )
                if generic:
                    verdict["severity"] = None
                    verdict["confidence"] = 0.1
                    verdict["verification"]["notes"] = (
                        "generic-200: response identical to control-id response "
                        "without PII evidence; cannot confirm cross-account access"
                    )
                verified.append(verdict)
                self.trajectory.step(
                    "verified_candidate",
                    {"probe_id": hit.probe_id, "severity": verdict["severity"],
                     "confidence": verdict["confidence"]},
                )

        rejected = [v for v in verified if v["severity"] is None]
        accepted = [v for v in verified if v["severity"] is not None]
        return AgentResult(
            agent=self.name,
            ok=True,
            data={"findings": accepted, "rejected": rejected},
        )

    # -- verification of a single candidate -----------------------------------

    async def _verify_one(
        self,
        client: HttpClient,
        profile: TargetProfile,
        hit: ProbeHit,
        baseline_pii: list[str],
        baseline_body: str,
        threshold: float,
        retries: int,
    ) -> dict[str, Any]:
        url = redact_url_credentials(hit.url)
        evidence_headers = redact_headers(hit.headers)

        # step 1: similarity (recomputed on fresh copy for accuracy)
        sim = similarity(hit.body, baseline_body) if baseline_body else None

        # step 2: cross-account PII
        pii = extract_pii(hit.body)
        other_pii = pii_diff(pii, baseline_pii)

        # step 3: consistency retry
        statuses = []
        consistent = True
        for _ in range(max(retries - 1, 1)):
            again = await client.get(hit.url)
            statuses.append(again.status)
            if again.status != hit.status:
                consistent = False

        # step 4: control-id result is shared, but candidate-level we still
        # classify (control check happens once per scan; see run())
        notes_parts = []
        if other_pii:
            notes_parts.append(f"cross-account pii: {', '.join(other_pii[:3])}")

        verification = {
            "similarity": round(sim, 3) if sim is not None else None,
            "pii_matches": other_pii,
            "retry_consistent": consistent if statuses else None,
            "control_id_blocked": None,  # filled by caller knowledge below
            "notes": "; ".join(notes_parts),
        }

        severity, confidence = self._score(
            status=hit.status,
            sim=sim,
            threshold=threshold,
            pii=other_pii,
            consistent=consistent if statuses else None,
        )
        return {
            "probe_id": hit.probe_id,
            "url": url,
            "status": hit.status,
            "evidence_headers": evidence_headers,
            "verification": verification,
            "severity": severity,
            "confidence": confidence,
            "body_snippet": hit.body[:400],
        }

    @staticmethod
    def _score(
        status: int,
        sim: float | None,
        threshold: float,
        pii: list[str],
        consistent: bool | None,
    ) -> tuple[str | None, float]:
        """Map signals → (severity|None, confidence) per PRD §4.1 table."""
        if status != 200:
            return None, 0.0
        if pii and (consistent is None or consistent):
            return "critical", 0.95
        if sim is not None and sim >= threshold:
            if consistent is False:
                return "medium", 0.5  # flaky → manual review
            return "high", 0.8
        # different shape from baseline but still a 200 object response:
        # defer to the control-id comparison (caller rejects generic bodies).
        return "medium", 0.5

    @staticmethod
    def _same_shape(candidate_body: str, control_body: str) -> bool:
        """True if candidate response is structurally identical to the control.

        JSON bodies are compared by key set (robust to value changes like the
        echoed id); non-JSON bodies fall back to text similarity.
        """
        try:
            cand = json.loads(candidate_body)
            ctrl = json.loads(control_body)
        except (json.JSONDecodeError, TypeError):
            return similarity(candidate_body, control_body) >= 0.8
        if isinstance(cand, dict) and isinstance(ctrl, dict):
            return set(cand.keys()) == set(ctrl.keys())
        return similarity(candidate_body, control_body) >= 0.8

    @staticmethod
    def _render(profile: TargetProfile, value: str) -> str:
        import re

        return re.sub(r"\{[A-Za-z_][A-Za-z0-9_]*\}", value, profile.url_template)


__all__ = ["VerifierAgent", "redact_headers"]
