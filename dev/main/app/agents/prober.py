"""🕵️ PROBER agent — candidate ID generation & parallel probing (PRD §4.1 stage 2).

Strategies:
* increment/decrement around baseline_id (±1..probe_max)
* wordlist (wordlists/ids.txt)
* adaptive: valid-id hit expands probing around that id (agent behaviour)

Every response is classified: same-shape / different-shape / blocked / error.
Findings are remembered in the 🧠 Brain.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.agents.base import AgentResult, BaseAgent
from app.agents.recon import TargetProfile
from app.utils.http_client import HttpClient, Response
from app.utils.redact import redact_headers
from app.utils.similarity import similarity

WORDLIST_PATH = Path(__file__).resolve().parents[2] / "wordlists" / "ids.txt"


@dataclass
class ProbeHit:
    probe_id: str
    url: str
    status: int
    similarity: float
    classification: str  # same-shape | different-shape | blocked | error
    body: str = ""
    headers: dict[str, str] = field(default_factory=dict)

    def to_dict(self, redact: bool = True) -> dict[str, Any]:
        return {
            "probe_id": self.probe_id,
            "url": self.url,
            "status": self.status,
            "similarity": round(self.similarity, 3),
            "classification": self.classification,
            "headers": redact_headers(self.headers) if redact else self.headers,
        }


class ProberAgent(BaseAgent):
    name = "prober"

    def __init__(
        self,
        scan_id: str,
        reports_dir: str | Path,
        brain: Any | None = None,
        wordlist_path: Path | None = None,
    ) -> None:
        super().__init__(scan_id, reports_dir)
        self.brain = brain
        self.wordlist_path = wordlist_path or WORDLIST_PATH

    async def run(self, ctx: dict[str, Any]) -> AgentResult:
        profile = TargetProfile.from_dict(ctx["profile"])
        headers: dict[str, str] = ctx.get("headers", {}) or {}
        cookies: dict[str, str] = ctx.get("cookies", {}) or {}
        method: str = ctx.get("method", "GET")
        probe_max: int = int(ctx.get("probe_max", 50))
        requested_ids: list[str] | None = ctx.get("probe_ids")
        baseline_body: str = ctx.get("baseline_body", "")
        # The caller's own object id (LinkScanRequest.baseline_id). Numeric
        # candidates are generated AROUND this id — previously it was ignored
        # and probing always centred on "1".
        baseline_id: str | None = ctx.get("baseline_id")

        # recall previous knowledge about this host (Brain memory capability)
        known_valid: list[str] = []
        if self.brain is not None:
            memory = self.brain.recall_host(profile.host)
            known_valid = list(memory.get("valid_ids", []))
            if known_valid:
                self.trajectory.step("brain_recall", {"valid_ids": known_valid})

        # build candidate list
        candidates = self._candidates(
            requested_ids, known_valid, profile, probe_max, baseline_id
        )
        self.trajectory.step("candidates_built", {"count": len(candidates)})

        baseline_body = baseline_body or profile.baseline_body
        hits: list[ProbeHit] = []
        valid_ids: list[str] = []

        async with HttpClient(
            timeout=ctx.get("timeout", 10.0),
            headers=headers,
            cookies=cookies,
            rate_limit=int(ctx.get("rate_limit", 50)),
            max_concurrency=int(ctx.get("max_concurrency", 10)),
        ) as client:
            # baseline reference for shape comparison (if not fetched in recon)
            if not baseline_body and profile.baseline_status == 0 and candidates:
                resp0 = await client.get(self._render(profile, candidates[0]))
                baseline_body = resp0.body if resp0.status else ""

            probe_ids = list(candidates)
            fired: set[str] = set()
            unreachable = 0  # probe responses with status 0 (connection failed)
            for _round in range(2):  # round 2 = adaptive expansion
                fired_before = set(fired)
                tasks = [self._probe_one(client, method, profile, pid, baseline_body)
                         for pid in probe_ids if pid not in fired]
                results = await asyncio.gather(*tasks)
                for hit in results:
                    fired.add(hit.probe_id)
                    if hit.status == 0:
                        unreachable += 1
                    if hit.classification in ("same-shape", "different-shape"):
                        valid_ids.append(hit.probe_id)
                    # forward every 200 candidate to the verifier; it decides
                    # (control-id + similarity + PII) what is a real object
                    if hit.status == 200:
                        hits.append(hit)

                # adaptive step: expand around valid ids discovered THIS round
                # (comparing against the whole candidate list was always empty
                # — round 0 fires exactly the candidates — so the adaptive
                # expansion never ran and was dead code)
                new_valid = [v for v in valid_ids if v not in fired_before]
                if not new_valid:
                    break
                seed = new_valid[0]
                expansion = self._numeric_neighbours(seed, 5)
                expansion = [e for e in expansion if e not in fired]
                if not expansion:
                    break
                self.trajectory.step("adaptive_expand", {"seed": seed, "count": len(expansion)})
                probe_ids = expansion

        # If we fired candidates but every response was a connection error
        # (status 0), the target is unreachable — surface as a scan FAILURE
        # instead of silently completing with zero findings (which made the
        # web UI show "Tidak ada temuan" with no explanation). This happens
        # e.g. when the URL points at a host the API container cannot reach
        # (localhost from inside Docker is the API container itself).
        if fired and unreachable == len(fired) and not hits:
            return AgentResult(
                agent=self.name,
                ok=False,
                error=(
                    f"target tidak terjangkau: semua {len(fired)} probe gagal "
                    "terhubung (connection refused/timeout). Periksa URL dan "
                    "jaringan — dari container API, 'localhost' adalah container "
                    "itu sendiri, bukan host/lab."
                ),
            )

        data = {
            # external-safe view (redacted headers, no body)
            "hits": [h.to_dict() for h in hits],
            # internal view for the verifier: same hits with response bodies
            "hits_internal": [
                {
                    "probe_id": h.probe_id,
                    "url": h.url,
                    "status": h.status,
                    "similarity": h.similarity,
                    "classification": h.classification,
                    "body": h.body,
                    "headers": h.headers,
                }
                for h in hits
            ],
            "valid_ids": sorted(set(valid_ids)),
            "candidates_fired": len(fired),
        }
        return AgentResult(agent=self.name, ok=True, data=data)

    # -- internals ------------------------------------------------------------

    async def _probe_one(
        self,
        client: HttpClient,
        method: str,
        profile: TargetProfile,
        probe_id: str,
        baseline_body: str,
    ) -> ProbeHit:
        url = self._render(profile, probe_id)
        resp: Response = await client.request(method, url)
        return self._classify(probe_id, url, resp, baseline_body)

    def _classify(
        self, probe_id: str, url: str, resp: Response, baseline_body: str
    ) -> ProbeHit:
        sim = similarity(resp.body, baseline_body) if baseline_body else 0.0
        if resp.status == 0:
            cls = "error"
        elif resp.blocked:
            cls = "blocked"
        elif baseline_body and sim >= 0.85:
            cls = "same-shape"
        elif baseline_body:
            cls = "different-shape"
        else:
            cls = "unknown"
        return ProbeHit(
            probe_id=probe_id,
            url=url,
            status=resp.status,
            similarity=sim,
            classification=cls,
            body=resp.body,
            headers=resp.headers,
        )

    def _candidates(
        self,
        requested: list[str] | None,
        known_valid: list[str],
        profile: TargetProfile,
        probe_max: int,
        baseline_id: str | None = None,
    ) -> list[str]:
        candidates: list[str] = []
        if requested:  # explicit list wins
            candidates = list(requested)
        else:
            # Prefer the caller-supplied own-id; fall back to the numeric
            # default when absent (keeps auto mode deterministic).
            baseline = baseline_id if baseline_id else self._baseline_id_hint(profile)
            if profile.placeholders and profile.placeholders[0] == "email":
                candidates = self._load_wordlist()
            elif baseline.isdigit():
                candidates = self._numeric_neighbours(baseline, probe_max)
            else:
                candidates = self._load_wordlist()
        # merge known valid ids from brain (memory), keep order, dedupe
        for kid in known_valid:
            if kid not in candidates:
                candidates.append(kid)
        # always include the control id later in verifier; not probed here
        seen: set[str] = set()
        ordered = [c for c in candidates if not (c in seen or seen.add(c))]
        return ordered

    @staticmethod
    def _baseline_id_hint(profile: TargetProfile) -> str:
        # Without an explicit baseline the numeric default is "1"; callers
        # should prefer explicit probe_ids for determinism.
        return "1"

    def _numeric_neighbours(self, seed: str, spread: int) -> list[str]:
        try:
            base = int(seed)
        except ValueError:
            return self._load_wordlist()
        out = []
        for delta in range(1, spread + 1):
            out.append(base + delta)
            out.append(base - delta)
        return [str(n) for n in out if n >= 0]

    def _load_wordlist(self) -> list[str]:
        # wordlist_path may be str or Path (callers historically passed Path;
        # be defensive so a str never crashes with AttributeError).
        path = Path(self.wordlist_path)
        try:
            lines = path.read_text().splitlines()
            return [line.strip() for line in lines if line.strip()]
        except OSError:
            return []

    @staticmethod
    def _render(profile: TargetProfile, probe_id: str) -> str:
        """Substitute probe_id into the active ``{PLACEHOLDER}`` of the template.

        Only the placeholder being actively probed (``profile.placeholders[0]``,
        the same one recon fills for the baseline) is replaced. Any *other*
        ``{...}`` tokens — e.g. ``{version}`` or a second, non-target id — are
        left literal. Previously *every* ``{...}`` token was substituted with
        the same candidate, so a URL like ``/v/{version}/invoice/{ID}`` was
        probed as ``/v/5/invoice/5`` instead of ``/v/{version}/invoice/5``
        (mirrors the crawler's "only the first ID becomes the placeholder" rule).

        The replacement goes through a lambda so the id is treated as a
        literal: a user-supplied probe id containing backslashes (e.g.
        ``\\1``) would otherwise be interpreted as a regex group reference
        and crash re.sub with ``re.error: invalid group reference``.
        """
        import re

        target = profile.placeholders[0].lower() if profile.placeholders else None
        if target is None:
            # No placeholders known: leave the URL untouched rather than
            # corrupting every {token} (defensive; recon rejects these URLs).
            return profile.url_template
        return re.sub(
            r"\{([A-Za-z_][A-Za-z0-9_]*)\}",
            lambda m: probe_id if m.group(1).lower() == target else m.group(0),
            profile.url_template,
        )


__all__ = ["ProberAgent", "ProbeHit", "redact_headers"]
