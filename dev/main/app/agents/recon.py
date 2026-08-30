"""🎯 RECON agent — target profiling & probing strategy (PRD v2.0 §4.1 stage 1).

Responsibilities:
* parse the target URL and detect placeholders ({ID}, {UID}, {GUID}, {EMAIL})
* fetch the baseline response (caller-supplied own id) and fingerprint it
  (server header, framework hints in body, content-type)
* ask the 🧠 Brain for a probing strategy based on the fingerprint
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from app.agents.base import AgentResult, BaseAgent
from app.utils.http_client import HttpClient
from app.utils.redact import redact_headers

PLACEHOLDER_RE = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")
KNOWN_PLACEHOLDERS = {"id", "uid", "guid", "email"}

FRAMEWORK_HINTS = {
    "django": ["csrf", "django"],
    "flask": ["werkzeug", "flask"],
    "laravel": ["laravel", "xsrf"],
    "rails": ["rails", "phusion"],
    "express": ["express", "x-powered-by"],
    "aspnet": ["asp.net", "x-aspnet"],
    "spring": ["x-application-context", "spring"],
}


@dataclass
class TargetProfile:
    url_template: str
    host: str
    placeholders: list[str] = field(default_factory=list)
    framework: str | None = None
    server: str | None = None
    content_type: str | None = None
    baseline_status: int = 0
    baseline_body: str = ""
    strategy: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "url_template": self.url_template,
            "host": self.host,
            "placeholders": self.placeholders,
            "framework": self.framework,
            "server": self.server,
            "content_type": self.content_type,
            "baseline_status": self.baseline_status,
            "baseline_body_len": len(self.baseline_body),
            "strategy": self.strategy,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TargetProfile:
        """Rebuild from a to_dict() payload (ignores derived summary keys)."""
        known = {
            "url_template",
            "host",
            "placeholders",
            "framework",
            "server",
            "content_type",
            "baseline_status",
            "baseline_body",
            "strategy",
        }
        # `baseline_body` is intentionally NOT persisted (may be large); a
        # profile rebuilt from a report keeps comparison fields empty.
        payload = {k: v for k, v in data.items() if k in known}
        payload.pop("baseline_body", None)
        return cls(**payload)


class ReconAgent(BaseAgent):
    name = "recon"

    def __init__(
        self,
        scan_id: str,
        reports_dir: str | Path,
        brain: Any | None = None,
    ) -> None:
        super().__init__(scan_id, reports_dir)
        self.brain = brain

    async def run(self, ctx: dict[str, Any]) -> AgentResult:
        url = str(ctx["url"])
        headers: dict[str, str] = ctx.get("headers", {}) or {}
        cookies: dict[str, str] = ctx.get("cookies", {}) or {}
        baseline_id: str | None = ctx.get("baseline_id")

        profile = TargetProfile(url_template=url, host=urlparse(url).netloc)
        profile.placeholders = self._detect_placeholders(url)
        self.trajectory.step("placeholders_detected", {"placeholders": profile.placeholders})

        if not profile.placeholders:
            return AgentResult(
                agent=self.name,
                ok=False,
                error="no {ID}-style placeholder found in url (use e.g. /invoice/{ID})",
            )

        # fetch baseline (own-id response) for fingerprinting & later comparison
        if baseline_id:
            template = self._fill(url, profile.placeholders[0], baseline_id)
            async with HttpClient(
                timeout=ctx.get("timeout", 10.0),
                headers=headers,
                cookies=cookies,
                rate_limit=ctx.get("rate_limit", 50),
                max_concurrency=ctx.get("max_concurrency", 10),
            ) as client:
                resp = await client.get(template)
            profile.baseline_status = resp.status
            profile.baseline_body = resp.body
            profile.server = resp.headers.get("server")
            profile.content_type = resp.headers.get("content-type")
            profile.framework = self._fingerprint(resp.headers, resp.body)
            self.trajectory.step(
                "baseline_fetched",
                {
                    "status": resp.status,
                    "framework": profile.framework,
                    "body_len": len(resp.body),
                },
            )

        # ask the Brain for a probing strategy (memory/knowledge capability)
        if self.brain is not None:
            fingerprint = {"framework": profile.framework, "server": profile.server}
            profile.strategy = self.brain.strategy_for(fingerprint)
            self.trajectory.step("brain_strategy", profile.strategy)

        data = {"profile": profile.to_dict()}
        # internal-only: baseline body for downstream verification (never
        # logged or reported; response bodies are target-owned data)
        data["baseline_body"] = profile.baseline_body
        return AgentResult(agent=self.name, ok=True, data=data)

    # -- helpers -------------------------------------------------------------

    @staticmethod
    def _detect_placeholders(url: str) -> list[str]:
        found = []
        for match in PLACEHOLDER_RE.finditer(url):
            name = match.group(1).lower()
            if name in KNOWN_PLACEHOLDERS and name not in found:
                found.append(name)
        return found

    @staticmethod
    def _fill(url: str, placeholder: str, value: str) -> str:
        return re.sub(
            PLACEHOLDER_RE,
            lambda m, _p=placeholder: value if m.group(1).lower() == placeholder else m.group(0),
            url,
        )

    @staticmethod
    def _fingerprint(headers: dict[str, str], body: str) -> str | None:
        server = headers.get("server", "").lower()
        powered = headers.get("x-powered-by", "").lower()
        body_lower = body[:4000].lower()
        for name, hints in FRAMEWORK_HINTS.items():
            for hint in hints:
                if hint in server or hint in powered or hint in body_lower:
                    return name
        return None


__all__ = ["ReconAgent", "TargetProfile", "redact_headers"]
