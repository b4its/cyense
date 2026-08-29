"""System endpoints: /health (liveness) and /rules (active rules)."""

from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(tags=["system"])


@router.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "cyense", "version": "2.0.0"}


@router.get("/rules")
async def rules() -> dict[str, object]:
    """Active rules (PRD §4.2: link pipeline + static rules CY001-CY007)."""
    return {
        "link": [
            {
                "rule": "IDOR-LINK",
                "description": (
                    "dynamic probing with 4-step verification "
                    "(similarity, PII, retry, control-id)"
                ),
                "severity": ["critical", "high", "medium"],
            }
        ],
        "program": [
            {"rule": "CY001", "severity": "high", "lang": "python"},
            {"rule": "CY002", "severity": "high", "lang": "python"},
            {"rule": "CY003", "severity": "high", "lang": "python"},
            {"rule": "CY004", "severity": "high", "lang": "python"},
            {"rule": "CY005", "severity": "high", "lang": "python"},
            {"rule": "CY006", "severity": "critical", "lang": "python"},
            {"rule": "CY007", "severity": "high", "lang": "js"},
        ],
    }
