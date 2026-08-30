"""System endpoints: /health (liveness) and /rules (active rules)."""

from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(tags=["system"])


@router.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "cyense", "version": "2.0.0"}


@router.get("/rules")
async def rules() -> dict[str, object]:
    """Active rules (PRD §4.2 + xss-detection feature)."""
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
            {"rule": "CY008", "severity": "high", "lang": "js"},
            {"rule": "CY009", "severity": "high", "lang": "php"},
            {"rule": "CY010", "severity": "high", "lang": "php"},
        ],
        "xss": [
            {"rule": "XS001", "severity": "high", "lang": "js",
             "title": "innerHTML assigned a dynamic value"},
            {"rule": "XS002", "severity": "high", "lang": "js",
             "title": "document.write with a dynamic value"},
            {"rule": "XS003", "severity": "high", "lang": "js",
             "title": "dangerouslySetInnerHTML fed a dynamic value"},
            {"rule": "XS004", "severity": "critical", "lang": "js",
             "title": "eval/new Function on dynamic input"},
            {"rule": "XS005", "severity": "high", "lang": "js",
             "title": "v-html bound to a dynamic expression"},
            {"rule": "XS006", "severity": "high", "lang": "php",
             "title": "PHP echo/print of superglobal input"},
            {"rule": "XS007", "severity": "high", "lang": "python",
             "title": "Jinja2 |safe filter disables auto-escaping"},
            {"rule": "XS008", "severity": "medium", "lang": "python",
             "title": "HTML string composed via f-string/format"},
        ],
    }
