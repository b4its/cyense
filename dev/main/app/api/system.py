"""System endpoints: /health (liveness) and /rules (active rules)."""

from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(tags=["system"])


@router.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "cyense", "version": "2.0.0"}


@router.get("/rules")
async def rules() -> dict[str, object]:
    """Active rules (PRD §4.2 + xss-detection feature + ci-compliance-reporting)."""
    return {
        "link": [
            {
                "rule": "IDOR-LINK",
                "description": (
                    "dynamic probing with 4-step verification "
                    "(similarity, PII, retry, control-id)"
                ),
                "severity": ["critical", "high", "medium"],
                "cwe": "CWE-639",
            }
        ],
        "program": [
            {"rule": "CY001", "severity": "high", "lang": "python", "cwe": "CWE-639", "cvss_score": 6.5, "cvss_vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"},
            {"rule": "CY002", "severity": "high", "lang": "python", "cwe": "CWE-639", "cvss_score": 6.5, "cvss_vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"},
            {"rule": "CY003", "severity": "high", "lang": "python", "cwe": "CWE-639", "cvss_score": 6.5, "cvss_vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"},
            {"rule": "CY004", "severity": "high", "lang": "python", "cwe": "CWE-639", "cvss_score": 6.5, "cvss_vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"},
            {"rule": "CY005", "severity": "high", "lang": "python", "cwe": "CWE-639", "cvss_score": 6.5, "cvss_vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"},
            {"rule": "CY006", "severity": "critical", "lang": "python", "cwe": "CWE-22", "cvss_score": 6.5, "cvss_vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"},
            {"rule": "CY007", "severity": "high", "lang": "js", "cwe": "CWE-639", "cvss_score": 6.5, "cvss_vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"},
            {"rule": "CY008", "severity": "high", "lang": "js", "cwe": "CWE-639", "cvss_score": 6.5, "cvss_vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"},
            {"rule": "CY009", "severity": "high", "lang": "php", "cwe": "CWE-639", "cvss_score": 6.5, "cvss_vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"},
            {"rule": "CY010", "severity": "high", "lang": "php", "cwe": "CWE-639", "cvss_score": 6.5, "cvss_vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"},
        ],
        "xss": [
            {"rule": "XS001", "severity": "high", "lang": "js", "cwe": "CWE-79", "cvss_score": 6.1, "cvss_vector": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
             "title": "innerHTML assigned a dynamic value"},
            {"rule": "XS002", "severity": "high", "lang": "js", "cwe": "CWE-79", "cvss_score": 6.1, "cvss_vector": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
             "title": "document.write with a dynamic value"},
            {"rule": "XS003", "severity": "high", "lang": "js", "cwe": "CWE-79", "cvss_score": 6.1, "cvss_vector": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
             "title": "dangerouslySetInnerHTML fed a dynamic value"},
            {"rule": "XS004", "severity": "critical", "lang": "js", "cwe": "CWE-95", "cvss_score": 9.8, "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
             "title": "eval/new Function on dynamic input"},
            {"rule": "XS005", "severity": "high", "lang": "js", "cwe": "CWE-79", "cvss_score": 6.1, "cvss_vector": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
             "title": "v-html bound to a dynamic expression"},
            {"rule": "XS006", "severity": "high", "lang": "php", "cwe": "CWE-79", "cvss_score": 6.1, "cvss_vector": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
             "title": "PHP echo/print of superglobal input"},
            {"rule": "XS007", "severity": "high", "lang": "python", "cwe": "CWE-79", "cvss_score": 6.1, "cvss_vector": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
             "title": "Jinja2 |safe filter disables auto-escaping"},
            {"rule": "XS008", "severity": "medium", "lang": "python", "cwe": "CWE-79", "cvss_score": 4.7, "cvss_vector": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N",
             "title": "HTML string composed via f-string/format"},
        ],
    }
