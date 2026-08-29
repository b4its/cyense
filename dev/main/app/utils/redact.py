"""Credential redaction (PRD v2.0 §9: keamanan service).

Every log line, evidence blob and report must pass through
``redact_headers`` / ``redact_mapping`` so Authorization/Cookie values never
leave the service (ground rule #8).
"""

from __future__ import annotations

import re

SENSITIVE_KEYS = {"authorization", "cookie", "set-cookie", "proxy-authorization", "x-api-key"}
_REDACTED = "[REDACTED]"


def redact_value(value: str) -> str:
    value = value.strip()
    if len(value) <= 8:
        return _REDACTED
    return f"{value[:4]}...{value[-4:]} [REDACTED]"


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, value in headers.items():
        if key.lower() in SENSITIVE_KEYS:
            out[key] = redact_value(value) if value else _REDACTED
        else:
            out[key] = value
    return out


def redact_mapping(mapping: dict[str, str]) -> dict[str, str]:
    return redact_headers(mapping)


def redact_cookies(cookies: dict[str, str]) -> dict[str, str]:
    return {key: _REDACTED for key in cookies}


def redact_url_credentials(url: str) -> str:
    return re.sub(r"(https?://)([^/@\s]+)@", r"\1[REDACTED]@", url)
