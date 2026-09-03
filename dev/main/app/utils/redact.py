"""Credential redaction (PRD v2.0 §9: keamanan service).

Every log line, evidence blob and report must pass through
``redact_headers`` / ``redact_mapping`` so Authorization/Cookie values never
leave the service (ground rule #8).
"""

from __future__ import annotations

import re

SENSITIVE_KEYS = {"authorization", "cookie", "set-cookie", "proxy-authorization", "x-api-key"}
# Additional header *name* patterns that commonly carry credentials/scanner
# auth (e.g. X-Api-Token, X-Custom-Auth, api-key, client-secret, x-signature).
# A user-supplied auth header under any of these would otherwise be stored and
# rendered unredacted in reports/trajectories (ground rule #8).
_SENSITIVE_NAME_RE = re.compile(
    r"(authorization|credential|secret|passwd|password|api[_-]?key|x[_-]?api[_-]?token"
    r"|(^|[^a-z0-9])(token|auth|signature|session)([^a-z0-9]|$)|bearer)",
    re.I,
)
_REDACTED = "[REDACTED]"


def _key_is_sensitive(key: str) -> bool:
    low = key.lower()
    if low in SENSITIVE_KEYS:
        return True
    return bool(_SENSITIVE_NAME_RE.search(low))


def redact_value(value: str) -> str:
    if not isinstance(value, str):
        return _REDACTED
    value = value.strip()
    if len(value) <= 8:
        return _REDACTED
    return f"{value[:4]}...{value[-4:]} [REDACTED]"


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, value in headers.items():
        if _key_is_sensitive(key):
            out[key] = redact_value(value) if value else _REDACTED
        else:
            # Even an innocuously-named header may carry a URL-embedded
            # credential (e.g. Referer/Origin with userinfo); scrub those.
            out[key] = redact_url_credentials(value) if isinstance(value, str) else value
    return out


def redact_mapping(mapping: dict[str, str]) -> dict[str, str]:
    return redact_headers(mapping)


def redact_cookies(cookies: dict[str, str]) -> dict[str, str]:
    return {key: _REDACTED for key in cookies}


def redact_url_credentials(url: str | None) -> str:
    if not isinstance(url, str):
        return "[REDACTED]"
    # Case-insensitive, any scheme, optional scheme. The credential span is
    # anything up to '@' (passwords may contain '/'); over-redaction is
    # preferred over leaking.
    result = re.sub(
        r"([a-zA-Z][a-zA-Z0-9+\-.]*://)([^@\s]+)@",
        r"\1[REDACTED]@", url, flags=re.I,
    )
    if result == url:
        # Scheme-relative (//user:pass@host) or no-scheme (user:pass@host).
        # Only run when the scheme-based pass did nothing — running it
        # unconditionally would strip the scheme from already-redacted URLs.
        # Try "//" FIRST so it is preserved in the output.
        result = re.sub(r"((?://)?)([^@\s]+)@", r"\1[REDACTED]@", result)
    return result
