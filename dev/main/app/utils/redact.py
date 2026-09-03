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
    # Redact userinfo in a URL authority — `scheme://user:pass@host`, or
    # scheme-relative `//user:pass@host`. Credentials can contain '/', so the
    # userinfo span is everything up to the LAST '@' before the host/path.
    # ONLY the authority `userinfo@` is redacted: an `@` inside the query
    # string (e.g. `?email=a@b.c`) or path is data, not credentials, and
    # must be left intact (previously the no-scheme fallback matched ANY
    # `[^@\s]+@`, mangling every such URL to `[REDACTED]@b.c` — breaking
    # finding evidence/locations).
    scheme_re = re.compile(r"([a-zA-Z][a-zA-Z0-9+\-.]*://)[^/\s?#]*@", re.I)
    result = scheme_re.sub(r"\1[REDACTED]@", url)
    # Scheme-relative userinfo: authority starting with `//` and containing
    # a `@` before the first `/` (host boundary).
    if result.startswith("//"):
        m = re.match(r"(//[^/\s?#]*@)", result)
        if m:
            result = result[: m.start()] + "//[REDACTED]@" + result[m.end():]
    else:
        # Bare `user:pass@host` (no scheme) — only at the very start of the
        # string, before the first `/`.
        m = re.match(r"([^/\s?#]+@)", result)
        if m and "/" not in m.group(1).split("@", 1)[0] and "://" not in result[: m.start()]:
            result = result[: m.start()] + "[REDACTED]@" + result[m.end():]
    return result
