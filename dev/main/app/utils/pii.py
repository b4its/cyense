"""Cross-account PII detection (PRD v2.0 §4.1 verification step 2)."""

from __future__ import annotations

import re

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
PHONE_RE = re.compile(r"(?<!\w)(?:\+?\d[\d\s().-]{7,}\d)(?!\w)")


def extract_pii(text: str) -> list[str]:
    """Extract emails and phone-number-like tokens from a response body."""
    found: list[str] = []
    for match in EMAIL_RE.finditer(text):
        found.append(match.group(0).lower())
    for match in PHONE_RE.finditer(text):
        token = re.sub(r"\D", "", match.group(0))
        if len(token) >= 8:
            found.append(token)
    return sorted(set(found))


def pii_diff(a: list[str], b: list[str]) -> list[str]:
    """PII present in ``a`` but absent from ``b`` (other user's data)."""
    return sorted(set(a) - set(b))
