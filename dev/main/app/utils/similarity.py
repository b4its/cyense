"""Body similarity via difflib (PRD v2.0 §4.1 verification step 1)."""

from __future__ import annotations

from difflib import SequenceMatcher


def similarity(a: str, b: str) -> float:
    """Return ratio in [0, 1]; equal texts -> 1.0."""
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return SequenceMatcher(None, a, b).ratio()
