"""OSINT Radar pivot engine — typed exploration map + health summary.

Faithful to the analysis' central design observation (§4.1): each catalogue
tool is a typed function ``you_have → you_get``, and an investigation pivots
by handing an identifier you now have to the next tool. This module exposes
two things the UI needs that aren't already derivable from the tool payload:

1. ``ARTEFACT_TYPES`` — for each ``you_get`` artefact label, the identifier
   type(s) it can hand off for the *next* lookup. This powers a user-guided
   Pivot Map (no auto-ranked suggestions, which the analysis flags as
   occasionally illogical — AlgoVPN from a breach email). The human picks the
   hop, so we never generate misleading "next steps".

2. ``build_health(TOOLS)`` — honest verification view: totals + per-category
   counts of Operational / Unverified / Flagged. The analysis stresses that
   showing status (incl. "not verified") rather than hiding it is what makes
   the catalogue trustworthy (§1.1, §4.1).

Everything is pure-Python, deterministic and derived from the merged ``TOOLS``
payload (no DB, no network, no engine change).
"""

from __future__ import annotations

from collections import defaultdict

# A ``you_get`` artefact label can hand off one or more identifier types to the
# NEXT lookup. Labels that are terminal findings (guides, references, breach
# names/dates, dork queries, banners, timestamps, raw documents) intentionally
# map to no identifier so the pivot map ends cleanly instead of inventing hops.
ARTEFACT_TYPES: dict[str, list[str]] = {
    # email-centric
    "emails": ["email", "domain"],
    "accounts": ["email", "username"],
    "deliverability": ["email"],
    "disposable inboxes": ["email"],
    "test identities": ["email"],
    "breaches": ["email", "username", "domain"],
    "credentials": ["email", "username"],
    "pastes": ["username", "email"],
    # domain / archive / web
    "subdomains": ["domain", "ip"],
    "dns records": ["domain", "ip"],
    "whois records": ["domain", "company", "ip"],
    "certificates": ["domain", "ip"],
    "historical pages": ["url", "domain"],
    "snapshots": ["url", "domain"],
    "archives": ["url", "name", "company"],
    "page content": ["url", "domain", "username"],
    "queries": ["url", "domain"],
    "indexed pages": ["url", "domain"],
    "source pages": ["url", "image", "file"],
    # network / threat
    "indicators": ["ip", "domain", "url", "file"],
    "infrastructure": ["ip", "domain", "url"],
    "hosts": ["ip", "domain"],
    "open services": ["ip", "domain"],
    "malware": ["file", "ip", "domain"],
    # crypto
    "transactions": ["wallet"],
    "tokens": ["wallet"],
    "counterparties": ["wallet"],
    # people / social
    "profiles": ["username", "email", "name"],
    "linked identifiers": ["username", "email", "name"],
    "profile URLs": ["url", "username"],
    "mentions": ["username", "domain", "url"],
    "posts": ["username", "url", "email"],
    # geo / transport
    "coordinates": ["location"],
    "map context": ["location", "image"],
    "imagery": ["location", "image"],
    "movement history": ["location", "ip"],
    "routes": ["location", "ip"],
    # records / media
    "public records": ["name", "company", "location"],
    "filings": ["name", "company", "location"],
    "matches": ["image", "url", "file"],
    "metadata": ["image", "file", "url"],
    "onion services": ["url", "domain"],
}

# Per-type canonical labels (mirror PIVOT_TYPES order) so the client can label
# suggested next hops; computed lazily to avoid an import cycle at module top.
TYPE_LABELS: dict[str, str] = {}


def _ensure_labels() -> None:
    if TYPE_LABELS:
        return
    from app.program.osintradar_methodology import PIVOT_TYPES

    TYPE_LABELS.update({p["code"]: p["label"] for p in PIVOT_TYPES})


def artefact_links(artefact: str) -> list[dict[str, str]]:
    """Identifier types an artefact can feed, as ``[{code,label}]``."""
    _ensure_labels()
    return [
        {"code": c, "label": TYPE_LABELS.get(c, c)}
        for c in ARTEFACT_TYPES.get(artefact, [])
    ]


def build_health(ordered_tools: list[dict[str, object]]) -> dict[str, object]:
    """Per-status totals + per-category breakdown from the merged tools."""
    status_totals: dict[str, int] = defaultdict(int)
    by_cat: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for t in ordered_tools:
        s = str(t.get("tool_status") or "Operational")
        status_totals[s] += 1
        by_cat[str(t.get("category") or "")][s] += 1
    return {
        "totals": dict(status_totals),
        "operational": int(status_totals.get("Operational", 0)),
        "unverified": int(status_totals.get("Unverified", 0)),
        "flagged": int(status_totals.get("Flagged", 0)),
        "by_category": {c: dict(v) for c, v in sorted(by_cat.items()) if any(v.values())},
    }


__all__ = [
    "ARTEFACT_TYPES",
    "TYPE_LABELS",
    "artefact_links",
    "build_health",
]
