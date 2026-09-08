"""OSINT Radar (osintradar.com) tool library — full data mirror.

Source: https://osintradar.com/tools — 346 curated OSINT tools, downloaded
and parsed per-tool from their canonical detail pages on 2026-09-08.
OSINT Radar content is MIT-licensed; every record links back to its
``source_page`` on osintradar.com plus the tool's own upstream URL.

Unlike the Kali-style entries, each record preserves the tool's ORIGINAL
operating model — how it actually works in an investigation, not just an
install command:

  * ``how_it_works``     the "Investigator Use" mechanism write-up
  * ``you_have``/``you_get``
                         pivot model from the site's "You have → You get"
                         map: identifier types accepted / produced
  * ``access``/``pricing``/``tool_status``
                         availability badges + operational status as published
  * ``osint_category``   original OSR category label (ids are mapped to the
                         ``osint-*`` categories appended by tools_catalog)

Data lives in ``osintradar_data.json`` (generated from the site — do not
hand-edit). ``osr_index()`` splits the 346 records into additions (tools the
Kali catalog does not have yet) and enrichments (extras merged onto matching
existing entries by upstream URL host or name, instead of duplicating them).
"""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

_DATA_PATH = Path(__file__).resolve().parent / "osintradar_data.json"

# Verification timeline — honest provenance metadata per §1.1/§A1: the vast
# majority of catalogue cards showed "Verified Jul 11, 2026" on the source and
# the rest "Not verified"; the Cyense mirror itself was taken on 2026-09-08
# (module docstring). The mirror is a point-in-time copy: re-sync before
# treating any card as current.
OSR_VERIFICATION: dict[str, str] = {
    "site_verified_at": "2026-07-11",   # majority badge date on osintradar.com
    "not_verified_label": "Not verified",  # how the rest was labelled
    "mirrored_at": "2026-09-08",        # when this dataset was scraped into Cyense
}

# OSINT-Radar categories appended to the catalog taxonomy (original grouping).
OSR_CATEGORIES: list[dict[str, str]] = [
    {"id": "osint-academic", "label": "Academic & Records Research", "emoji": "🎓"},
    {"id": "osint-archive", "label": "Archive & Capture", "emoji": "🗃️"},
    {"id": "osint-breach", "label": "Breach & Leak OSINT", "emoji": "🚨"},
    {"id": "osint-crypto", "label": "Cryptocurrency OSINT", "emoji": "🪙"},
    {"id": "osint-threat", "label": "Cyber Threat OSINT", "emoji": "⚠️"},
    {"id": "osint-darkweb", "label": "Dark Web OSINT", "emoji": "🕳️"},
    {"id": "osint-domain", "label": "Domain OSINT", "emoji": "🌐"},
    {"id": "osint-email", "label": "Email OSINT", "emoji": "✉️"},
    {"id": "osint-geo", "label": "Geolocation OSINT", "emoji": "📍"},
    {"id": "osint-ip", "label": "IP Address OSINT", "emoji": "🧭"},
    {"id": "osint-image", "label": "Image & Video OSINT", "emoji": "🖼️"},
    {"id": "osint-search", "label": "OSINT Search Techniques", "emoji": "🔎"},
    {"id": "osint-people", "label": "People OSINT", "emoji": "🧑"},
    {"id": "osint-privacy", "label": "Privacy & Security OSINT", "emoji": "🔒"},
    {"id": "osint-records", "label": "Public Records OSINT", "emoji": "🗂️"},
    {"id": "osint-social", "label": "Social Media OSINT", "emoji": "💬"},
    {"id": "osint-synthetic", "label": "Synthetic Identity & Test Data", "emoji": "🎲"},
    {"id": "osint-training", "label": "Training & Reference OSINT", "emoji": "📚"},
    {"id": "osint-transport", "label": "Transport & Infrastructure Tracking", "emoji": "🚆"},
    {"id": "osint-username", "label": "Username Analysis", "emoji": "🔤"},
    {"id": "osint-web", "label": "Web & URL OSINT", "emoji": "🔗"},
]

OSR_CATEGORY_IDS = frozenset(c["id"] for c in OSR_CATEGORIES)

# Fields copied verbatim from an OSR record onto a catalog entry.
OSR_EXTRA_FIELDS = (
    "how_it_works", "you_have", "you_get", "access", "pricing",
    "tool_status", "osint_category", "source_page", "slug",
)


def _load() -> list[dict[str, object]]:
    if not _DATA_PATH.is_file():
        return []
    return json.loads(_DATA_PATH.read_text(encoding="utf-8"))


# All 346 parsed records (raw shape, including url_host for matching).
ALL_OSR: list[dict[str, object]] = _load()


def _extra_fields(rec: dict[str, object]) -> dict[str, object]:
    return {k: rec[k] for k in OSR_EXTRA_FIELDS if k in rec}


def _canon(url: str) -> str:
    """Canonical URL key: netloc + path, no scheme/www/trailing-slash/.git.

    Netloc-only matching would collapse every ``github.com/owner/repo`` tool
    onto one entry, so repos are matched on their full path (with moved-repo
    pairs like gitleaks/gitleaks vs zricethezav/gitleaks falling back to the
    catalog-name match).
    """
    try:
        p = urlparse(url)
        host = p.netloc.lower().removeprefix("www.")
        path = p.path.lower().rstrip("/")
    except Exception:
        return ""
    if not host:
        return ""
    if path.endswith(".git"):
        path = path[:-4]
    return f"{host}{path}"


def osr_index(existing: list[dict[str, object]]) -> tuple[dict[str, dict], list[dict]]:
    """Partition OSR records against the current catalog.

    Returns ``(enrichments, additions)``:
      * ``enrichments``: existing tool name (lowercase) → OSR extra fields,
        for records whose upstream URL/name already lives in the catalog.
      * ``additions``: full OSR records (minus internal ``url_host``) for
        tools the catalog does not have yet.
    """
    by_url: dict[str, str] = {}
    by_name: dict[str, str] = {}
    for t in existing:
        name_key = str(t.get("name") or "").lower()
        u = _canon(str(t.get("url") or ""))
        if u:
            by_url.setdefault(u, name_key)
        by_name.setdefault(name_key, name_key)

    enrichments: dict[str, dict] = {}
    additions: list[dict] = []
    claimed: set[str] = set()
    for r in ALL_OSR:
        name_key = str(r.get("name") or "").lower()
        u = _canon(str(r.get("url") or ""))
        target = by_name.get(name_key) or by_url.get(u)
        if target is not None and target not in claimed:
            claimed.add(target)
            enrichments[target] = _extra_fields(r)
        elif target is None:
            additions.append({k: v for k, v in r.items() if k != "url_host"})
    return enrichments, additions


__all__ = [
    "ALL_OSR",
    "OSR_CATEGORIES",
    "OSR_CATEGORY_IDS",
    "OSR_EXTRA_FIELDS",
    "osr_index",
]
