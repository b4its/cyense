"""Pentest Tools catalog — Kali-style tool database for CLI & Website.

Static, deterministic catalog of open-source penetration-testing tools,
grouped by the same categories used by the Kali Tools / Pentest-Tools
references. Each tool carries: name, url, description, category, platforms
(OS badge keys), and optional tags.

The tool data comes from three sources, merged at import time:

  * ``pentest_tools.md`` — the full Kali-style Pentest Tools reference
    (every ``* [name](url) - description`` row, with ``![](svg/*.svg)``
    platform badges mapped to stable keys).
  * ``_OSINT_TOOLS`` — the awesome-osint additions (DataSploit, Depix,
    Skiptracer, wayparam, ...) that are not part of the Kali-style list.
  * ``osintradar_tools`` — a full mirror of the OSINT Radar tool library
    (osintradar.com, 346 curated OSINT tools with their original
    how-it-works mechanism + pivot model). Records that match a tool
    already in the catalog enrich it in place; the rest are appended
    under the ``osint-*`` categories from the site's own taxonomy.

This module powers:
  * the CLI ``cyense tools`` command (browse / search the catalog),
  * the Website ``/ui/#/tools`` page (browse + search API).

Data is pure-Python (no external DB) so both clients can render it without
network calls or a runtime dependency.
"""

from __future__ import annotations

import re
from pathlib import Path

# ruff: noqa: E501 — descriptions are lifted verbatim from the source list;
# wrapping them adds no value.

# Platform badge keys that viewers may use to render OS icons. Values are the
# lowercase short name (`windows`, `linux`, `mac`, `chrome`, `docker`,
# `cross` for everything).
_ALL_PLATFORMS = ("windows", "linux", "mac", "chrome", "docker", "cross")

# Short and long descriptions of each platform (used by tooltips/legends).
PLATFORM_LABELS: dict[str, str] = {
    "windows": "Windows",
    "linux": "Linux",
    "mac": "macOS",
    "chrome": "Chrome (browser extension)",
    "docker": "Docker",
    "cross": "Cross-platform",
}

# Map the markdown platform badges (svg filename) to stable platform keys.
_SVG_TO_PLATFORM: dict[str, str] = {
    "windows": "windows",
    "linux": "linux",
    "mac": "mac",
    "macos": "mac",
    "chrome": "chrome",
    "docker": "docker",
    "win": "windows",
}

_MD_PATH = Path(__file__).resolve().parent / "pentest_tools.md"


# ---------------------------------------------------------------------------
# Section → category mapping (markdown heading text → category id).
# Both `###` (top-level section) and `####` (subsection) headings are mapped;
# subsections give the most specific assignment.
# ---------------------------------------------------------------------------

_SECTION_CATEGORY: dict[str, str] = {
    # Information Gathering
    "Information Gathering": "recon",
    "Domain Name": "recon",
    "Subdomain": "recon",
    "Google Hacking": "recon",
    "Github": "recon",
    "GitHub": "recon",
    "SVN": "recon",
    "Port Scan": "recon",
    "OSINT": "osint",
    # Phishing / Social Engineering
    "Phishing": "social-engineering",
    "Social Engineering Tools": "social-engineering",
    # Vulnerability Analysis
    "Vulnerability Analysis": "vuln-scan",
    "Fuzzing": "vuln-scan",
    "Vulnerability Scanner": "vuln-scan",
    "Docker Scanners": "vuln-scan",
    # Web Applications
    "Web Applications": "webapp-cms",
    "CMS & Framwork Identification": "webapp-cms",
    "CMS & Framework Identification": "webapp-cms",
    "Web Applications Proxies": "webapp-proxy",
    "web browser extension": "webapp-browser",
    "Web Crawlers & Directory Brute Force": "webapp-crawler",
    # Database Assessment
    "Database Assessment": "database",
    # Password Attacks
    "Password Attacks": "password",
    "Wordlists": "password",
    # Wireless Attacks
    "Wireless Attacks": "wireless",
    "Wireless Tools": "wireless",
    # Reverse Engineering
    "Reverse Engineering": "reverse-engineering",
    # Exploitation Tools
    "Exploitation Tools": "exploit-framework",
    "Vulnerability Search": "exploit-search",
    "Cross-site Scripting(XSS)": "xss",
    "Sql Injection": "sqli",
    "Command Injection": "command-injection",
    "File Include": "file-include",
    "File Upload vulnerability": "file-include",
    "XML External Entity Attack(XXE)": "xxe",
    "Cross-site request forgery (CSRF)": "csrf",
    "Deserialization exploit framework": "exploit-framework",
    "Exploit Framework": "exploit-framework",
    "Machine Learning": "exploit-framework",
    "Automate": "exploit-framework",
    # Sniffing & Spoofing
    "Sniffing & Spoofing": "sniffing",
    # Maintaining Access
    "Maintaining Access": "shell",
    "Shell": "shell",
    "Listener": "shell",
    "Web Shell": "webshell",
    "Privilege Escalation Auxiliary": "privesc",
    "C2": "c2",
    "Bypass AV": "bypass-av",
    # Golang Sec Tools
    "Golang Sec Tools": "recon",
    "Golang Sec": "recon",
    # Reporting & Collaboration
    "Reporting & Collaboration": "reporting",
    "Audit Tools": "code-audit",
    # Code Audit
    "Code Audit": "code-audit",
    # Intranet penetration
    "Intranet penetration": "tunnel",
    "Service Detection": "recon",
    "Port Forwarding & Proxies": "tunnel",
    # DevSecOps
    "DevSecOps": "devsecops",
    # RootKit
    "RootKit": "rootkit",
    # Pentesting Distribution
    "Pentesting Distribution": "distribution",
    # Cyber Range
    "Cyber Range": "cyber-range",
    "Vulnerability application": "cyber-range",
    "Simulation Range": "cyber-range",
    "Honeyhots": "cyber-range",
    "Honeypots": "cyber-range",
    "CTF challenges": "cyber-range",
    # Collections / excellent projects
    "Excellent project": "collections",
    "Excellent projects": "collections",
}

# Rows under these sections are NOT tools (headers / notes alone).
_SKIP_SECTION_NAMES = {"Free VPS for Open Source"}


# ---------------------------------------------------------------------------
# Markdown parser
# ---------------------------------------------------------------------------

_ITEM_RE = re.compile(r"^\*\s+\[([^\]]+)\]\((https?://[^)\s]+)\)\s*-?\s*(.*)$")
_ITEM_URL_ONLY_RE = re.compile(r"^\*\s+\[([^\]]+)\]\((https?://[^)\s]+)\)\s*$")
_BADGE_RE = re.compile(r"!\[[^\]]*\]\(([^)]*)\)")
_LOCK_RE = re.compile(r":lock:")


def _platforms_from_line(line: str) -> tuple[list[str], str]:
    """Extract platform keys from ``![](svg/X.svg)`` badges; return cleaned line."""
    platforms: list[str] = []
    for m in _BADGE_RE.finditer(line):
        path = m.group(1).lower()
        for key, value in _SVG_TO_PLATFORM.items():
            if key in path:
                platforms.append(value)
                break
    cleaned = _BADGE_RE.sub("", line)
    cleaned = _LOCK_RE.sub("", cleaned).strip()
    return platforms, cleaned


def _parse_pentest_markdown() -> list[dict[str, object]]:
    """Parse pentest_tools.md into tool records (name/url/desc/category/platforms).

    Heading rules (the file uses a clean ``###``/``####`` structure):
      * ``### <Section>``   → a top-level section.
      * ``#### <Sub>``      → a subsection that refines the current section.
    A row belongs to the most specific category available: the ``####``
    heading wins when it maps to a category, otherwise the ``###`` section.
    """
    try:
        text = _MD_PATH.read_text(encoding="utf-8")
    except OSError:
        return []

    tools: list[dict[str, object]] = []
    section_cat: str | None = None   # category from the current `###` heading
    sub_cat: str | None = None       # category from the current `####` heading

    for raw in text.splitlines():
        line = raw.strip()

        # -- headings -------------------------------------------------------
        if line.startswith("### "):
            heading = line[4:].strip()
            if heading in _SKIP_SECTION_NAMES:
                section_cat = None
                sub_cat = None
                continue
            section_cat = _SECTION_CATEGORY.get(heading, "recon")
            sub_cat = None
            continue
        if line.startswith("#### "):
            heading = line[5:].strip()
            # A subsection only refines the current section; unknown
            # subsections keep the parent's category.
            sub_cat = _SECTION_CATEGORY.get(heading)
            continue

        # -- tool rows ------------------------------------------------------
        if not line.startswith("* "):
            continue
        # Only top-level bullets (no leading indentation) are tool rows.
        if raw.startswith("  ") or raw.startswith("\t"):
            continue

        m = _ITEM_RE.match(line)
        if not m:
            m = _ITEM_URL_ONLY_RE.match(line)
        if not m:
            continue

        name, url = m.group(1).strip(), m.group(2).strip()
        desc = (m.group(3) if m.lastindex and m.lastindex >= 3 else "").strip()
        platforms, desc = _platforms_from_line(desc)

        # A trailing "-" separator leaves an empty description on URL-only rows.
        desc = desc.lstrip("-").strip()
        if not platforms:
            platforms = ["cross"] if name not in ("whois",) else ["windows"]

        category = sub_cat or section_cat or "recon"
        tools.append({
            "name": name,
            "url": url,
            "description": desc,
            "category": category,
            "platforms": platforms,
            "tags": [],
        })
    return tools


# ---------------------------------------------------------------------------
# Curated OSINT additions (awesome-osint list — not part of the Kali-style md)
# ---------------------------------------------------------------------------

_OSINT_TOOLS: list[dict[str, object]] = [
    {
        "name": "DataSploit",
        "url": "https://github.com/DataSploit/datasploit",
        "description": (
            "OSINT visualizer utilizing Shodan, Censys, Clearbit, EmailHunter, "
            "FullContact, and ZoomEye behind the scenes."
        ),
        "category": "osint",
        "platforms": ("cross",),
        "tags": ("shodan", "censys", "clearbit", "email", "zoomeye"),
    },
    {
        "name": "Depix",
        "url": "https://github.com/spipm/Depix",
        "description": (
            "Tool for recovering passwords from pixelized screenshots "
            "(by de-pixelating text)."
        ),
        "category": "osint",
        "platforms": ("linux",),
        "tags": ("password", "screenshot", "de-pixelating"),
    },
    {
        "name": "GyoiThon",
        "url": "https://github.com/gyoisamurai/GyoiThon",
        "description": "Intelligence Gathering tool using Machine Learning.",
        "category": "recon",
        "platforms": ("linux",),
        "tags": ("machine-learning", "intelligence", "gathering"),
    },
    {
        "name": "Intrigue",
        "url": "http://intrigue.io/",
        "description": (
            "Automated OSINT & Attack Surface discovery framework with "
            "powerful API, UI and CLI."
        ),
        "category": "osint",
        "platforms": ("cross",),
        "tags": ("attack-surface", "framework", "api"),
    },
    {
        "name": "Maltego",
        "url": "https://www.maltego.com/",
        "description": "Proprietary software for open sources intelligence and forensics.",
        "category": "osint",
        "platforms": ("windows", "linux", "mac"),
        "tags": ("forensics", "graph", "intelligence"),
    },
    {
        "name": "PacketTotal",
        "url": "https://www.packettotal.com/",
        "description": (
            "Simple, free, high-quality packet capture file analysis facilitating "
            "the quick detection of network-borne malware (using Zeek and Suricata "
            "IDS signatures under the hood)."
        ),
        "category": "osint",
        "platforms": ("chrome",),
        "tags": ("pcap", "malware", "zeek", "suricata"),
    },
    {
        "name": "Skiptracer",
        "url": "https://github.com/xillwillx/skiptracer",
        "description": (
            "OSINT scraping framework that utilizes basic Python webscraping "
            "(BeautifulSoup) of PII paywall sites to compile passive information "
            "on a target on a ramen noodle budget."
        ),
        "category": "osint",
        "platforms": ("cross",),
        "tags": ("python", "beautifulsoup", "pii", "scraping"),
    },
    {
        "name": "Sn1per",
        "url": "https://github.com/1N3/Sn1per",
        "description": "Automated Pentest Recon Scanner.",
        "category": "recon",
        "platforms": ("linux",),
        "tags": ("recon", "automation", "scanner", "reconnaissance"),
    },
    {
        "name": "Spiderfoot",
        "url": "https://github.com/smicallef/spiderfoot",
        "description": (
            "Multi-source OSINT automation tool with a Web UI and report visualizations."
        ),
        "category": "osint",
        "platforms": ("cross",),
        "tags": ("automation", "web-ui", "visualization"),
    },
    {
        "name": "creepy",
        "url": "https://github.com/jkakavas/creepy",
        "description": "Geolocation OSINT tool.",
        "category": "osint",
        "platforms": ("cross",),
        "tags": ("geolocation", "geo", "metadata"),
    },
    {
        "name": "gOSINT",
        "url": "https://github.com/Nhoya/gOSINT",
        "description": "OSINT tool with multiple modules and a telegram scraper.",
        "category": "osint",
        "platforms": ("cross",),
        "tags": ("telegram", "scraper", "modules"),
    },
    {
        "name": "image-match",
        "url": "https://github.com/ascribe/image-match",
        "description": "Quickly search over billions of images.",
        "category": "osint",
        "platforms": ("cross",),
        "tags": ("image", "search", "reverse-image"),
    },
    {
        "name": "recon-ng",
        "url": "https://github.com/lanmaster53/recon-ng",
        "description": (
            "Full-featured Web Reconnaissance framework written in Python."
        ),
        "category": "osint",
        "platforms": ("linux",),
        "tags": ("reconnaissance", "framework", "python"),
    },
    {
        "name": "sn0int",
        "url": "https://github.com/kpcyrd/sn0int",
        "description": "Semi-automatic OSINT framework and package manager.",
        "category": "osint",
        "platforms": ("linux",),
        "tags": ("automation", "package-manager", "recon"),
    },
    {
        "name": "Keyscope",
        "url": "https://github.com/SpectralOps/keyscope",
        "description": (
            "An extensible key and secret validation for auditing active secrets "
            "against multiple SaaS vendors."
        ),
        "category": "secret",
        "platforms": ("cross",),
        "tags": ("secrets", "validation", "saas", "audit"),
    },
    {
        "name": "Facebook Friend List Scraper",
        "url": "https://github.com/narkopolo/facebook-friend-list-scraper",
        "description": (
            "Tool to scrape names and usernames from large friend lists on "
            "Facebook, without being rate limited."
        ),
        "category": "osint",
        "platforms": ("cross",),
        "tags": ("facebook", "scraper", "social-media"),
    },
    {
        "name": "wayparam",
        "url": "https://github.com/env0/wayparam",
        "description": (
            "Tools designed to discover hidden or undocumented parameters and "
            "endpoints by generating or normalizing request inputs, often used "
            "to identify input handling issues and unexpected application behavior."
        ),
        "category": "recon",
        "platforms": ("cross",),
        "tags": ("hidden", "parameters", "endpoints", "passive"),
    },
]


# ---------------------------------------------------------------------------
# Categories with stable ids + display labels, in a sensible display order.
# ---------------------------------------------------------------------------

CATEGORIES: list[dict[str, object]] = [
    {"id": "recon", "label": "Information Gathering & Recon", "emoji": "🎯"},
    {"id": "osint", "label": "OSINT", "emoji": "🕵️"},
    {"id": "social-engineering", "label": "Phishing & Social Engineering", "emoji": "🎣"},
    {"id": "vuln-scan", "label": "Vulnerability Analysis", "emoji": "🛡️"},
    {"id": "webapp-cms", "label": "CMS & Framework Identification", "emoji": "🔍"},
    {"id": "webapp-proxy", "label": "Web Application Proxies", "emoji": "🔌"},
    {"id": "webapp-browser", "label": "Web Browser Extensions", "emoji": "🌐"},
    {"id": "webapp-crawler", "label": "Web Crawlers & Directory Brute Force", "emoji": "🕷️"},
    {"id": "database", "label": "Database Assessment", "emoji": "🗄️"},
    {"id": "password", "label": "Password Attacks", "emoji": "🔑"},
    {"id": "wireless", "label": "Wireless Attacks", "emoji": "📡"},
    {"id": "exploit-search", "label": "Exploitation / Vulnerability Search", "emoji": "💥"},
    {"id": "xss", "label": "Cross-site Scripting (XSS)", "emoji": "📝"},
    {"id": "sqli", "label": "SQL Injection", "emoji": "💉"},
    {"id": "command-injection", "label": "Command Injection", "emoji": "⌨️"},
    {"id": "file-include", "label": "File Include", "emoji": "📂"},
    {"id": "xxe", "label": "XML External Entity (XXE)", "emoji": "🧾"},
    {"id": "csrf", "label": "Cross-Site Request Forgery (CSRF)", "emoji": "🎭"},
    {"id": "exploit-framework", "label": "Exploit Frameworks", "emoji": "⚡"},
    {"id": "sniffing", "label": "Sniffing & Spoofing", "emoji": "📡"},
    {"id": "shell", "label": "Maintaining Access / Shells", "emoji": "🐚"},
    {"id": "webshell", "label": "Web Shells", "emoji": "🕸️"},
    {"id": "privesc", "label": "Privilege Escalation", "emoji": "⬆️"},
    {"id": "c2", "label": "Command & Control (C2)", "emoji": "🕹️"},
    {"id": "bypass-av", "label": "Bypass AV / Evasion", "emoji": "🛸"},
    {"id": "tunnel", "label": "Port Forwarding & Proxies", "emoji": "🚇"},
    {"id": "reporting", "label": "Reporting & Collaboration", "emoji": "📊"},
    {"id": "secret", "label": "Secret Detection", "emoji": "🤫"},
    {"id": "code-audit", "label": "Code Audit", "emoji": "🔎"},
    {"id": "devsecops", "label": "DevSecOps", "emoji": "⚙️"},
    {"id": "reverse-engineering", "label": "Reverse Engineering", "emoji": "🧬"},
    {"id": "rootkit", "label": "RootKit", "emoji": "🫥"},
    {"id": "distribution", "label": "Pentesting Distributions", "emoji": "🧰"},
    {"id": "cyber-range", "label": "Cyber Range & CTF", "emoji": "🏴‍☠️"},
    {"id": "collections", "label": "Collections & Resources", "emoji": "📦"},
]

# OSINT Radar taxonomy (osintradar.com): each site category becomes its own
# catalog category so the 346 mirrored tools keep their original grouping.
from app.program.osintradar_tools import OSR_CATEGORIES as _OSR_CATEGORIES  # noqa: E402

CATEGORIES += _OSR_CATEGORIES

_CATEGORY_IDS = {c["id"] for c in CATEGORIES}


def _all_tools() -> list[dict[str, object]]:
    """Merge markdown tools + curated OSINT + OSINT Radar mirror; validate + dedupe."""
    from app.program.osintradar_tools import osr_index
    from app.program.tool_features import TOOL_FEATURES
    from app.program.tool_usage import (
        curated_bookmarks,
        curated_related,
        curated_usage,
        default_usage,
    )

    merged: list[dict[str, object]] = []
    seen: set[str] = set()

    base_tools = _parse_pentest_markdown() + _OSINT_TOOLS  # type: ignore[operator]
    # OSR records that match a base tool (by upstream host or name) enrich it
    # in place; the remainder are appended as catalog additions.
    osr_enrichments, osr_additions = osr_index(base_tools)

    for t in base_tools + osr_additions:
        cat = t.get("category")
        if cat not in _CATEGORY_IDS:
            raise ValueError(f"tools_catalog: unknown category {cat!r} for {t.get('name')!r}")
        name = str(t["name"])
        if not name or name.lower() in seen:
            continue
        seen.add(name.lower())

        platforms = tuple(t.get("platforms") or ("cross",))
        platforms = list(dict.fromkeys(p for p in platforms if p in _ALL_PLATFORMS)) or ["cross"]
        rec = dict(t)
        rec["platforms"] = platforms
        rec["tags"] = list(dict.fromkeys(str(x) for x in (t.get("tags") or [])))
        # OSR additions ship curated features/usage inline; Kali rows fall back
        # to the curated maps, then the per-category defaults.
        rec["features"] = list(dict.fromkeys(t.get("features") or TOOL_FEATURES.get(name, [])))
        # Enrich with usage examples (curated → record's own → category fallback)
        # + bookmarks
        usage = curated_usage(name) or list(t.get("usage") or []) or default_usage(str(cat))
        bookmarks = curated_bookmarks(name) or list(t.get("bookmarks") or []) or [str(t.get("url") or "")]
        rec["usage"] = usage
        rec["bookmarks"] = bookmarks
        rec.update(osr_enrichments.get(name.lower()) or {})
        merged.append(rec)

    # Second pass: related tools = curated cross-family relations (or the
    # OSR record's own related list) filtered to existing names + same-category
    # siblings for a useful "similar tools" list.
    names_lower = {str(t["name"]).lower() for t in merged}
    for rec in merged:
        name = str(rec["name"])
        source = curated_related(name) or [str(r) for r in (rec.get("related") or [])]
        related: list[str] = [
            r for r in source
            if r.lower() in names_lower and r.lower() != name.lower()
        ]
        related_lower = {r.lower() for r in related}
        for sibling in merged:
            if sibling is rec or sibling.get("category") != rec.get("category"):
                continue
            sname = str(sibling["name"])
            if sname.lower() == name.lower() or sname.lower() in related_lower:
                continue
            if len(related) >= 4:
                break
            related.append(sname)
            related_lower.add(sname.lower())
        rec["related"] = related
    return merged


# Public, ordered catalog. One object, reused across requests — callers must
# not mutate it.
TOOLS: list[dict[str, object]] = _all_tools()

# Convenience index: category id → list of tools (same order as TOOLS).
TOOLS_BY_CATEGORY: dict[str, list[dict[str, object]]] = {}
for _t in TOOLS:
    TOOLS_BY_CATEGORY.setdefault(str(_t["category"]), []).append(_t)


def tools_catalog() -> dict[str, object]:
    """Return the full catalog payload (categories + tools) for API / CLI.

    Shape:
      {
        "categories": [{"id", "label", "emoji", "count", "note?", "risk?"}...],
        "tools":      [{name, url, description, category, platforms, tags}...],
        "total":      int,
        "platforms":  {"windows": "Windows", ...},
        "pivot_types" / "workflows" / "reporting_checkpoints" /
        "confidence_scale":  OSINT Radar methodology layer (Lapis A)
      }
    """
    from app.program.osintradar_methodology import (
        CATEGORY_NOTES,
        CONFIDENCE_SCALE,
        PIVOT_TYPES,
        REPORTING_CHECKPOINTS,
        WORKFLOWS,
    )

    return {
        "categories": [
            {
                "id": c["id"],
                "label": c["label"],
                "emoji": c["emoji"],
                "count": len(TOOLS_BY_CATEGORY.get(str(c["id"]), [])),
                **(CATEGORY_NOTES.get(str(c["id"])) or {}),
            }
            for c in CATEGORIES
        ],
        "tools": TOOLS,
        "total": len(TOOLS),
        "platforms": PLATFORM_LABELS,
        "pivot_types": PIVOT_TYPES,
        "workflows": WORKFLOWS,
        "reporting_checkpoints": REPORTING_CHECKPOINTS,
        "confidence_scale": CONFIDENCE_SCALE,
    }


__all__ = [
    "CATEGORIES",
    "TOOLS",
    "TOOLS_BY_CATEGORY",
    "PLATFORM_LABELS",
    "tools_catalog",
]
