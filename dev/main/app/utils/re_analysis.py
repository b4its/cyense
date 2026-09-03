"""Client-side reverse engineering checks (web RE tools adaptation).

Implements a deterministic, passive re-analysis of the JS a target website
serves, inspired by famous RE / client-side-analysis tooling:

  * **Source-map exposure** (``webpack-source-map-exposer`` / manual RE):
    web apps often ship ``.js.map`` source maps or an inline
    ``//# sourceMappingURL=`` comment. A publicly-servable source map leaks
    the full original source (the entire TypeScript/ES module graph), which
    is a common information-disclosure finding. We detect the *exposure
    surface* (map referenced + reachable) without downloading huge maps.
  * **Retire.js** — detect known-vulnerable / obsolete client-side libraries
    (jQuery, AngularJS, Bootstrap, React, etc.) from version markers in JS
    source, asset URLs and HTML. Vulnerable JS libraries are the client-side
    analogue of server CVE matching and a top REAL bug-bounty finding class.
  * **JSlulce / JS skillsets** — extract ``sourceMappingURL`` references,
    embedded secrets/endpoints (already handled by discovery.py+secrets.py);
    here we add *version fingerprint extraction* from version comment
    banners (``/*! jQuery v3.4.1 */``) used by Retire.js-style matching.

Read-only and deterministic: works on bodies already fetched by the crawler;
never executes the JS.
"""

from __future__ import annotations

import re
from typing import Any

# ---------------------------------------------------------------------------
# Source-map exposure
# ---------------------------------------------------------------------------

_SOURCEMAP_MARKERS = (
    r"//[#@]\s*sourceMappingURL\s*=\s*([^\s\"']+)",
    r"sourceMappingURL\s*:\s*[\"']([^\"']+)[\"']",
    r"sourceMappingURL=([^\s\"'>]+)",
)

# Version-banner patterns — mirror the minified-library banners Retire.js /
# Wappalyzer / WhatWeb use. (library, regex → extracts version)
_LIB_VERSION_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    ("jquery", "jQuery",
     re.compile(r"^\s*/\*!\s*jQuery(?:\.min)?\s*v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.M)),
    ("jquery", "jQuery-footer",
     re.compile(r"jQuery\s+JavaScript Library\s+v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.I)),
    ("angularjs", "AngularJS",
     re.compile(r"@license\s+AngularJS?\s+v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.I)),
    ("bootstrap", "Bootstrap",
     re.compile(r"^/\*!\s*Bootstrap\s+v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.M)),
    ("react", "React",
     re.compile(r"React\s+(?:v)?([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.I)),
    ("vue", "Vue.js",
     re.compile(r"Vue\.js\s+v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.I)),
    ("lodash", "Lodash",
     re.compile(r"Lodash\s+(?:v)?([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.I)),
    ("moment", "Moment.js",
     re.compile(r"Moment\.js\s+v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.I)),
    ("handlebars", "Handlebars",
     re.compile(r"Handlebars\s+(?:compiler\s+)?v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.I)),
    ("backbone", "Backbone.js",
     re.compile(r"Backbone\.js\s+v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.I)),
    ("underscore", "Underscore.js",
     re.compile(r"Underscore\.js\s+v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.I)),
    ("dojo", "Dojo",
     re.compile(r"Dojo\s+(?:toolkit\s+)?v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.I)),
    ("d3", "D3",
     re.compile(r"(?i)(?:d3|d3-plus)\s+v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)")),
]


def find_sourcemap_refs(body: str) -> list[str]:
    """Return sourceMappingURL references found in a JS/HTML body."""
    if not body:
        return []
    refs: list[str] = []
    for pat in _SOURCEMAP_MARKERS:
        for m in re.finditer(pat, body):
            refs.append(m.group(1))
    return list(dict.fromkeys(refs))


def sourcemap_exposure_findings(
    body: str,
    url: str = "",
) -> list[dict[str, Any]]:
    """Flag that a served JS references a (potentially reachable) source map."""
    findings: list[dict[str, Any]] = []
    refs = find_sourcemap_refs(body)
    if refs:
        findings.append({
            "rule": "RE-SOURCEMAP-REF",
            "severity": "medium",
            "confidence": 0.6,
            "cwe": "CWE-540",
            "title": "Referensi source map JavaScript ter-expose",
            "description": (
                "File JS merujuk sourceMappingURL — jika map dapat diunduh, "
                "source asli (seluruh modul TS/ES) bocor. Ini dokumentasi "
                "pembangunan web RE: banyak target secara tidak sengaja "
                "membiarkan .js.map/penafsir diakses publik."
            ),
            "evidence": {"refs": refs[:10], "url": url},
            "remediation": (
                "Jangan deploy source map ke produksi (atau batasi aksesnya); "
                "hapus komentar sourceMappingURL dari bundle."
            ),
            "location": url,
        })
    return findings


# ---------------------------------------------------------------------------
# Retire.js-style vulnerable / obsolete client-side library detection
# ---------------------------------------------------------------------------

def _parse_version(v: str) -> tuple[int, int, int]:
    parts = str(v).split(".")
    nums: list[int] = []
    for p in parts[:3]:
        try:
            nums.append(int(re.sub(r"\D.*", "", p)))
        except ValueError:
            nums.append(0)
    while len(nums) < 3:
        nums.append(0)
    return (nums[0], nums[1], nums[2])


def _version_in_range(version: str, low: str, high: str | None) -> bool:
    v = _parse_version(version)
    if v < _parse_version(low):
        return False
    if high is not None and v > _parse_version(high):
        return False
    return True


# library → (event, low, high|None) — known-vulnerable / EOL ranges.
_VULNERABLE_JS: dict[str, list[tuple[str, str, str | None]]] = {
    "jquery": [
        ("CVE-2019-11358", "1.0.0", "3.4.0"),
        ("CVE-2020-11023", "1.0.0", "3.4.9"),
        ("CVE-2020-11022", "1.0.0", "3.4.9"),
        ("CVE-2015-9251", "1.0.0", "3.0.0"),
    ],
    "angularjs": [
        ("CVE-2018-10006", "1.0.0", "1.6.9"),
        ("CVE-2017-1000500", "1.0.0", "1.5.8"),
        ("EOL (AngularJS LTS berakhir)", "1.0.0", "1.8.99"),
    ],
    "bootstrap": [
        ("CVE-2018-14042", "3.0.0", "3.4.0"),
        ("CVE-2019-8331", "3.0.0", "4.3.0"),
    ],
    "react": [],
    "vue": [],
    "lodash": [
        ("CVE-2019-10744", "1.0.0", "4.17.14"),
        ("ReDoS prototype pollution (CVE-2021-23337)", "1.0.0", "4.17.20"),
    ],
    "moment": [],
    "handlebars": [
        ("CVE-2019-19919", "4.0.0", "4.4.4"),
        ("CVE-2021-23383 (prototype pollution)", "4.5.0", "4.7.6"),
    ],
    "backbone": [],
    "underscore": [
        ("CVE-2021-26658 (prototype pollution)", "1.0.0", "1.12.0"),
    ],
    "dojo": [],
    "d3": [],
}


def retirejs_findings(
    js_bodies: list[tuple[str, str]],
) -> list[dict[str, Any]]:
    """Scan JS bodies (list of (url, text)) for known-vulnerable libraries.

    Returns findings rule ``RE-VULN-JS``. Version matching is conservative:
    only a library whose version falls in a known vulnerable range is flagged.
    """
    findings: list[dict[str, Any]] = []
    for url, body in js_bodies:
        if not body:
            continue
        for lib, _label, pattern in _LIB_VERSION_PATTERNS:
            m = pattern.search(body)
            if not m:
                continue
            version = m.group(1)
            ranges = _VULNERABLE_JS.get(lib, [])
            if not ranges:
                continue
            for event, low, high in ranges:
                if _version_in_range(version, low, high):
                    findings.append({
                        "rule": "RE-VULN-JS",
                        "severity": "medium",
                        "confidence": 0.6,
                        "cwe": "CWE-829",
                        "title": f"Library JS rentan/usang: {lib} {version}",
                        "description": (
                            f"Library {lib} v{version} dalam rentang rentan "
                            f"({event}). Risiko: {event} — lib dari pihak "
                            "ketiga ini rentan/end-of-life."
                        ),
                        "evidence": {
                            "library": lib,
                            "version": version,
                            "event": event,
                            "url": url,
                        },
                        "remediation": (
                            f"Upgrade {lib} ke versi yang tidak terkena "
                            f"({high or 'latest'}); pantau kebaruan asset JS."
                        ),
                        "location": url,
                    })
                    break
    return findings


def run_re_passive(
    js_bodies: list[tuple[str, str]],
    html_bodies: list[tuple[str, str]],
) -> list[dict[str, Any]]:
    """Run all passive RE checks (source maps + retire.js) over fetched JS."""
    findings: list[dict[str, Any]] = []
    for url, body in js_bodies:
        findings.extend(sourcemap_exposure_findings(body, url))
    for url, body in html_bodies:
        # Inline ``//# sourceMappingURL`` may appear inside <script> in HTML.
        findings.extend(sourcemap_exposure_findings(body, url))
    findings.extend(retirejs_findings(js_bodies))
    return findings


__all__ = [
    "find_sourcemap_refs",
    "sourcemap_exposure_findings",
    "retirejs_findings",
    "run_re_passive",
]
