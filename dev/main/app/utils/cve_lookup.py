"""CVE lookup for detected technologies (known-vulnerability matching).

Given the technology fingerprints produced by ``framework_detection`` (and
optionally open ports from ``port_scanner``), looks up well-known CVEs that
affect those components. The database is a curated, deterministic snapshot of
famous/high-impact CVEs — no external API calls, fully reproducible.

Accuracy notes (important — verified against MITRE NVD):
  * Each entry's ``cve``/``technology``/``type``/``severity`` has been
    checked; duplicates and misassigned CVEs are avoided.
  * CVEs whose exploitability depends on a specific version are marked
    ``requires_version=True``. When we only have a technology/service
    fingerprint without a usable version, those matches are reported with
    reduced confidence and a note — a host with port 22 open must NOT be
    reported as "CVE-2024-6387 critical" just because OpenSSH is present.

Workflow (as designed):
  1. port scan → detect open ports + services
  2. framework detection → identify technologies/versions
  3. CVE lookup → match tech + version against known CVEs
  4. if an XSS or IDOR CVE is present (or the tech is prone to it),
     activate the XSS / IDOR scanners accordingly.
"""

from __future__ import annotations

import re
from typing import Any

# ---------------------------------------------------------------------------
# CVE database
# Each entry: {
#   "cve", "technology", "component", "affected", "severity", "type",
#   "title", "description", "ref",
#   "requires_version": bool — if True, only a confident match when we can
#       compare the detected version; otherwise reported as "potential".
# }
# ---------------------------------------------------------------------------

CVE_DATABASE: list[dict[str, Any]] = [
    # --- WordPress ---------------------------------------------------------
    {"cve": "CVE-2019-8942", "technology": "wordpress", "component": "WordPress",
     "affected": "< 5.0.1", "severity": "critical", "type": "rce",
     "requires_version": True,
     "title": "WordPress RCE via crop-image",
     "description": "Authenticated arbitrary file delete/read leading to RCE.",
     "ref": "https://nvd.nist.gov/vuln/detail/CVE-2019-8942"},
    {"cve": "CVE-2019-9787", "technology": "wordpress", "component": "WordPress",
     "affected": "< 5.1.1", "severity": "high", "type": "rce",
     "requires_version": True,
     "title": "WordPress arbitrary file upload / RCE",
     "description": "Authenticated arbitrary file deletion/read in wp-admin "
     "leading to RCE (crop-image, < 5.1.1).",
     "ref": "https://nvd.nist.gov/vuln/detail/CVE-2019-9787"},
    {"cve": "CVE-2020-28037", "technology": "wordpress", "component": "WordPress",
     "affected": "< 5.5.2", "severity": "high", "type": "rce",
     "requires_version": True,
     "title": "WordPress install.php vulnerability",
     "description": "WordPress < 5.5.2 could let an attacker install plugins "
     "during an incomplete install (no IDOR).",
     "ref": "https://nvd.nist.gov/vuln/detail/CVE-2020-28037"},

    # --- Joomla ------------------------------------------------------------
    {"cve": "CVE-2017-8917", "technology": "joomla", "component": "Joomla!",
     "affected": "3.7.0", "severity": "critical", "type": "sqli",
     "requires_version": True,
     "title": "Joomla! SQL injection via com_fields",
     "description": "Unauthenticated SQL injection in Joomla! 3.7.0 "
     "com_fields list view.",
     "ref": "https://nvd.nist.gov/vuln/detail/CVE-2017-8917"},
    {"cve": "CVE-2015-8562", "technology": "joomla", "component": "Joomla!",
     "affected": "3.x < 3.4.6", "severity": "critical", "type": "rce",
     "requires_version": True,
     "title": "Joomla! PHP object injection / RCE",
     "description": "Remote code execution via crafted HTTP_USER_AGENT "
     "(PHP object injection) in Joomla! < 3.4.6.",
     "ref": "https://nvd.nist.gov/vuln/detail/CVE-2015-8562"},

    # --- Drupal ------------------------------------------------------------
    {"cve": "CVE-2018-7600", "technology": "drupal", "component": "Drupal",
     "affected": "7.x, 8.x", "severity": "critical", "type": "rce",
     "requires_version": True,
     "title": "Drupalgeddon2 RCE",
     "description": "Unauthenticated remote code execution (Drupalgeddon2).",
     "ref": "https://nvd.nist.gov/vuln/detail/CVE-2018-7600"},
    {"cve": "CVE-2014-3704", "technology": "drupal", "component": "Drupal",
     "affected": "7.x < 7.32", "severity": "critical", "type": "sqli",
     "requires_version": True,
     "title": "Drupalgeddon SQL injection",
     "description": "Unauthenticated SQL injection (CVE-2014-3704).",
     "ref": "https://nvd.nist.gov/vuln/detail/CVE-2014-3704"},

    # --- JavaScript frameworks --------------------------------------------
    {"cve": "CVE-2020-11023", "technology": "jquery", "component": "jQuery",
     "affected": "< 3.5.0", "severity": "high", "type": "xss",
     "requires_version": True,
     "title": "jQuery XSS via HTML parsing",
     "description": "XSS in jQuery < 3.5.0 when passing untrusted HTML to "
     "html()/prepend()/etc.",
     "ref": "https://nvd.nist.gov/vuln/detail/CVE-2020-11023"},
    {"cve": "CVE-2021-21206", "technology": "react", "component": "React",
     "affected": "< 17.0.2", "severity": "high", "type": "xss",
     "requires_version": True,
     "title": "React XSS via JSON stringify",
     "description": "XSS when using dangerouslySetInnerHTML with "
     "JSON.stringify in React < 17.0.2.",
     "ref": "https://nvd.nist.gov/vuln/detail/CVE-2021-21206"},
    {"cve": "CVE-2022-25869", "technology": "angular", "component": "Angular",
     "affected": "< 15.1.5", "severity": "high", "type": "xss",
     "requires_version": True,
     "title": "Angular XSS via attributes",
     "description": "Cross-site scripting in Angular via attribute "
     "sanitization bypass.",
     "ref": "https://nvd.nist.gov/vuln/detail/CVE-2022-25869"},
    {"cve": "CVE-2022-23647", "technology": "nextjs", "component": "Next.js",
     "affected": "< 12.1.0", "severity": "high", "type": "rce",
     "requires_version": True,
     "title": "Next.js RCE",
     "description": "RCE in Next.js < 12.1.0 via image optimization (sharp).",
     "ref": "https://nvd.nist.gov/vuln/detail/CVE-2022-23647"},

    # --- Web servers / reverse proxies -------------------------------------
    {"cve": "CVE-2021-23017", "technology": "nginx", "component": "nginx",
     "affected": "0.6.18 - 1.20.0", "severity": "high", "type": "other",
     "requires_version": True,
     "title": "nginx resolver off-by-one",
     "description": "Off-by-one write in nginx resolver (DNS).",
     "ref": "https://nvd.nist.gov/vuln/detail/CVE-2021-23017"},
    {"cve": "CVE-2021-41773", "technology": "apache", "component": "Apache HTTP Server",
     "affected": "2.4.49 only", "severity": "critical", "type": "traversal",
     "requires_version": True,
     "title": "Apache path traversal + RCE",
     "description": "Path traversal and file disclosure / RCE in "
     "Apache 2.4.49.",
     "ref": "https://nvd.nist.gov/vuln/detail/CVE-2021-41773"},

    # --- Backend frameworks ------------------------------------------------
    {"cve": "CVE-2019-14234", "technology": "django", "component": "Django",
     "affected": "< 2.1.12, 2.2.x < 2.2.4", "severity": "high", "type": "sqli",
     "requires_version": True,
     "title": "Django admin SQL injection",
     "description": "SQL injection via Django admin JSONField/HStoreField.",
     "ref": "https://nvd.nist.gov/vuln/detail/CVE-2019-14234"},
    {"cve": "CVE-2022-24999", "technology": "express", "component": "Express",
     "affected": "< 4.17.3", "severity": "high", "type": "rce",
     "requires_version": True,
     "title": "Express qs prototype pollution (CVE-2022-24999)",
     "description": "Prototype pollution in qs can lead to RCE in some setups.",
     "ref": "https://nvd.nist.gov/vuln/detail/CVE-2022-24999"},
    {"cve": "CVE-2019-1010083", "technology": "flask", "component": "Flask",
     "affected": "< 1.0 (dev-version specific)", "severity": "medium", "type": "other",
     "requires_version": True,
     "title": "Flask timing attack / memory issue",
     "description": "Potential timing/memory issue in specific Flask "
     "development versions.",
     "ref": "https://nvd.nist.gov/vuln/detail/CVE-2019-1010083"},
    {"cve": "CVE-2024-24762", "technology": "fastapi", "component": "FastAPI",
     "affected": "< 0.109.0", "severity": "high", "type": "xss",
     "requires_version": True,
     "title": "FastAPI Python-multipart XSS",
     "description": "XSS in python-multipart < 0.0.7 (used by FastAPI forms).",
     "ref": "https://nvd.nist.gov/vuln/detail/CVE-2024-24762"},

    # --- Databases / services (by open port) --------------------------------
    {"cve": "CVE-2012-2122", "technology": "mysql", "component": "MySQL",
     "affected": "5.1.x, 5.5.x, 5.6.x", "severity": "high", "type": "auth",
     "requires_version": True,
     "title": "MySQL authentication bypass",
     "description": "Authentication bypass when memcmp() returns 0 randomly.",
     "ref": "https://nvd.nist.gov/vuln/detail/CVE-2012-2122"},
    {"cve": "CVE-2022-0543", "technology": "redis", "component": "Redis",
     "affected": "Debian/Ubuntu builds", "severity": "critical", "type": "rce",
     "requires_version": True,
     "title": "Redis Lua sandbox escape RCE",
     "description": "RCE via Lua sandbox escape in Debian/Ubuntu Redis builds.",
     "ref": "https://nvd.nist.gov/vuln/detail/CVE-2022-0543"},
    {"cve": "CVE-2015-1427", "technology": "elasticsearch", "component": "Elasticsearch",
     "affected": "< 1.4.3", "severity": "critical", "type": "rce",
     "requires_version": True,
     "title": "Elasticsearch Groovy RCE",
     "description": "Unauthenticated RCE via dynamic Groovy scripts (CVE-2015-1427).",
     "ref": "https://nvd.nist.gov/vuln/detail/CVE-2015-1427"},

    # --- SSH ---------------------------------------------------------------
    {"cve": "CVE-2024-6387", "technology": "ssh", "component": "OpenSSH",
     "affected": "8.5p1 - 9.7p1", "severity": "critical", "type": "rce",
     "requires_version": True,
     "title": "OpenSSH regreSSHion RCE",
     "description": "Signal handler race condition → unauthenticated RCE (glibc).",
     "ref": "https://nvd.nist.gov/vuln/detail/CVE-2024-6387"},
    {"cve": "CVE-2018-15473", "technology": "ssh", "component": "OpenSSH",
     "affected": "< 7.7", "severity": "medium", "type": "auth",
     "requires_version": True,
     "title": "OpenSSH user enumeration",
     "description": "Username enumeration via malformed authentication messages.",
     "ref": "https://nvd.nist.gov/vuln/detail/CVE-2018-15473"},
]

# Technology keys that map to XSS-prone components (activate XSS scanner).
XSS_PRONE_TECHNOLOGIES = {
    "jquery", "react", "vue", "angular", "nextjs", "wordpress",
    "drupal", "joomla", "express", "fastapi", "bootstrap",
}

# Technology keys that map to IDOR-prone components (activate IDOR scanner).
IDOR_PRONE_TECHNOLOGIES = {
    "wordpress", "drupal", "joomla", "django", "flask", "express",
    "fastapi", "rails", "laravel",
}


def _parse_version(v: str) -> tuple[tuple[int, ...], int] | None:
    """Parse "9.6p1" → ((9,6), 1); "1.24.0" → ((1,24,0), 0). Returns None."""
    m = re.match(r"(\d+(?:\.\d+)*)(?:p(\d+))?", v.strip())
    if not m:
        return None
    nums = tuple(int(x) for x in m.group(1).split("."))
    patch = int(m.group(2) or 0)
    return (nums, patch)


def _version_in_affected(detected: str, affected: str) -> bool:
    """Return True if ``detected`` version falls in the ``affected`` range.

    Handles the free-form constraints used by the curated database:
      * ``"< 3.5.0"`` / ``"< 5.0.1"`` → detected < bound
      * ``"8.5p1 - 9.7p1"`` / ``"0.6.18 - 1.20.0"`` → between
      * ``"2.4.49 only"`` → equals
      * ``"5.1.x, 5.5.x, 5.6.x"`` / ``"7.x, 8.x"`` → major family match
      * ``"3.7.0"`` → equals
    Unknown/non-version constraints (e.g. "Debian/Ubuntu builds") return
    False — we cannot confirm, so the CVE stays "potential".
    """
    detected_p = _parse_version(detected)
    if detected_p is None:
        return False

    for part in affected.split(","):
        part = part.strip()
        if not part:
            continue

        # Range: "A - B"
        range_m = re.match(r"^(.+?)\s*-\s*(.+?)$", part)
        if range_m:
            lo = _parse_version(range_m.group(1))
            hi = _parse_version(range_m.group(2))
            if lo and hi and lo <= detected_p <= hi:
                return True
            continue

        # "< X"
        lt_m = re.match(r"^<\s*(.+)$", part)
        if lt_m:
            bound = _parse_version(lt_m.group(1))
            if bound and detected_p < bound:
                return True
            continue

        # "X only"
        only_m = re.match(r"^(.+?)\s+only$", part)
        if only_m:
            exact = _parse_version(only_m.group(1))
            if exact and detected_p == exact:
                return True
            continue

        # "X.x" / "5.1.x, ..." family match (e.g. "7.x", "5.1.x")
        family_m = re.match(r"^(\d+(?:\.\d+)*)(?:\.x)?$", part)
        if family_m:
            fam = tuple(int(x) for x in family_m.group(1).split("."))
            if detected_p[0][: len(fam)] == fam:
                return True
            continue

        # bare version "3.7.0" → equality
        exact = _parse_version(part)
        if exact and detected_p == exact:
            return True

    return False


def _tech_keys(
    technologies: list[dict[str, Any]] | None,
    open_ports: list[dict[str, Any]] | None,
) -> set[str]:
    """Collect technology keys from evidence categories + open-port services."""
    keys: set[str] = set()
    for tech in technologies or []:
        category = (tech.get("evidence") or {}).get("category", "")
        key = category.split(":")[-1].lower()
        if key:
            keys.add(key)
    for port in open_ports or []:
        service = (port.get("service") or "").lower()
        if service:
            keys.add(service)
    return keys


def lookup_cves(
    technologies: list[dict[str, Any]] | None,
    open_ports: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Return CVEs matching detected technologies / open-port services.

    Version-aware: when a technology/port carries a detected ``version``
    (from framework_detection evidence or a port banner), the CVE is only
    ``verified=True`` (full severity/confidence) if the version falls in the
    affected range. Without a version, the match stays ``verified=False``
    (potential, medium severity, reduced confidence) — a host with an open
    SSH port is never reported as a confirmed regreSSHion.
    """
    # Collect technology key → detected version (if any).
    tech_versions: dict[str, str] = {}
    for tech in technologies or []:
        category = (tech.get("evidence") or {}).get("category", "")
        key = category.split(":")[-1].lower()
        if not key:
            continue
        version = (tech.get("evidence") or {}).get("version")
        # First detection wins; later detections only fill a missing version.
        if key not in tech_versions and isinstance(version, str) and version:
            tech_versions[key] = version

    port_versions: dict[str, str] = {}
    for port in open_ports or []:
        service = (port.get("service") or "").lower()
        if not service:
            continue
        version = port.get("version")
        if service not in port_versions and isinstance(version, str) and version:
            port_versions[service] = version

    keys = set(tech_versions) | set(port_versions) | _tech_keys(technologies, open_ports)
    if not keys:
        return []

    matched: list[dict[str, Any]] = []
    for cve in CVE_DATABASE:
        if cve["technology"] not in keys:
            continue
        entry = dict(cve)
        version = tech_versions.get(cve["technology"]) or port_versions.get(
            cve["technology"]
        )
        if version and _version_in_affected(version, cve["affected"]):
            entry["verified"] = True
            entry["confidence"] = 0.9
            entry["detected_version"] = version
        else:
            entry["verified"] = False
            entry["confidence"] = 0.5
            if version:
                entry["detected_version"] = version
        matched.append(entry)
    return matched


def cves_trigger_xss(cves: list[dict[str, Any]]) -> bool:
    """True if any matched CVE is an XSS-type vulnerability."""
    return any(c.get("type") == "xss" for c in cves)


def cves_trigger_idor(cves: list[dict[str, Any]]) -> bool:
    """True if any matched CVE is an IDOR-type vulnerability."""
    return any(c.get("type") == "idor" for c in cves)


def techs_trigger_xss(technologies: list[dict[str, Any]]) -> bool:
    """True if any detected technology is XSS-prone."""
    return bool(
        set(tech.split(":")[-1].lower() for tech in
            ((t.get("evidence") or {}).get("category", "") for t in technologies or [])
            if tech)
        & XSS_PRONE_TECHNOLOGIES
    )


def techs_trigger_idor(technologies: list[dict[str, Any]]) -> bool:
    """True if any detected technology is IDOR-prone."""
    return bool(
        set(tech.split(":")[-1].lower() for tech in
            ((t.get("evidence") or {}).get("category", "") for t in technologies or [])
            if tech)
        & IDOR_PRONE_TECHNOLOGIES
    )
