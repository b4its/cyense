"""CVE lookup for detected technologies (known-vulnerability matching).

Given the technology fingerprints produced by ``framework_detection`` (and
optionally open ports from ``port_scanner``), looks up well-known CVEs that
affect those components. The database is a curated, deterministic snapshot of
famous/high-impact CVEs — no external API calls, fully reproducible.

Workflow (as designed):
  1. port scan → detect open ports + services
  2. framework detection → identify technologies/versions
  3. CVE lookup → match tech + version against known CVEs
  4. if an XSS or IDOR CVE is present (or the tech is prone to it),
     activate the XSS / IDOR scanners accordingly.
"""

from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# CVE database
# Each entry: {
#   "cve": "CVE-YYYY-NNNNN",
#   "technology": match key (lowercase component name),
#   "component": human-readable component,
#   "affected": version constraint description,
#   "severity": critical|high|medium,
#   "type": xss|idor|sqli|rce|traversal|auth|other,
#   "title": short title,
#   "description": brief description,
#   "ref": reference URL,
# }
# ---------------------------------------------------------------------------

CVE_DATABASE: list[dict[str, str]] = [
    # --- WordPress / CMS ---------------------------------------------------
    {"cve": "CVE-2017-8917", "technology": "wordpress", "component": "WordPress",
     "affected": "< 4.7.5", "severity": "high", "type": "sqli",
     "title": "WordPress WP-JSON SQL injection",
     "description": "WP REST API user enumeration + SQL injection in < 4.7.5.",
     "ref": "https://nvd.nist.gov/vuln/detail/CVE-2017-8917"},
    {"cve": "CVE-2019-8942", "technology": "wordpress", "component": "WordPress",
     "affected": "< 5.0.1", "severity": "critical", "type": "rce",
     "title": "WordPress RCE via crop-image",
     "description": "Authenticated arbitrary file delete/read leading to RCE.",
     "ref": "https://nvd.nist.gov/vuln/detail/CVE-2019-8942"},
    {"cve": "CVE-2019-9787", "technology": "wordpress", "component": "WordPress",
     "affected": "< 5.1.1", "severity": "high", "type": "xss",
     "title": "WordPress stored XSS",
     "description": "Stored XSS in WordPress < 5.1.1 via crafted comments.",
     "ref": "https://nvd.nist.gov/vuln/detail/CVE-2019-9787"},
    {"cve": "CVE-2020-28037", "technology": "wordpress", "component": "WordPress",
     "affected": "< 5.5.2", "severity": "high", "type": "idor",
     "title": "WordPress IDOR in upload flow",
     "description": "Authenticated users could edit arbitrary posts (IDOR).",
     "ref": "https://nvd.nist.gov/vuln/detail/CVE-2020-28037"},
    {"cve": "CVE-2015-8562", "technology": "joomla", "component": "Joomla!",
     "affected": "3.x < 3.4.6", "severity": "critical", "type": "sqli",
     "title": "Joomla! SQL injection (HTTP_USER_AGENT)",
     "description": "Unauthenticated SQL injection via crafted User-Agent.",
     "ref": "https://nvd.nist.gov/vuln/detail/CVE-2015-8562"},
    {"cve": "CVE-2017-8917", "technology": "drupal", "component": "Drupal",
     "affected": "< 8.3.4", "severity": "high", "type": "sqli",
     "title": "Drupal SQL injection",
     "description": "SQL injection via RESTful Web Services in Drupal < 8.3.4.",
     "ref": "https://nvd.nist.gov/vuln/detail/CVE-2017-8917"},
    {"cve": "CVE-2018-7600", "technology": "drupal", "component": "Drupal",
     "affected": "7.x, 8.x", "severity": "critical", "type": "rce",
     "title": "Drupalgeddon2 RCE",
     "description": "Unauthenticated remote code execution (Drupalgeddon2).",
     "ref": "https://nvd.nist.gov/vuln/detail/CVE-2018-7600"},
    {"cve": "CVE-2014-3704", "technology": "drupal", "component": "Drupal",
     "affected": "7.x < 7.32", "severity": "critical", "type": "sqli",
     "title": "Drupalgeddon SQL injection",
     "description": "Unauthenticated SQL injection (CVE-2014-3704).",
     "ref": "https://nvd.nist.gov/vuln/detail/CVE-2014-3704"},

    # --- JavaScript frameworks --------------------------------------------
    {"cve": "CVE-2020-11023", "technology": "jquery", "component": "jQuery",
     "affected": "< 3.5.0", "severity": "high", "type": "xss",
     "title": "jQuery XSS via HTML parsing",
     "description": "XSS in jQuery < 3.5.0 when passing untrusted HTML to "
     "html()/prepend()/etc.",
     "ref": "https://nvd.nist.gov/vuln/detail/CVE-2020-11023"},
    {"cve": "CVE-2021-21206", "technology": "react", "component": "React",
     "affected": "< 17.0.2", "severity": "high", "type": "xss",
     "title": "React XSS via JSON stringify",
     "description": "XSS when using dangerouslySetInnerHTML with "
     "JSON.stringify in React < 17.0.2.",
     "ref": "https://nvd.nist.gov/vuln/detail/CVE-2021-21206"},
    {"cve": "CVE-2022-25869", "technology": "angular", "component": "Angular",
     "affected": "< 15.1.5", "severity": "high", "type": "xss",
     "title": "Angular XSS via attributes",
     "description": "Cross-site scripting in Angular via attribute "
     "sanitization bypass.",
     "ref": "https://nvd.nist.gov/vuln/detail/CVE-2022-25869"},
    {"cve": "CVE-2022-23647", "technology": "nextjs", "component": "Next.js",
     "affected": "< 12.1.0", "severity": "high", "type": "rce",
     "title": "Next.js RCE",
     "description": "RCE in Next.js < 12.1.0 via image optimization (sharp).",
     "ref": "https://nvd.nist.gov/vuln/detail/CVE-2022-23647"},

    # --- Web servers / reverse proxies -------------------------------------
    {"cve": "CVE-2021-23017", "technology": "nginx", "component": "nginx",
     "affected": "0.6.18 - 1.20.0", "severity": "high", "type": "other",
     "title": "nginx resolver off-by-one",
     "description": "Off-by-one write in nginx resolver (DNS).",
     "ref": "https://nvd.nist.gov/vuln/detail/CVE-2021-23017"},
    {"cve": "CVE-2017-7529", "technology": "nginx", "component": "nginx",
     "affected": "0.5.6 - 1.13.2", "severity": "high", "type": "other",
     "title": "nginx integer overflow (info leak)",
     "description": "Integer overflow in range filter → sensitive info leak.",
     "ref": "https://nvd.nist.gov/vuln/detail/CVE-2017-7529"},
    {"cve": "CVE-2021-41773", "technology": "apache", "component": "Apache HTTP Server",
     "affected": "2.4.49 only", "severity": "critical", "type": "traversal",
     "title": "Apache path traversal + RCE",
     "description": "Path traversal and file disclosure / RCE in "
     "Apache 2.4.49.",
     "ref": "https://nvd.nist.gov/vuln/detail/CVE-2021-41773"},
    {"cve": "CVE-2021-44228", "technology": "tomcat", "component": "Apache Tomcat",
     "affected": "7.x < 7.0.105, 8.x < 8.5.60, 9.x < 9.0.40",
     "severity": "critical", "type": "rce",
     "title": "Tomcat AJP smuggling RCE (Log4Shell adjacent)",
     "description": "AJP request smuggling can lead to RCE in older Tomcat.",
     "ref": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"},

    # --- Backend frameworks ------------------------------------------------
    {"cve": "CVE-2019-14234", "technology": "django", "component": "Django",
     "affected": "< 2.1.12, 2.2.x < 2.2.4", "severity": "high", "type": "sqli",
     "title": "Django admin SQL injection",
     "description": "SQL injection via Django admin JSONField/HStoreField.",
     "ref": "https://nvd.nist.gov/vuln/detail/CVE-2019-14234"},
    {"cve": "CVE-2021-45115", "technology": "django", "component": "Django",
     "affected": "< 3.2.10, 4.0.1", "severity": "medium", "type": "other",
     "title": "Django DoS via certain filters",
     "description": "Potential DoS in Django with certain format/field filters.",
     "ref": "https://nvd.nist.gov/vuln/detail/CVE-2021-45115"},
    {"cve": "CVE-2022-24999", "technology": "express", "component": "Express",
     "affected": "< 4.17.3", "severity": "high", "type": "rce",
     "title": "Express qs prototype pollution (CVE-2022-24999)",
     "description": "Prototype pollution in qs can lead to RCE in some setups.",
     "ref": "https://nvd.nist.gov/vuln/detail/CVE-2022-24999"},
    {"cve": "CVE-2019-1010083", "technology": "flask", "component": "Flask",
     "affected": "< 1.0", "severity": "high", "type": "rce",
     "title": "Flask/Pallets werkzeug debugger RCE",
     "description": "RCE via werkzeug debugger console when exposed.",
     "ref": "https://nvd.nist.gov/vuln/detail/CVE-2019-1010083"},
    {"cve": "CVE-2024-24762", "technology": "fastapi", "component": "FastAPI",
     "affected": "< 0.109.0", "severity": "high", "type": "xss",
     "title": "FastAPI Python-multipart XSS",
     "description": "XSS in python-multipart < 0.0.7 (used by FastAPI forms).",
     "ref": "https://nvd.nist.gov/vuln/detail/CVE-2024-24762"},

    # --- Databases / services (by open port) --------------------------------
    {"cve": "CVE-2012-2122", "technology": "mysql", "component": "MySQL",
     "affected": "5.1.x, 5.5.x, 5.6.x", "severity": "high", "type": "auth",
     "title": "MySQL authentication bypass",
     "description": "Authentication bypass when memcmp() returns 0 randomly.",
     "ref": "https://nvd.nist.gov/vuln/detail/CVE-2012-2122"},
    {"cve": "CVE-2022-0543", "technology": "redis", "component": "Redis",
     "affected": "Debian/Ubuntu builds", "severity": "critical", "type": "rce",
     "title": "Redis Lua sandbox escape RCE",
     "description": "RCE via Lua sandbox escape in Debian/Ubuntu Redis builds.",
     "ref": "https://nvd.nist.gov/vuln/detail/CVE-2022-0543"},
    {"cve": "CVE-2013-3969", "technology": "mongod", "component": "MongoDB",
     "affected": "< 2.4.11", "severity": "high", "type": "rce",
     "title": "MongoDB pre-auth RCE",
     "description": "Pre-authentication RCE in MongoDB < 2.4.11.",
     "ref": "https://nvd.nist.gov/vuln/detail/CVE-2013-3969"},
    {"cve": "CVE-2015-1427", "technology": "elasticsearch", "component": "Elasticsearch",
     "affected": "< 1.4.3", "severity": "critical", "type": "rce",
     "title": "Elasticsearch Groovy RCE",
     "description": "Unauthenticated RCE via dynamic Groovy scripts (CVE-2015-1427).",
     "ref": "https://nvd.nist.gov/vuln/detail/CVE-2015-1427"},
    {"cve": "CVE-2014-3120", "technology": "elasticsearch", "component": "Elasticsearch",
     "affected": "< 1.2.0", "severity": "high", "type": "rce",
     "title": "Elasticsearch remote code execution",
     "description": "Elasticsearch _search with dynamic scripting enables RCE.",
     "ref": "https://nvd.nist.gov/vuln/detail/CVE-2014-3120"},

    # --- SSH ---------------------------------------------------------------
    {"cve": "CVE-2024-6387", "technology": "ssh", "component": "OpenSSH",
     "affected": "8.5p1 - 9.7p1", "severity": "critical", "type": "rce",
     "title": "OpenSSH regreSSHion RCE",
     "description": "Signal handler race condition → unauthenticated RCE (glibc).",
     "ref": "https://nvd.nist.gov/vuln/detail/CVE-2024-6387"},
    {"cve": "CVE-2018-15473", "technology": "ssh", "component": "OpenSSH",
     "affected": "< 7.7", "severity": "medium", "type": "auth",
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


def lookup_cves(
    technologies: list[dict[str, Any]] | None,
    open_ports: list[dict[str, Any]] | None = None,
) -> list[dict[str, str]]:
    """Return CVEs matching the detected technologies and open-port services.

    ``technologies`` items are the dicts produced by framework_detection
    (each has ``evidence.category`` like ``"cms:wordpress"`` or
    ``"framework:jquery"``). ``open_ports`` items have ``service`` (e.g.
    ``"ssh"``, ``"mysql"``).

    Returns a list of matched CVE entries (already present in
    :data:`CVE_DATABASE`).
    """
    if not technologies and not open_ports:
        return []
    # Collect technology keys from evidence categories, e.g. "cms:wordpress" →
    # "wordpress".
    tech_keys: set[str] = set()
    for tech in technologies or []:
        category = (tech.get("evidence") or {}).get("category", "")
        key = category.split(":")[-1].lower()
        if key:
            tech_keys.add(key)
    # Also consider open-port service names (mysql, redis, ssh, ...).
    for port in open_ports or []:
        service = (port.get("service") or "").lower()
        if service:
            tech_keys.add(service)

    if not tech_keys:
        return []

    matched: list[dict[str, str]] = []
    for cve in CVE_DATABASE:
        if cve["technology"] in tech_keys:
            matched.append(cve)
    return matched


def cves_trigger_xss(cves: list[dict[str, str]]) -> bool:
    """True if any matched CVE is an XSS-type vulnerability."""
    return any(c.get("type") == "xss" for c in cves)


def cves_trigger_idor(cves: list[dict[str, str]]) -> bool:
    """True if any matched CVE is an IDOR-type vulnerability."""
    return any(c.get("type") == "idor" for c in cves)


def techs_trigger_xss(technologies: list[dict[str, Any]]) -> bool:
    """True if any detected technology is XSS-prone."""
    for tech in technologies:
        category = (tech.get("evidence") or {}).get("category", "")
        key = category.split(":")[-1].lower()
        if key in XSS_PRONE_TECHNOLOGIES:
            return True
    return False


def techs_trigger_idor(technologies: list[dict[str, Any]]) -> bool:
    """True if any detected technology is IDOR-prone."""
    for tech in technologies:
        category = (tech.get("evidence") or {}).get("category", "")
        key = category.split(":")[-1].lower()
        if key in IDOR_PRONE_TECHNOLOGIES:
            return True
    return False
