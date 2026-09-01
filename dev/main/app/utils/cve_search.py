"""Live CVE search via public CVE-reporting sources.

Searches well-known CVE reporting websites / APIs for vulnerabilities
affecting a detected technology:

  * **NVD** — ``services.nvd.nist.gov`` (keyword search by technology +
    optional version filter; includes CVSS metrics and references)
  * **MITRE CVE API** — ``cveawg.mitre.org`` (CVE record details)

Used to *augment* the deterministic local CVE database in ``cve_lookup``:
online results are merged (deduplicated by CVE id) and each finding records
its ``source`` ("local" vs "nvd" vs "mitre") and the advisory URL.

Design:
  * fully optional — if the API is unreachable or times out, the scan
    silently falls back to the local database (never fails a scan);
  * rate-limit friendly — small concurrency cap + per-tech result cap;
  * deterministic merge — local DB entries take precedence on id conflict.
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx

# NVD API — returns CVE summaries with CVSS metrics.
_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# MITRE CVE API — returns full CVE record for a given id.
_MITRE_URL = "https://cveawg.mitre.org/api/cve/{cve_id}"

_DEFAULT_TIMEOUT = 12.0
_MAX_RESULTS_PER_TECH = 8
_MAX_CONCURRENCY = 3
_NVD_RESULTS_PER_PAGE = 20

# Technology key → NVD-friendly search term. Keys come from
# framework_detection categories ("cms:wordpress" → "wordpress") and
# port_scanner services ("ssh" → "openssh").
_NVD_SEARCH_TERMS: dict[str, str] = {
    "ssh": "OpenSSH",
    "mysql": "MySQL Server",
    "redis": "Redis",
    "mongod": "MongoDB",
    "elasticsearch": "Elasticsearch",
    "php": "PHP",
    "django": "Django",
    "flask": "Flask",
    "fastapi": "FastAPI",
    "express": "Express",
    "nginx": "nginx",
    "apache": "Apache HTTP Server",
    "tomcat": "Apache Tomcat",
    "wordpress": "WordPress",
    "joomla": "Joomla",
    "drupal": "Drupal",
    "jquery": "jQuery",
    "react": "React",
    "angular": "Angular",
    "nextjs": "Next.js",
    "laravel": "Laravel",
    "rails": "Ruby on Rails",
}


def _tech_keys(
    technologies: list[dict[str, Any]] | None,
    open_ports: list[dict[str, Any]] | None,
) -> dict[str, str]:
    """Return {tech_key: detected_version} from tech findings + ports."""
    versions: dict[str, str] = {}
    for tech in technologies or []:
        category = (tech.get("evidence") or {}).get("category", "")
        key = category.split(":")[-1].lower()
        if not key:
            continue
        version = (tech.get("evidence") or {}).get("version")
        if key not in versions and isinstance(version, str) and version:
            versions[key] = version
    for port in open_ports or []:
        service = (port.get("service") or "").lower()
        if service and service not in versions:
            version = port.get("version")
            if isinstance(version, str) and version:
                versions[service] = version
            else:
                versions[service] = ""
    return versions


def _parse_nvd_cve(item: dict[str, Any]) -> dict[str, Any] | None:
    """Convert one NVD vulnerability object into a CVE entry dict."""
    cve = item.get("cve") or {}
    cve_id = cve.get("id")
    if not cve_id:
        return None
    # Filter the well-known NVD placeholder entry.
    if cve_id == "CVE-1999-0661":
        return None

    desc = ""
    for d in cve.get("descriptions") or []:
        if d.get("lang") == "en":
            desc = d.get("value", "")
            break

    severity = "medium"
    cvss_score: float | None = None
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for m in metrics.get(key) or []:
            data = m.get("cvssData") or {}
            if data.get("baseScore") is not None:
                cvss_score = float(data["baseScore"])
                # V3.x carries baseSeverity inside cvssData; V2 carries it at
                # the metric level.
                base_sev = data.get("baseSeverity") or m.get("baseSeverity")
                severity = str(base_sev).lower() if base_sev else "medium"
            break
        if cvss_score is not None:
            break

    refs = [r.get("url") for r in (cve.get("references") or []) if r.get("url")]
    return {
        "cve": cve_id,
        "title": cve_id,
        "description": desc,
        "severity": severity if severity in ("critical", "high", "medium", "low") else "medium",
        "cvss_score": cvss_score,
        "type": "other",
        "ref": refs[0] if refs else f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        "source": "nvd",
    }


def _version_relevant(desc: str, version: str) -> bool:
    """Soft relevance check (kept for callers that want a version hint).

    NOTE: descriptions state affected RANGES, so this is a hint only and is
    NOT used to filter NVD results.
    """
    if not version:
        return True
    parts = version.split(".")
    short = ".".join(parts[:2]) if len(parts) >= 2 else version
    return short in desc


async def _query_nvd(
    client: httpx.AsyncClient,
    search_term: str,
    version: str,
) -> list[dict[str, Any]]:
    """Query NVD for CVEs matching a technology.

    NVD keyword search already returns technology-relevant CVEs. The detected
    version is recorded on each result (the caller/version-aware local DB
    decides confirmed vs potential) — we do NOT filter descriptions by the
    version string, because descriptions state affected RANGES, not the
    deployed version.
    """
    params = {"keywordSearch": search_term, "resultsPerPage": _NVD_RESULTS_PER_PAGE}
    try:
        resp = await client.get(_NVD_URL, params=params)
        resp.raise_for_status()
        data = resp.json()
    except (httpx.HTTPError, ValueError, KeyError):
        return []

    out: list[dict[str, Any]] = []
    try:
        for item in (data.get("vulnerabilities") or [])[:_MAX_RESULTS_PER_TECH]:
            entry = _parse_nvd_cve(item)
            if entry:
                entry["detected_version"] = version or None
                out.append(entry)
    except (ValueError, TypeError, KeyError):
        # A single malformed NVD item must never abort the whole online
        # search (silent-fallback contract).
        return []
    return out


async def search_cves_online(
    technologies: list[dict[str, Any]] | None,
    open_ports: list[dict[str, Any]] | None = None,
    *,
    timeout: float = _DEFAULT_TIMEOUT,
    max_concurrency: int = _MAX_CONCURRENCY,
) -> list[dict[str, Any]]:
    """Search live CVE sources for detected technologies.

    Returns a list of CVE entry dicts (with ``source`` set). Returns an empty
    list on any network/API failure — callers must fall back to the local
    database silently.
    """
    versions = _tech_keys(technologies, open_ports)
    if not versions:
        return []

    sem = asyncio.Semaphore(max_concurrency)
    # One shared client reused across techs (connection pooling).
    client = httpx.AsyncClient(timeout=timeout, follow_redirects=True)

    async def _bounded(key: str, version: str) -> list[dict[str, Any]]:
        async with sem:
            term = _NVD_SEARCH_TERMS.get(key, key.title())
            return await _query_nvd(client, term, version)

    try:
        # Run all tech queries CONCURRENTLY (bounded by semaphore) with a
        # global deadline so a hung upstream cannot stall the scan for
        # N × timeout.
        tasks = [_bounded(key, version) for key, version in versions.items()]
        gathered = await asyncio.wait_for(
            asyncio.gather(*tasks, return_exceptions=True),
            timeout=timeout * 2 + 5,
        )
    except TimeoutError:
        return []
    finally:
        await client.aclose()

    results: list[dict[str, Any]] = []
    for found in gathered:
        if isinstance(found, list):
            results.extend(found)

    # De-duplicate by CVE id (first wins), then sort by severity (CVSS desc).
    seen: set[str] = set()
    deduped: list[dict[str, Any]] = []
    for entry in results:
        if entry["cve"] not in seen:
            seen.add(entry["cve"])
            deduped.append(entry)
    deduped.sort(
        key=lambda e: (e.get("cvss_score") or 0.0),
        reverse=True,
    )
    return deduped


def merge_cves(
    local: list[dict[str, Any]],
    online: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Merge local + online CVEs, dedupe by id; local entries take precedence."""
    by_id: dict[str, dict[str, Any]] = {}
    for entry in local:
        by_id[entry["cve"]] = dict(entry)
    for entry in online:
        cve_id = entry.get("cve")
        if cve_id and cve_id not in by_id:
            by_id[cve_id] = dict(entry)
    return list(by_id.values())
