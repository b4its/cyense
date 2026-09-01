"""Tests for CVE lookup + conditional XSS/IDOR activation.

Covers the workflow:
  1. CVE lookup matches detected technology → known CVEs
  2. Port services (ssh, mysql, redis) → service CVEs
  3. XSS/IDOR activation flags from CVE type and technology type
  4. WebsiteEngine._cve_lookup_stage builds CVE-MATCH findings
"""

from __future__ import annotations

from app.utils.cve_lookup import (
    cves_trigger_idor,
    cves_trigger_xss,
    lookup_cves,
    techs_trigger_idor,
    techs_trigger_xss,
)


def _tech(category: str) -> dict:
    return {
        "rule": "DETECT-X",
        "severity": "info",
        "evidence": {"category": category, "url": "http://x.test/"},
    }


# ---------------------------------------------------------------------------
# lookup_cves — technology match
# ---------------------------------------------------------------------------

def test_lookup_wordpress_cves() -> None:
    cves = lookup_cves([_tech("cms:wordpress")])
    cve_ids = {c["cve"] for c in cves}
    assert "CVE-2019-8942" in cve_ids  # WP RCE
    assert "CVE-2019-9787" in cve_ids  # WP RCE (file upload)
    assert "CVE-2020-28037" in cve_ids  # WP install.php
    # CVE-2017-8917 is a Joomla CVE — must NOT be attributed to WordPress.
    assert "CVE-2017-8917" not in cve_ids


def test_lookup_jquery_cve() -> None:
    cves = lookup_cves([_tech("lib:jquery")])
    assert any(c["cve"] == "CVE-2020-11023" for c in cves)  # jQuery XSS


def test_lookup_nginx_cves() -> None:
    cves = lookup_cves([_tech("server:nginx")])
    cve_ids = {c["cve"] for c in cves}
    assert "CVE-2021-23017" in cve_ids
    # CVE-2017-7529 removed from DB (superseded/less relevant); nginx now has
    # only the resolver CVE in the curated set.
    assert len(cve_ids) >= 1


def test_lookup_via_open_port_service() -> None:
    """Open port services (ssh/mysql/redis) also drive CVE lookup."""
    cves = lookup_cves([], open_ports=[
        {"port": 22, "service": "ssh"},
        {"port": 3306, "service": "mysql"},
        {"port": 6379, "service": "redis"},
    ])
    cve_ids = {c["cve"] for c in cves}
    assert "CVE-2024-6387" in cve_ids  # OpenSSH regreSSHion
    assert "CVE-2012-2122" in cve_ids  # MySQL auth bypass
    assert "CVE-2022-0543" in cve_ids  # Redis RCE


def test_lookup_no_technologies_returns_empty() -> None:
    assert lookup_cves([]) == []
    assert lookup_cves(None) == []


# ---------------------------------------------------------------------------
# Activation flags
# ---------------------------------------------------------------------------

def test_xss_trigger_from_cve() -> None:
    cves = lookup_cves([_tech("lib:jquery")])
    assert cves_trigger_xss(cves) is True  # jQuery XSS CVE
    assert cves_trigger_idor(cves) is False


def test_idor_trigger_from_cve() -> None:
    # Currently no curated CVE is IDOR-type (CVE-2020-28037 is actually an
    # install/RCE issue, not IDOR). cves_trigger_idor is therefore False for
    # the curated set — the IDOR signal comes from techs_trigger_idor instead.
    cves = lookup_cves([_tech("cms:wordpress")])
    assert cves_trigger_idor(cves) is False
    # Tech-based IDOR signal still fires for CMS/framework stacks.
    assert techs_trigger_idor([_tech("cms:wordpress")]) is True


def test_xss_trigger_from_technology() -> None:
    # jQuery / React / WordPress are XSS-prone technologies even w/o CVE match
    assert techs_trigger_xss([_tech("framework:jquery")]) is True
    assert techs_trigger_xss([_tech("framework:react")]) is True
    assert techs_trigger_xss([_tech("cms:wordpress")]) is True
    assert techs_trigger_xss([_tech("server:nginx")]) is False


def test_idor_trigger_from_technology() -> None:
    assert techs_trigger_idor([_tech("cms:drupal")]) is True
    assert techs_trigger_idor([_tech("stack:django")]) is True
    assert techs_trigger_idor([_tech("server:nginx")]) is False


# ---------------------------------------------------------------------------
# WebsiteEngine._cve_lookup_stage
# ---------------------------------------------------------------------------

class _Settings:
    cve_online_enabled = False  # offline tests (deterministic)
    cve_search_timeout = 3.0


def test_cve_lookup_stage_builds_findings_and_flags() -> None:
    import asyncio

    from app.engines.website_engine import WebsiteEngine

    engine = WebsiteEngine("t", brain=None, reports_dir="/tmp", settings=_Settings())
    tech_findings = [
        _tech("cms:wordpress"),   # → SQLi + XSS + IDOR CVEs
        _tech("lib:jquery"),      # → XSS CVE
    ]
    findings, xss_rel, idor_rel = asyncio.run(
        engine._cve_lookup_stage("scan-abc", tech_findings, [], "http://x.test/")
    )

    cve_findings = [f for f in findings if f["rule"] == "CVE-MATCH"]
    assert len(cve_findings) >= 3
    # XSS + IDOR both relevant for wordpress + jquery stack
    assert xss_rel is True
    assert idor_rel is True

    # finding_id is scan-scoped (no cross-scan collision)
    assert all(f["finding_id"].startswith("scan-abc-WCVE") for f in cve_findings)
    # version-blind matches are potential (medium severity, verified False)
    assert all(f["evidence"]["verified"] is False for f in cve_findings)
    assert all(f["severity"] == "medium" for f in cve_findings)
    # local database source recorded
    assert all(f["evidence"]["source"] == "local" for f in cve_findings)

    # evidence carries the CVE id
    cve_ids = {f["evidence"]["cve"] for f in cve_findings}
    assert "CVE-2020-11023" in cve_ids  # jQuery XSS


def test_cve_lookup_stage_no_triggers_for_plain_server() -> None:
    import asyncio

    from app.engines.website_engine import WebsiteEngine

    engine = WebsiteEngine("t", brain=None, reports_dir="/tmp", settings=_Settings())
    findings, xss_rel, idor_rel = asyncio.run(
        engine._cve_lookup_stage("scan-abc", [_tech("server:nginx")], [], "http://x.test/")
    )
    cve_findings = [f for f in findings if f["rule"] == "CVE-MATCH"]
    assert len(cve_findings) >= 1  # nginx CVEs (potential)
    # nginx is neither XSS-prone nor IDOR-prone → scanners not force-activated
    assert xss_rel is False
    assert idor_rel is False


# ---------------------------------------------------------------------------
# Version-aware CVE matching
# ---------------------------------------------------------------------------

def test_version_in_affected_ranges() -> None:
    from app.utils.cve_lookup import _version_in_affected

    assert _version_in_affected("3.4.0", "< 3.5.0")
    assert not _version_in_affected("3.5.0", "< 3.5.0")
    assert _version_in_affected("9.6p1", "8.5p1 - 9.7p1")
    assert not _version_in_affected("9.8p1", "8.5p1 - 9.7p1")
    assert _version_in_affected("2.4.49", "2.4.49 only")
    assert _version_in_affected("7.3", "7.x, 8.x")
    assert _version_in_affected("8.1", "7.x, 8.x")
    assert not _version_in_affected("6.2", "7.x, 8.x")
    assert _version_in_affected("1.20.0", "0.6.18 - 1.20.0")
    assert not _version_in_affected("1.21.0", "0.6.18 - 1.20.0")


def test_lookup_verified_when_version_affected() -> None:
    """nginx 1.18.0 falls in the resolver CVE range → verified match."""
    cves = lookup_cves([_tech_with_version("server:nginx", "1.18.0")])
    nginx_cve = next(c for c in cves if c["cve"] == "CVE-2021-23017")
    assert nginx_cve["verified"] is True
    assert nginx_cve["detected_version"] == "1.18.0"
    assert nginx_cve["confidence"] == 0.9


def test_lookup_not_verified_when_version_ok() -> None:
    """nginx 1.24.0 is outside the affected range → stays potential."""
    cves = lookup_cves([_tech_with_version("server:nginx", "1.24.0")])
    nginx_cve = next(c for c in cves if c["cve"] == "CVE-2021-23017")
    assert nginx_cve["verified"] is False
    assert nginx_cve["confidence"] == 0.5


def test_lookup_verified_via_ssh_banner_version() -> None:
    """OpenSSH 9.6p1 (from banner) is in regreSSHion range → verified."""
    cves = lookup_cves([], open_ports=[
        {"port": 22, "service": "ssh", "version": "9.6p1"},
    ])
    ssh_cve = next(c for c in cves if c["cve"] == "CVE-2024-6387")
    assert ssh_cve["verified"] is True
    assert ssh_cve["detected_version"] == "9.6p1"
    # OpenSSH 9.8p1 is OUTSIDE the range → not verified.
    cves2 = lookup_cves([], open_ports=[
        {"port": 22, "service": "ssh", "version": "9.8p1"},
    ])
    ssh_cve2 = next(c for c in cves2 if c["cve"] == "CVE-2024-6387")
    assert ssh_cve2["verified"] is False


def _tech_with_version(category: str, version: str) -> dict:
    return {
        "rule": "DETECT-X",
        "severity": "info",
        "evidence": {"category": category, "url": "http://x.test/",
                     "version": version},
    }
