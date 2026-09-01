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

def test_cve_lookup_stage_builds_findings_and_flags() -> None:
    from app.engines.website_engine import WebsiteEngine

    tech_findings = [
        _tech("cms:wordpress"),   # → SQLi + XSS + IDOR CVEs
        _tech("lib:jquery"),      # → XSS CVE
    ]
    findings, xss_rel, idor_rel = WebsiteEngine._cve_lookup_stage(
        "scan-abc", tech_findings, [], "http://x.test/"
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

    # evidence carries the CVE id
    cve_ids = {f["evidence"]["cve"] for f in cve_findings}
    assert "CVE-2020-11023" in cve_ids  # jQuery XSS


def test_cve_lookup_stage_no_triggers_for_plain_server() -> None:
    from app.engines.website_engine import WebsiteEngine

    findings, xss_rel, idor_rel = WebsiteEngine._cve_lookup_stage(
        "scan-abc", [_tech("server:nginx")], [], "http://x.test/"
    )
    cve_findings = [f for f in findings if f["rule"] == "CVE-MATCH"]
    assert len(cve_findings) >= 1  # nginx CVEs (potential)
    # nginx is neither XSS-prone nor IDOR-prone → scanners not force-activated
    assert xss_rel is False
    assert idor_rel is False
