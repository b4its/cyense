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
    assert "CVE-2017-8917" in cve_ids  # WP SQLi
    assert "CVE-2019-9787" in cve_ids  # WP stored XSS
    assert "CVE-2020-28037" in cve_ids  # WP IDOR


def test_lookup_jquery_cve() -> None:
    cves = lookup_cves([_tech("lib:jquery")])
    assert any(c["cve"] == "CVE-2020-11023" for c in cves)  # jQuery XSS


def test_lookup_nginx_cves() -> None:
    cves = lookup_cves([_tech("server:nginx")])
    cve_ids = {c["cve"] for c in cves}
    assert "CVE-2021-23017" in cve_ids
    assert "CVE-2017-7529" in cve_ids


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
    cves = lookup_cves([_tech("cms:wordpress")])
    assert cves_trigger_idor(cves) is True  # CVE-2020-28037 IDOR


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
        tech_findings, [], "http://x.test/"
    )

    cve_findings = [f for f in findings if f["rule"] == "CVE-MATCH"]
    assert len(cve_findings) >= 3
    # XSS + IDOR both relevant for wordpress + jquery stack
    assert xss_rel is True
    assert idor_rel is True

    # evidence carries the CVE id
    cve_ids = {f["evidence"]["cve"] for f in cve_findings}
    assert "CVE-2020-11023" in cve_ids  # jQuery XSS


def test_cve_lookup_stage_no_triggers_for_plain_server() -> None:
    from app.engines.website_engine import WebsiteEngine

    findings, xss_rel, idor_rel = WebsiteEngine._cve_lookup_stage(
        [_tech("server:nginx")], [], "http://x.test/"
    )
    cve_findings = [f for f in findings if f["rule"] == "CVE-MATCH"]
    assert len(cve_findings) >= 2  # nginx CVEs
    # nginx is neither XSS-prone nor IDOR-prone → scanners not force-activated
    assert xss_rel is False
    assert idor_rel is False
