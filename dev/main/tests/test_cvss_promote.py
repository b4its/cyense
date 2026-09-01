"""Tests for enrich_finding CVSS promotion (CVE-MATCH evidence → top-level)."""

from __future__ import annotations

from app.report.cvss import enrich_finding


def test_promote_evidence_cvss_score() -> None:
    f = {"rule": "CVE-MATCH", "severity": "critical",
         "evidence": {"cvss_score": 9.8, "cve": "CVE-2024-6387"}}
    enrich_finding(f)
    assert f["cvss_score"] == 9.8
    # cwe filled from the CVE-MATCH profile so SARIF isn't CWE-Unknown
    assert f.get("cwe") == "CWE-1035"


def test_promote_does_not_overwrite_existing() -> None:
    f = {"rule": "CVE-MATCH", "cvss_score": 8.0,
         "evidence": {"cvss_score": 9.8}}
    enrich_finding(f)
    assert f["cvss_score"] == 8.0  # existing top-level wins


def test_no_crash_on_bogus_evidence_score() -> None:
    f = {"rule": "CVE-MATCH", "evidence": {"cvss_score": "9.8-bogus"}}
    enrich_finding(f)  # must not raise
    assert f.get("cvss_score") is None or isinstance(f["cvss_score"], float)


def test_deep_rules_get_profiles() -> None:
    from app.report.cvss import get_profile
    for rule in ("CY011", "CY012", "CY013", "XS009", "XS010", "XS011"):
        assert get_profile(rule) is not None, rule
