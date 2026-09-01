"""Tests for the domain scan engine (whole-domain assessment)."""

from __future__ import annotations

import asyncio

import pytest

from app.engines.domain_engine import DomainEngine, normalize_domain

# ---------------------------------------------------------------------------
# normalize_domain
# ---------------------------------------------------------------------------

def test_normalize_domain_url() -> None:
    assert normalize_domain("https://www.example.com/path") == "example.com"


def test_normalize_domain_bare() -> None:
    assert normalize_domain("example.com") == "example.com"
    assert normalize_domain("www.example.com") == "example.com"


def test_normalize_domain_subdomain() -> None:
    assert normalize_domain("api.sub.example.com") == "example.com"


def test_normalize_domain_public_suffix() -> None:
    assert normalize_domain("sub.example.co.uk") == "example.co.uk"
    assert normalize_domain("www.example.co.id") == "example.co.id"


def test_normalize_domain_case_and_trailing_dot() -> None:
    assert normalize_domain("Example.COM.") == "example.com"


# ---------------------------------------------------------------------------
# DomainEngine.run with mocked enumeration + website scans
# ---------------------------------------------------------------------------

class _Settings:
    discovery_enabled = True
    cve_online_enabled = False
    cve_search_timeout = 3.0
    rate_limit = 100
    max_concurrency = 10
    request_timeout = 5.0


def _fake_website_report(host: str, findings: list[dict]) -> dict:
    return {
        "meta": {"scan_id": f"s-{host}", "mode": "website"},
        "summary": {"total": len(findings), "critical": 0, "high": 0,
                    "medium": 0, "low": 0, "info": 0},
        "findings": [
            {"rule": "SECRET-LEAK", "severity": "high", "confidence": 0.8,
             "title": "token", "description": "x", "location": f"http://{host}/"}
            for _ in findings
        ],
    }


def test_domain_engine_aggregates_per_host(monkeypatch) -> None:
    """Enumeration + per-host scans are aggregated with host attribution."""
    from app.engines import domain_engine as de

    async def _fake_wayback(domain: str):
        return [f"http://api.{domain}/x", f"http://www.{domain}/"]

    async def _fake_dns(domain: str, prefixes=None):
        return [f"www.{domain}", f"mail.{domain}"]

    async def _fake_website_run(self, url: str, **kw):
        host = url.replace("http://", "").rstrip("/")
        findings = [{"rule": "SECRET-LEAK", "severity": "high",
                     "confidence": 0.8, "title": "token", "description": "x",
                     "evidence": {}, "location": url}]
        return {
            "meta": {"scan_id": f"s-{host}", "mode": "website"},
            "summary": {"total": 1, "critical": 0, "high": 1, "medium": 0,
                        "low": 0, "info": 0},
            "findings": findings,
        }

    monkeypatch.setattr(de, "fetch_wayback_urls", _fake_wayback)
    monkeypatch.setattr(de, "discover_subdomains", _fake_dns)
    monkeypatch.setattr(de.WebsiteEngine, "run", _fake_website_run)

    engine = DomainEngine("dom-1", None, "/tmp", _Settings())
    report = asyncio.run(engine.run(domain="example.com", max_hosts=10))

    assert report["meta"]["mode"] == "domain"
    summary = report["summary"]
    assert summary["hosts_scanned"] == 4  # example.com + api + www + mail
    assert summary["total"] == 4
    # Every finding carries host attribution
    for f in report["findings"]:
        assert "host" in f
        assert f["evidence"]["host"]
    # hosts table present
    assert len(report["hosts"]) == 4
    assert all(h["findings_count"] == 1 for h in report["hosts"])


def test_domain_engine_invalid_domain(monkeypatch) -> None:
    engine = DomainEngine("dom-2", None, "/tmp", _Settings())
    report = asyncio.run(engine.run(domain="not-a-domain"))
    assert report["meta"]["error"]
    assert report["summary"]["total"] == 0


def test_domain_engine_host_failure_does_not_fail_all(monkeypatch) -> None:
    """One failing host must not abort the whole domain scan."""
    from app.engines import domain_engine as de

    async def _fake_wayback(domain: str):
        return []

    async def _fake_dns(domain: str, prefixes=None):
        return [f"www.{domain}", f"broken.{domain}"]

    calls = {"n": 0}

    async def _fake_website_run(self, url: str, **kw):
        calls["n"] += 1
        if "broken" in url:
            raise RuntimeError("boom")
        return {
            "meta": {"scan_id": "s", "mode": "website"},
            "summary": {"total": 0, "critical": 0, "high": 0, "medium": 0,
                        "low": 0, "info": 0},
            "findings": [],
        }

    monkeypatch.setattr(de, "fetch_wayback_urls", _fake_wayback)
    monkeypatch.setattr(de, "discover_subdomains", _fake_dns)
    monkeypatch.setattr(de.WebsiteEngine, "run", _fake_website_run)

    engine = DomainEngine("dom-3", None, "/tmp", _Settings())
    report = asyncio.run(engine.run(domain="example.com", max_hosts=10))

    assert calls["n"] == 3  # example.com + www + broken all attempted
    statuses = {h["host"]: h["status"] for h in report["hosts"]}
    assert statuses.get("broken.example.com") == "failed"
    assert report["summary"]["hosts_completed"] == 2


def test_domain_scan_request_validation() -> None:
    from app.core.models import DomainScanRequest

    with pytest.raises(ValueError):
        DomainScanRequest(mode="domain", domain="https://evil/path")

    r = DomainScanRequest(mode="domain", domain="Example.com",
                          i_have_permission=True)
    assert r.domain == "example.com"
