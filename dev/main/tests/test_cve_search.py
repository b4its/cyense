"""Tests for live CVE search (app/utils/cve_search.py).

Uses a mocked httpx transport — no real network in tests.
"""

from __future__ import annotations

import httpx

from app.utils.cve_search import merge_cves, search_cves_online


def _nvd_response(cves: list[dict]) -> dict:
    return {
        "resultsPerPage": len(cves),
        "totalResults": len(cves),
        "vulnerabilities": [
            {"cve": cve} for cve in cves
        ],
    }


def _nvd_cve(cve_id: str, score: float, sev: str, desc: str) -> dict:
    return {
        "id": cve_id,
        "descriptions": [{"lang": "en", "value": desc}],
        "metrics": {
            "cvssMetricV31": [{
                "cvssData": {
                    "baseScore": score,
                    "baseSeverity": sev,
                },
            }],
        },
        "references": [{"url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"}],
    }


def _mock_transport(nvd_cves: list[dict]):
    def handler(request: httpx.Request) -> httpx.Response:
        if "nvd.nist.gov" in str(request.url):
            return httpx.Response(200, json=_nvd_response(nvd_cves))
        return httpx.Response(404)

    return httpx.MockTransport(handler)


def _patch_client(monkeypatch, nvd_cves: list[dict]):
    original_init = httpx.AsyncClient.__init__

    def patched_init(self, *args, **kwargs):
        kwargs["transport"] = _mock_transport(nvd_cves)
        original_init(self, *args, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "__init__", patched_init)


def test_search_cves_online_returns_nvd_results(monkeypatch) -> None:
    import asyncio

    nvd_cves = [
        _nvd_cve("CVE-2024-6387", 9.8, "CRITICAL", "OpenSSH regreSSHion RCE"),
        _nvd_cve("CVE-2021-23017", 7.5, "HIGH", "nginx resolver off-by-one"),
    ]
    _patch_client(monkeypatch, nvd_cves)

    techs = [{"evidence": {"category": "server:nginx", "version": "1.18.0"}}]
    ports = [{"port": 22, "service": "ssh", "version": "9.6p1"}]

    results = asyncio.run(search_cves_online(techs, ports))
    ids = {c["cve"] for c in results}
    assert "CVE-2024-6387" in ids
    assert "CVE-2021-23017" in ids
    # severity + cvss parsed from NVD
    reg = next(c for c in results if c["cve"] == "CVE-2024-6387")
    assert reg["severity"] == "critical"
    assert reg["cvss_score"] == 9.8
    assert reg["source"] == "nvd"
    # sorted by cvss desc
    scores = [c.get("cvss_score") for c in results]
    assert scores == sorted(scores, reverse=True)


def test_search_cves_online_empty_input(monkeypatch) -> None:
    import asyncio

    _patch_client(monkeypatch, [])
    results = asyncio.run(search_cves_online([], []))
    assert results == []


def test_search_cves_online_handles_api_error(monkeypatch) -> None:
    """Network/API failure must return [] (graceful offline fallback)."""
    import asyncio

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="rate limited")

    original_init = httpx.AsyncClient.__init__

    def patched_init(self, *args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        original_init(self, *args, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "__init__", patched_init)

    techs = [{"evidence": {"category": "server:nginx"}}]
    results = asyncio.run(search_cves_online(techs, []))
    assert results == []


def test_search_cves_online_filters_placeholder_cve(monkeypatch) -> None:
    import asyncio

    nvd_cves = [_nvd_cve("CVE-1999-0661", 10.0, "CRITICAL", "placeholder")]
    _patch_client(monkeypatch, nvd_cves)
    techs = [{"evidence": {"category": "server:nginx"}}]
    results = asyncio.run(search_cves_online(techs, []))
    assert "CVE-1999-0661" not in {c["cve"] for c in results}


def test_merge_cves_local_precedence() -> None:
    local = [{"cve": "CVE-2021-23017", "source": "local", "severity": "high"}]
    online = [
        {"cve": "CVE-2021-23017", "source": "nvd", "severity": "high"},
        {"cve": "CVE-2020-11023", "source": "nvd", "severity": "high"},
    ]
    merged = merge_cves(local, online)
    ids = [c["cve"] for c in merged]
    assert ids == ["CVE-2021-23017", "CVE-2020-11023"]
    # local entry wins on id conflict
    first = next(c for c in merged if c["cve"] == "CVE-2021-23017")
    assert first["source"] == "local"
