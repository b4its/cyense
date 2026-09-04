"""Tests for OWASP Top 10 posture in link mode.

Covers the shared ``run_owasp_posture`` orchestrator (passive + active
aggregation, best-effort active probing) and the link orchestrator's
``_link_owasp_posture`` which fetches the target page and converts the dict
findings into ``Finding`` models.
"""

from __future__ import annotations

import pytest

from app.core.models import Finding, Severity


def _page(
    *,
    url: str = "http://app/",
    status: int = 200,
    body: str = "<html><body>ok</body></html>",
    content_type: str = "text/html; charset=utf-8",
    headers: dict[str, str] | None = None,
) -> dict:
    return {
        "url": url,
        "status": status,
        "body": body,
        "content_type": content_type,
        "headers": headers or {},
    }


# ---------------------------------------------------------------------------
# run_owasp_posture — passive + active aggregation, best-effort active
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_run_owasp_posture_runs_passive_and_active(monkeypatch) -> None:
    from app.engines import live_owasp as m

    class _FakeClient:
        async def __aenter__(self) -> _FakeClient:
            return self

        async def __aexit__(self, *exc: object) -> bool:
            return False

    monkeypatch.setattr(m, "HttpClient", lambda **_: _FakeClient())

    async def ep(client, origin):
        return [{"rule": "OWASP-CONF-003", "severity": "medium"}]

    async def hm(client, origin):
        return [{"rule": "OWASP-CONF-005", "severity": "medium"}]

    async def auth(client, origin):
        return []

    async def dt(client, origin):
        return [{"rule": "OWASP-CONF-009", "severity": "high"}]

    async def tls(origin):
        return [{"rule": "OWASP-SENSITIVE-005", "severity": "high"}]

    monkeypatch.setattr(m, "probe_owasp_endpoints", ep)
    monkeypatch.setattr(m, "probe_http_methods", hm)
    monkeypatch.setattr(m, "probe_auth_surfaces", auth)
    monkeypatch.setattr(m, "probe_webapp_directory_traversal", dt)
    monkeypatch.setattr(m, "probe_webapp_tls", tls)

    findings = await m.run_owasp_posture(
        [_page(url="http://app/")],
        origin="http://app",
        headers={},
        cookies={},
    )
    rules = {f["rule"] for f in findings}
    # passive (plaintext http) + active probes
    assert "OWASP-SENSITIVE-001" in rules
    assert "OWASP-CONF-003" in rules
    assert "OWASP-CONF-005" in rules
    assert "OWASP-CONF-009" in rules
    assert "OWASP-SENSITIVE-005" in rules


@pytest.mark.asyncio
async def test_run_owasp_posture_swallows_active_exception(monkeypatch) -> None:
    from app.engines import live_owasp as m

    class _FakeClient:
        async def __aenter__(self) -> _FakeClient:
            return self

        async def __aexit__(self, *exc: object) -> bool:
            return False

    monkeypatch.setattr(m, "HttpClient", lambda **_: _FakeClient())

    async def boom(client, origin):
        raise RuntimeError("probe exploded")

    monkeypatch.setattr(m, "probe_owasp_endpoints", boom)
    monkeypatch.setattr(m, "probe_http_methods", boom)
    monkeypatch.setattr(m, "probe_auth_surfaces", boom)
    monkeypatch.setattr(m, "probe_webapp_directory_traversal", boom)
    monkeypatch.setattr(m, "probe_webapp_tls", boom)

    findings = await m.run_owasp_posture(
        [_page(url="http://app/")],
        origin="http://app",
        headers={},
        cookies={},
    )
    # passive still ran; active failure did not raise
    assert "OWASP-SENSITIVE-001" in {f["rule"] for f in findings}


# ---------------------------------------------------------------------------
# _link_owasp_posture — fetch page, run posture, convert to Finding
# ---------------------------------------------------------------------------

class _Settings:
    request_timeout = 10.0
    rate_limit = 10
    max_concurrency = 3


async def _fake_run_owasp_posture(*_a, **_k):
    return [
        {
            "rule": "OWASP-CONF-007",
            "severity": "medium",
            "confidence": 0.5,
            "title": "Open Redirect / URL Redirection",
            "description": "redirect param present",
            "evidence": {"parameter": "redirect"},
            "remediation": "whitelist",
            "location": "http://app/?redirect=x",
        }
    ]


def _make_orchestrator() -> object:
    from app.agents.orchestrator import Orchestrator

    return Orchestrator("scan-1", brain=None, reports_dir="/tmp", settings=_Settings())


@pytest.mark.asyncio
async def test_link_owasp_posture_converts_to_finding(monkeypatch) -> None:
    from app.agents import orchestrator as omod

    orch = _make_orchestrator()
    monkeypatch.setattr(omod, "run_owasp_posture", _fake_run_owasp_posture)

    profile = {
        "url_template": "http://app/invoice/{ID}",
        "placeholders": ["id"],
    }
    findings = await orch._link_owasp_posture(profile, {}, {}, "1")
    assert len(findings) == 1
    f = findings[0]
    assert isinstance(f, Finding)
    assert f.finding_id == "scan-1-OW001"
    assert f.rule == "OWASP-CONF-007"
    assert f.severity == Severity.MEDIUM
    assert f.location == "http://app/?redirect=x"


@pytest.mark.asyncio
async def test_link_owasp_posture_skips_without_placeholder(monkeypatch) -> None:
    from app.agents import orchestrator as omod

    orch = _make_orchestrator()
    monkeypatch.setattr(omod, "run_owasp_posture", _fake_run_owasp_posture)
    findings = await orch._link_owasp_posture({"url_template": "http://app/"}, {}, {}, "1")
    assert findings == []


@pytest.mark.asyncio
async def test_link_owasp_posture_swallows_fetch_error(monkeypatch) -> None:
    from app.agents import orchestrator as omod

    class _Resp:
        url = "http://app/invoice/1"
        status = 200
        body = "<html>ok</html>"
        headers = {"content-type": "text/html"}

    class _Client:
        async def __aenter__(self) -> _Client:
            return self

        async def __aexit__(self, *exc: object) -> bool:
            return False

        async def get(self, url: str) -> _Resp:
            return _Resp()

    monkeypatch.setattr(omod.HttpClient, "__init__", lambda *a, **k: None)
    monkeypatch.setattr(omod.HttpClient, "__aenter__", lambda *a: _Client())
    monkeypatch.setattr(omod.HttpClient, "__aexit__", lambda *a, **k: False)
    monkeypatch.setattr(omod, "run_owasp_posture", lambda *a, **k: [])

    orch = _make_orchestrator()
    findings = await orch._link_owasp_posture(
        {"url_template": "http://app/invoice/{ID}", "placeholders": ["id"]},
        {}, {}, "1",
    )
    assert findings == []
