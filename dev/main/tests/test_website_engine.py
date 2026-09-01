"""Regression tests for WebsiteEngine active IDOR probing.

Bug: ``_probe_id_endpoints`` built the probe URL with
``template.replace("{ID}", baseline)`` — the placeholder was gone before
ReconAgent ever saw it, so recon always failed with "no {ID}-style
placeholder found" and active probing NEVER ran for website scans.
"""

from __future__ import annotations

import asyncio


class _Settings:
    request_timeout = 5.0
    rate_limit = 100
    max_concurrency = 5
    probe_max = 5
    similarity_threshold = 0.85
    verify_retries = 1
    control_id = "99999999"


def test_probe_id_endpoints_keeps_placeholder_and_passes_baseline(monkeypatch) -> None:
    """Recon must receive the {ID} template + the observed id as baseline_id."""
    from app.agents.base import AgentResult
    from app.engines.website_engine import WebsiteEngine

    captured: dict[str, dict] = {}

    class _Recon:
        def __init__(self, *a, **k):
            pass

        async def __call__(self, ctx):
            captured["recon_ctx"] = dict(ctx)
            return AgentResult(
                agent="recon",
                ok=True,
                data={
                    "profile": {
                        "url_template": ctx["url"],
                        "host": "x.test",
                        "placeholders": ["id"],
                    },
                    "baseline_body": "<html>baseline</html>",
                },
            )

    class _Prober:
        def __init__(self, *a, **k):
            pass

        async def __call__(self, ctx):
            captured["probe_ctx"] = dict(ctx)
            return AgentResult(agent="prober", ok=True, data={"hits_internal": []})

    class _Verifier:
        def __init__(self, *a, **k):
            pass

        async def __call__(self, ctx):
            captured["verify_ctx"] = dict(ctx)
            return AgentResult(agent="verifier", ok=True, data={"findings": [], "rejected": []})

    monkeypatch.setattr("app.agents.recon.ReconAgent", _Recon)
    monkeypatch.setattr("app.agents.prober.ProberAgent", _Prober)
    monkeypatch.setattr("app.agents.verifier.VerifierAgent", _Verifier)

    engine = WebsiteEngine("t", brain=None, reports_dir="/tmp", settings=_Settings())
    endpoints = [
        {
            "url": "http://x.test/invoice/5",
            "template": "http://x.test/invoice/{ID}",
            "id_segments": ["5"],
            "query_ids": {},
        }
    ]

    confirmed = asyncio.run(
        engine._probe_id_endpoints(endpoints, headers={}, cookies={})
    )
    assert confirmed == []

    recon_ctx = captured["recon_ctx"]
    # The placeholder must survive so recon/prober can substitute candidates.
    assert "{ID}" in recon_ctx["url"], (
        "placeholder was stripped — recon would reject the URL and probing "
        "would never run (the pre-fix bug)"
    )
    # The crawler-observed id must be passed as the baseline.
    assert recon_ctx.get("baseline_id") == "5"
    assert captured["probe_ctx"]["url"] == recon_ctx["url"]
    assert captured["verify_ctx"]["hits_internal"] == []


def test_probe_id_endpoints_confirms_hits(monkeypatch) -> None:
    """A verifier finding is converted into an IDOR-WEBSITE-HIT dict."""
    from app.agents.base import AgentResult
    from app.engines.website_engine import WebsiteEngine

    class _Recon:
        def __init__(self, *a, **k):
            pass

        async def __call__(self, ctx):
            return AgentResult(
                agent="recon",
                ok=True,
                data={
                    "profile": {"url_template": ctx["url"], "host": "x.test",
                                "placeholders": ["id"]},
                    "baseline_body": "",
                },
            )

    class _Prober:
        def __init__(self, *a, **k):
            pass

        async def __call__(self, ctx):
            return AgentResult(
                agent="prober",
                ok=True,
                data={"hits_internal": [{"probe_id": "6"}]},
            )

    class _Verifier:
        def __init__(self, *a, **k):
            pass

        async def __call__(self, ctx):
            return AgentResult(
                agent="verifier",
                ok=True,
                data={
                    "findings": [
                        {
                            "probe_id": "6",
                            "url": "http://x.test/invoice/6",
                            "status": 200,
                            "severity": "critical",
                            "confidence": 0.95,
                            "body_snippet": '{"email": "a@b.c"}',
                            "verification": {"pii_matches": ["a@b.c"]},
                        }
                    ],
                    "rejected": [],
                },
            )

    monkeypatch.setattr("app.agents.recon.ReconAgent", _Recon)
    monkeypatch.setattr("app.agents.prober.ProberAgent", _Prober)
    monkeypatch.setattr("app.agents.verifier.VerifierAgent", _Verifier)

    engine = WebsiteEngine("t", brain=None, reports_dir="/tmp", settings=_Settings())
    endpoints = [
        {
            "url": "http://x.test/invoice/5",
            "template": "http://x.test/invoice/{ID}",
            "id_segments": ["5"],
            "query_ids": {},
        }
    ]

    confirmed = asyncio.run(
        engine._probe_id_endpoints(endpoints, headers={}, cookies={})
    )
    assert len(confirmed) == 1
    assert confirmed[0]["severity"] == "critical"
    assert "6" in confirmed[0]["title"]
