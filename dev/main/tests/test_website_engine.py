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


# ---------------------------------------------------------------------------
# Benign reflected-XSS probe (read-only, alphanumeric marker)
# ---------------------------------------------------------------------------

def test_reflection_probe_confirms_reflected_param(monkeypatch) -> None:
    """A param echoed back unencoded is flagged as XS-LIVE-017."""
    from app.engines.website_engine import WebsiteEngine
    from app.utils.http_client import HttpClient, Response

    captured: dict[str, str] = {}

    class _Client:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return None

        async def get(self, url: str) -> Response:
            captured["probe_url"] = url
            # Echo the whole query back raw (unencoded) — reflected sink.
            from urllib.parse import parse_qs, urlparse
            qs = parse_qs(urlparse(url).query)
            body = "<html><p>search results</p></html>"
            marker = [v for v in qs.values()][0][0]
            return Response(
                status=200,
                headers={"content-type": "text/html"},
                body=body.replace("</p>", f" {marker}</p>"),
                elapsed_ms=1,
                url=url,
            )

    monkeypatch.setattr(HttpClient, "__init__", _Client.__init__)
    monkeypatch.setattr(HttpClient, "__aenter__", _Client.__aenter__)
    monkeypatch.setattr(HttpClient, "__aexit__", _Client.__aexit__)
    monkeypatch.setattr(HttpClient, "get", _Client.get)

    engine = WebsiteEngine("t", brain=None, reports_dir="/tmp", settings=_Settings())
    pages = [
        {
            "url": "http://x.test/search?q=hello",
            "status": 200,
            "body": "<html><p>search results hello</p></html>",
            "content_type": "text/html",
            "headers": {"content-type": "text/html"},
        }
    ]
    findings = asyncio.run(engine._probe_reflected_xss(pages, headers={}, cookies={}))
    assert len(findings) == 1, findings
    assert findings[0]["rule"] == "XS-LIVE-017"
    assert findings[0]["confidence"] == 0.8
    assert "q" in findings[0]["evidence"]["param"]
    # The marker must be in the probe URL (probe actually fired).
    assert "Cyense" in captured["probe_url"]


def test_reflection_probe_ignores_encoded_reflection(monkeypatch) -> None:
    """HTML-encoded reflection must NOT be flagged."""
    from app.engines.website_engine import WebsiteEngine
    from app.utils.http_client import HttpClient, Response

    class _Client:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return None

        async def get(self, url: str) -> Response:
            # Echo back the marker HTML-encoded.
            import html as _html
            from urllib.parse import parse_qs, urlparse
            qs = parse_qs(urlparse(url).query)
            marker = [v for v in qs.values()][0][0]
            return Response(
                status=200,
                headers={"content-type": "text/html"},
                body=f"<html><p>{_html.escape(marker)}</p></html>",
                elapsed_ms=1,
                url=url,
            )

    monkeypatch.setattr(HttpClient, "__init__", _Client.__init__)
    monkeypatch.setattr(HttpClient, "__aenter__", _Client.__aenter__)
    monkeypatch.setattr(HttpClient, "__aexit__", _Client.__aexit__)
    monkeypatch.setattr(HttpClient, "get", _Client.get)

    engine = WebsiteEngine("t", brain=None, reports_dir="/tmp", settings=_Settings())
    pages = [
        {
            "url": "http://x.test/search?q=hello",
            "status": 200,
            "body": "<html><p>search</p></html>",
            "content_type": "text/html",
            "headers": {"content-type": "text/html"},
        }
    ]
    findings = asyncio.run(engine._probe_reflected_xss(pages, headers={}, cookies={}))
    assert findings == []


def test_reflection_probe_skips_non_2xx_and_no_query() -> None:
    """Non-2xx pages and pages without query params are never probed."""
    from app.engines.website_engine import WebsiteEngine

    engine = WebsiteEngine("t", brain=None, reports_dir="/tmp", settings=_Settings())
    pages = [
        {
            "url": "http://x.test/404?q=hi",  # non-2xx
            "status": 404,
            "body": "<html>not found</html>",
            "content_type": "text/html",
            "headers": {},
        },
        {
            "url": "http://x.test/about",  # no query
            "status": 200,
            "body": "<html>about</html>",
            "content_type": "text/html",
            "headers": {},
        },
    ]
    # No network should be touched for these pages (they are filtered before
    # any HTTP request). We just assert the result is empty & fast.
    findings = asyncio.run(engine._probe_reflected_xss(pages, headers={}, cookies={}))
    assert findings == []


# ---------------------------------------------------------------------------
# XSS payload injection probe (confirmed reflected XSS via real vectors)
# ---------------------------------------------------------------------------

def test_xss_payload_confirms_vulnerability(monkeypatch) -> None:
    """A param that reflects <img onerror> raw is flagged as XS-LIVE-032."""
    from app.engines.website_engine import WebsiteEngine
    from app.utils.http_client import HttpClient, Response

    captured: dict[str, str] = {}

    class _Client:
        def __init__(self, *a, **k):
            pass
        async def __aenter__(self):
            return self
        async def __aexit__(self, *exc):
            return None
        async def get(self, url: str) -> Response:
            captured["probe_url"] = url
            # Echo the payload raw (unencoded) — vulnerable!
            from urllib.parse import parse_qs, urlparse
            qs = parse_qs(urlparse(url).query)
            val = list(qs.values())[0][0]
            return Response(
                status=200,
                headers={"content-type": "text/html"},
                body=f"<html><p>Reflected: {val}</p></html>",
                elapsed_ms=1,
                url=url,
            )

    monkeypatch.setattr(HttpClient, "__init__", _Client.__init__)
    monkeypatch.setattr(HttpClient, "__aenter__", _Client.__aenter__)
    monkeypatch.setattr(HttpClient, "__aexit__", _Client.__aexit__)
    monkeypatch.setattr(HttpClient, "get", _Client.get)

    engine = WebsiteEngine("t", brain=None, reports_dir="/tmp", settings=_Settings())
    pages = [
        {
            "url": "http://x.test/search?q=hello",
            "status": 200,
            "body": "<html><p>search</p></html>",
            "content_type": "text/html",
            "headers": {"content-type": "text/html"},
        }
    ]
    findings = asyncio.run(engine._probe_xss_payloads(pages, headers={}, cookies={}))
    assert len(findings) >= 1, findings
    # At least the universal marker or an onerror payload should match
    payload_rules = {f["rule"] for f in findings}
    assert "XS-LIVE-032" in payload_rules, findings
    # The finding must include the working payload
    assert any("payload" in f.get("evidence", {}) for f in findings)


def test_xss_payload_encoded_reflection_not_flagged(monkeypatch) -> None:
    """HTML-encoded payload reflection must NOT be flagged."""
    from app.engines.website_engine import WebsiteEngine
    from app.utils.http_client import HttpClient, Response

    class _Client:
        def __init__(self, *a, **k):
            pass
        async def __aenter__(self):
            return self
        async def __aexit__(self, *exc):
            return None
        async def get(self, url: str) -> Response:
            import html as _html
            from urllib.parse import parse_qs, urlparse
            qs = parse_qs(urlparse(url).query)
            val = list(qs.values())[0][0]
            return Response(
                status=200,
                headers={"content-type": "text/html"},
                body=f"<html><p>{_html.escape(val)}</p></html>",
                elapsed_ms=1,
                url=url,
            )

    monkeypatch.setattr(HttpClient, "__init__", _Client.__init__)
    monkeypatch.setattr(HttpClient, "__aenter__", _Client.__aenter__)
    monkeypatch.setattr(HttpClient, "__aexit__", _Client.__aexit__)
    monkeypatch.setattr(HttpClient, "get", _Client.get)

    engine = WebsiteEngine("t", brain=None, reports_dir="/tmp", settings=_Settings())
    pages = [
        {
            "url": "http://x.test/search?q=hello",
            "status": 200,
            "body": "<html><p>search</p></html>",
            "content_type": "text/html",
            "headers": {"content-type": "text/html"},
        }
    ]
    findings = asyncio.run(engine._probe_xss_payloads(pages, headers={}, cookies={}))
    # Only the universal marker (no special chars) MIGHT slip through;
    # payloads with <>/' should NOT be detected.
    payload_findings = [f for f in findings
                        if f["evidence"].get("payload", "") != "/\"'<>CyenseXSS"]
    assert payload_findings == [], payload_findings


def test_xss_payload_skips_non_2xx_and_no_query() -> None:
    """Non-2xx and no-query pages never receive payload probes."""
    from app.engines.website_engine import WebsiteEngine

    engine = WebsiteEngine("t", brain=None, reports_dir="/tmp", settings=_Settings())
    pages = [
        {"url": "http://x.test/404?q=hi", "status": 404,
         "body": "not found", "content_type": "text/html", "headers": {}},
        {"url": "http://x.test/about", "status": 200,
         "body": "about", "content_type": "text/html", "headers": {}},
    ]
    findings = asyncio.run(engine._probe_xss_payloads(pages, headers={}, cookies={}))
    assert findings == []
