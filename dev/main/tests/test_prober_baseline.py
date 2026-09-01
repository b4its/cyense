"""Regression tests for ProberAgent / VerifierAgent rendering + candidates.

Bugs fixed:
1. ProberAgent ignored ``ctx['baseline_id']`` — auto-mode candidates were
   always generated around the hardcoded default "1" instead of the
   caller's own object id.
2. ``_render`` used the probe id directly as the re.sub replacement string,
   so an id containing a backslash (e.g. ``\\1``) raised
   ``re.error: invalid group reference``.
"""

from __future__ import annotations

import asyncio

from app.agents.prober import ProberAgent
from app.agents.recon import TargetProfile


def _profile() -> TargetProfile:
    return TargetProfile(
        url_template="http://x.test/invoice/{ID}",
        host="x.test",
        placeholders=["id"],
    )


def test_candidates_center_on_caller_baseline_id() -> None:
    prober = ProberAgent("t", "/tmp")
    profile = _profile()
    candidates = prober._candidates(
        None, [], profile, probe_max=3, baseline_id="42"
    )
    assert "43" in candidates and "41" in candidates, (
        "auto candidates must be neighbours of the caller's baseline_id"
    )
    assert "2" not in candidates, "must NOT probe around the old default '1'"


def test_candidates_default_hint_stays_numeric_one() -> None:
    prober = ProberAgent("t", "/tmp")
    profile = _profile()
    candidates = prober._candidates(None, [], profile, probe_max=3)
    assert "2" in candidates and "0" in candidates


def test_render_treats_probe_id_as_literal() -> None:
    prober = ProberAgent("t", "/tmp")
    profile = _profile()
    # A backslash in the replacement string used to raise re.error.
    out = prober._render(profile, r"\1evil")
    assert out == r"http://x.test/invoice/\1evil"

    out2 = prober._render(profile, "43")
    assert out2 == "http://x.test/invoice/43"


def test_verifier_render_treats_value_as_literal() -> None:
    from app.agents.verifier import VerifierAgent

    profile = _profile()
    out = VerifierAgent._render(profile, r"\g<id>")
    assert out == r"http://x.test/invoice/\g<id>"


def test_run_uses_baseline_id_from_ctx(monkeypatch) -> None:
    """Full prober.run() must probe around ctx['baseline_id'] ('42')."""
    requested_urls: list[str] = []

    class _Resp:
        status = 200
        headers: dict[str, str] = {}
        body = '{"invoice": 1}'
        elapsed_ms = 1
        url = ""

        @property
        def blocked(self) -> bool:
            return False

    class _StubClient:
        def __init__(self, **_kwargs) -> None:
            pass

        async def __aenter__(self) -> "_StubClient":
            return self

        async def __aexit__(self, *_exc) -> None:
            pass

        async def request(self, method: str, url: str) -> _Resp:
            requested_urls.append(url)
            resp = _Resp()
            resp.url = url
            return resp

        async def get(self, url: str) -> _Resp:
            return await self.request("GET", url)

    monkeypatch.setattr("app.agents.prober.HttpClient", _StubClient)

    prober = ProberAgent("t", "/tmp")
    result = asyncio.run(
        prober(
            {
                "profile": _profile().to_dict(),
                "baseline_body": '{"invoice": 1}',
                "baseline_id": "42",
                "probe_ids": None,
                "probe_max": 3,
                "method": "GET",
            }
        )
    )
    assert result.ok
    assert any(u.endswith("/invoice/43") for u in requested_urls), requested_urls
    assert any(u.endswith("/invoice/41") for u in requested_urls), requested_urls
    assert not any(u.endswith("/invoice/2") for u in requested_urls), (
        "prober must not probe around the default '1' when baseline_id is given"
    )
