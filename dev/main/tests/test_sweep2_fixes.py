"""Regression tests for the latest sweep fixes.

Covers:
  * worker resume overlay preserves checkpoint params (level/scan_mode/lang)
  * live_webapp header lookup is case-insensitive (crawler lowercases keys)
  * owasp_live session-entropy only flags session-like cookies
  * live_owasp SameSite=None+Secure order-independent
  * osint _vcard_country survives malformed vcardArray
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# worker resume overlay
# ---------------------------------------------------------------------------

def test_resume_overlay_preserves_checkpoint_params() -> None:
    """A fresh resume request with only mode/i_have_permission/resume_from must
    NOT overwrite the checkpoint's level/scan_mode/lang with model defaults."""
    from app.core.models_github import GithubScanRequest

    fresh = GithubScanRequest(mode="github", i_have_permission=True, resume_from="abc")
    explicit = fresh.model_dump(mode="json", exclude_defaults=True)

    checkpoint = {
        "repo_url": "https://github.com/acme/x",
        "level": "max",
        "lang": "python",
        "scan_mode": "deep",
        "mode": "github",
    }
    merged = dict(checkpoint)
    for k, v in explicit.items():
        if v is not None:
            merged[k] = v

    assert merged["level"] == "max"
    assert merged["lang"] == "python"
    assert merged["scan_mode"] == "deep"
    assert merged["repo_url"] == "https://github.com/acme/x"
    assert merged["resume_from"] == "abc"


# ---------------------------------------------------------------------------
# live_webapp header lookup
# ---------------------------------------------------------------------------

def test_live_webapp_header_lookup_case_insensitive() -> None:
    """Crawler stores headers lowercase; passive checks must still find them."""
    from app.engines import live_webapp as lw

    # A page with X-Frame-Options DENY + CSP frame-ancestors + no-store should
    # NOT produce frame-injection or cache findings.
    page = {
        "headers": {
            "x-frame-options": "DENY",
            "cache-control": "no-store, no-cache",
            "pragma": "no-cache",
            "content-security-policy": "frame-ancestors 'self'",
            "set-cookie": "sessionid=abc; Max-Age=3600; Secure; HttpOnly",
        },
        "body": "<html><body>hi</body></html>",
        "url": "http://x/",
        "status": 200,
        "content_type": "text/html",
    }
    res = lw.analyze_webapp(page)
    rules = {f["rule"] for f in res}
    assert "OWASP-CONF-008" not in rules  # frame injection not fired
    assert "OWASP-SENSITIVE-004" not in rules  # cache not fired (no password form anyway)
    assert "OWASP-AUTH-006" not in rules  # session cookie has Max-Age


def test_live_webapp_session_timeout_lowercase_set_cookie() -> None:
    """Set-Cookie stored lowercase, string (not list) — checks must parse it."""
    from app.engines import live_webapp as lw

    page = {
        "headers": {"set-cookie": "sessionid=abc; Path=/"},
        "body": "<html></html>",
        "url": "http://x/",
        "status": 200,
        "content_type": "text/html",
    }
    res = lw.analyze_webapp(page)
    assert any(f["rule"] == "OWASP-AUTH-006" for f in res)


# ---------------------------------------------------------------------------
# owasp_live session entropy
# ---------------------------------------------------------------------------

def test_session_entropy_ignores_benign_cookies() -> None:
    from app.utils.owasp_live import check_session_id_entropy

    benign = {
        "Set-Cookie": "lang=en; Path=/, theme=dark; Path=/",
    }
    assert check_session_id_entropy(benign, "https://x/") == []


def test_session_entropy_flags_session_like_short_cookie() -> None:
    from app.utils.owasp_live import check_session_id_entropy

    f = check_session_id_entropy(
        {"Set-Cookie": "PHPSESSID=ab12cd34ef56; path=/"}, "https://x/",
    )
    assert any(x["rule"] == "OWASP-SESSION-ENTROPY" for x in f)


# ---------------------------------------------------------------------------
# live_owasp SameSite=None + Secure order independence
# ---------------------------------------------------------------------------

def test_samesite_none_secure_order_independent() -> None:
    from app.engines import live_owasp as lo

    # Secure BEFORE SameSite=None is correctly configured → the combined
    # OWASP-CSRF-004 condition (SameSite=None present AND Secure absent) must
    # NOT be satisfied.
    samesite_present = lo._SAMESITE_NONE_RE.search("a=1; Secure; SameSite=None") is not None
    secure_present = lo._SECURE_RE.search("a=1; Secure; SameSite=None") is not None
    assert samesite_present and secure_present
    assert not (samesite_present and not secure_present)

    # SameSite=None WITHOUT Secure → insecure condition is satisfied.
    s2 = lo._SAMESITE_NONE_RE.search("a=1; SameSite=None") is not None
    secure2 = lo._SECURE_RE.search("a=1; SameSite=None") is not None
    assert s2 and not secure2


# ---------------------------------------------------------------------------
# osint _vcard_country malformed input
# ---------------------------------------------------------------------------

def test_vcard_country_malformed_no_crash() -> None:
    from app.utils.osint import _vcard_country

    assert _vcard_country([{"vcardArray": [["vcard"]]}]) is None
    assert _vcard_country([{"vcardArray": "bad"}]) is None
    assert _vcard_country([{
        "vcardArray": [["vcard"], [["adr", {}, "text", ["", "", "", "US"]]]],
    }]) == "US"


# ---------------------------------------------------------------------------
# unreachable-target handling (link + website) — page must fail loudly
# ---------------------------------------------------------------------------

def test_link_prober_fails_fast_when_target_unreachable() -> None:
    """All probes returning status 0 (connection refused) must surface as a
    scan FAILURE (ok=False) instead of a silent 0-finding completion — this
    was why the web page showed an unexplained 'Tidak ada temuan'."""
    import asyncio

    from app.agents.prober import ProberAgent
    from app.agents.recon import TargetProfile

    class _Err:
        status = 0
        headers: dict[str, str] = {}
        body = ""
        elapsed_ms = 1
        url = ""

        @property
        def blocked(self) -> bool:
            return False

    class _StubClient:
        def __init__(self, **_kwargs) -> None:
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_exc) -> None:
            return None

        async def get(self, url: str):
            r = _Err()
            r.url = url
            return r

        async def request(self, method: str, url: str):
            return await self.get(url)

    import app.agents.prober as p

    orig_run = p.ProberAgent.run
    orig_client = p.HttpClient

    async def patched_run(self, ctx):
        p.HttpClient = _StubClient  # type: ignore[misc]
        try:
            return await orig_run(self, ctx)
        finally:
            p.HttpClient = orig_client

    p.ProberAgent.run = patched_run  # type: ignore[method-assign]

    try:
        prober = ProberAgent("t", "/tmp")
        profile = TargetProfile(
            url_template="http://10.255.255.1/invoice/{ID}",
            host="10.255.255.1",
            placeholders=["id"],
        )
        ctx = {
            "profile": profile.to_dict(),
            "baseline_body": "",
            "baseline_id": None,
            "probe_ids": None,
            "probe_max": 3,
            "method": "GET",
            "timeout": 1,
            "rate_limit": 50,
            "max_concurrency": 5,
        }
        res = asyncio.run(prober(ctx))
        assert res.ok is False
        assert "tidak terjangkau" in (res.error or "").lower()
    finally:
        p.ProberAgent.run = orig_run  # type: ignore[method-assign]
        p.HttpClient = orig_client


def test_crawler_counters_ok_responses() -> None:
    """Crawler must report how many HTTP responses it actually received so the
    website engine can distinguish 'target unreachable' (0 responses) from a
    legitimately empty scan."""
    # No network in tests: with a bad host the crawler gets 0 responses and
    # must still return ok=True but expose ok_responses == 0.
    import asyncio

    from app.agents.crawler import CrawlerAgent

    async def _run():
        crawler = CrawlerAgent("t", "/tmp")
        ctx = {
            "url": "http://127.0.0.1:1/nope",
            "max_depth": 0,
            "max_pages": 2,
            "rate_limit": 50,
            "headers": {},
            "cookies": {},
        }
        return await crawler(ctx)

    res = asyncio.run(_run())
    assert res.ok is True
    assert res.data.get("ok_responses", 0) == 0
    assert res.data.get("pages", []) == []


# ---------------------------------------------------------------------------
# realtime step-by-step events (web UI live feed)
# ---------------------------------------------------------------------------

async def _make_running_job(store) -> str:
    """Create a scan job in a terminal state and return its scan_id."""
    from app.core.models import LinkScanRequest

    req = LinkScanRequest(
        mode="link",
        url="http://lab/invoice/{ID}",
        i_have_permission=True,
    )
    job = store.create(req)
    return job.scan_id


def test_store_records_realtime_stage_events(tmp_path) -> None:
    """mark_stage/mark_completed must append step-by-step events so the web UI
    can render a LIVE feed — previously the stage history was never recorded
    and the page showed nothing while the scan ran."""
    import asyncio

    from app.core.store import JobStore

    store = JobStore(tmp_path / "reports")
    scan_id = asyncio.run(_make_running_job(store))

    # Simulate a website scan walking through stages as the worker would.
    asyncio.run(store.mark_running(scan_id, stage="recon"))
    for stage, prog in (("crawl", 8), ("analyze", 18), ("cve", 30),
                        ("discovery", 36), ("report", 90)):
        asyncio.run(store.mark_stage(scan_id, stage, prog))
    asyncio.run(store.mark_completed(scan_id))

    events = store.events(scan_id)
    assert events, "expected step-by-step events after stage transitions"
    joined = "\n".join(events)
    assert "stage: recon → crawl" in joined
    assert "stage: crawl → analyze" in joined
    assert "stage: discovery → report" in joined
    assert "status: completed" in joined
    # The progress is monotonic (max kept) — final snapshot reports 100%.
    assert "100%" in joined


def test_store_records_failed_event(tmp_path) -> None:
    """mark_failed must append an event carrying the error message."""
    import asyncio

    from app.core.store import JobStore

    store = JobStore(tmp_path / "reports")
    scan_id = asyncio.run(_make_running_job(store))
    asyncio.run(store.mark_running(scan_id, stage="recon"))
    asyncio.run(store.mark_failed(scan_id, "target tidak terjangkau"))

    events = store.events(scan_id)
    assert any("failed" in e and "tidak terjangkau" in e for e in events)
