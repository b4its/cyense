"""Tests for the read-only CTF flag-hunt engine (app/engines/flag_hunt.py).

Covers: marker regex matching (body + header), page scanning, same-origin
probe-URL construction, live GET probing against a local HTTP server, and
the combined run_flag_hunt stage. Every probe is GET-only on the scanned
origin (ground rule #6).
"""

from __future__ import annotations

import http.server
import threading

from app.engines.flag_hunt import (
    COMMON_FLAG_PATHS,
    find_flags,
    flag_probe_urls,
    probe_flag_paths,
    run_flag_hunt,
    scan_pages_for_flags,
)

# ---------------------------------------------------------------------------
# pure helpers
# ---------------------------------------------------------------------------

def test_find_flags_matches_ctf_and_flag_forms() -> None:
    body = (
        "<html>congrats CTF{alpha_beta-123} "  # CTF{...}
        "also flag{abc} and picoCTF{z9x8}"
        "</html>"
    )
    hits = find_flags(body)
    assert len(hits) >= 2, hits
    joined = " ".join(h["marker"] for h in hits)
    assert "CTF{alpha_beta-123}" in joined
    assert "flag{abc}" in joined

def test_find_flags_ignores_noise() -> None:
    assert find_flags("<html>nothing here</html>") == []
    assert find_flags("") == []

def test_find_flags_caps_output() -> None:
    body = "flag{1} " + "flag{2} " * 40  # > 8 hits
    assert len(find_flags(body)) <= 8


# ---------------------------------------------------------------------------
# page scanning (pure — bodies the crawler already fetched)
# ---------------------------------------------------------------------------

def _page(url: str, body: str, headers: dict | None = None) -> dict:
    return {"url": url, "body": body, "headers": headers or {}}

def test_scan_pages_reports_flag_marker_finding() -> None:
    findings = scan_pages_for_flags([_page("http://app/page", "flag{s3cret}")])
    assert len(findings) == 1
    f = findings[0]
    assert f["rule"] == "FLAG-PAGE"
    assert f["severity"] == "info"
    assert f["location"] == "http://app/page"
    assert f["evidence"]["marker"] == "flag{s3cret}"

def test_scan_pages_ignores_clean_pages() -> None:
    findings = scan_pages_for_flags([
        _page("http://app/", "<html>ok</html>"),
        _page("http://app/x", "no marker"),
    ])
    assert findings == []

def test_scan_pages_detects_flag_header() -> None:
    findings = scan_pages_for_flags([_page("http://app/", "<html/>",
                                           {"x-flag": "picoCTF{hdr}"})])
    assert findings and findings[0]["rule"] == "FLAG-PAGE"

def test_scan_pages_empty_or_none() -> None:
    assert scan_pages_for_flags([]) == []
    assert scan_pages_for_flags(None) == []


# ---------------------------------------------------------------------------
# probe URL construction (same-origin)
# ---------------------------------------------------------------------------

def test_flag_probe_urls_same_origin() -> None:
    urls = flag_probe_urls("https://ctf.example.com:8443/path/index")
    assert len(urls) == len(COMMON_FLAG_PATHS)
    for u in urls:
        assert u.startswith("https://ctf.example.com:8443/")
    assert "https://ctf.example.com:8443/flag.txt" in urls

def test_flag_probe_urls_invalid_base() -> None:
    assert flag_probe_urls("not a url") == []


# ---------------------------------------------------------------------------
# live GET probing against a local HTTP server (read-only, same-origin)
# ---------------------------------------------------------------------------

class _FlagHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 — BaseHTTPRequestHandler API
        if self.path == "/flag.txt":
            body = b"CTF{local-flag-live}\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/robots.txt":
            body = b"User-agent: *\nDisallow: /flag.txt\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args: object) -> None:  # silence test output
        pass


def _serve_flag_app() -> tuple[http.server.ThreadingHTTPServer, str]:
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _FlagHandler)
    base = f"http://127.0.0.1:{server.server_port}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, base


async def test_probe_flag_paths_live() -> None:
    server, base = _serve_flag_app()
    try:
        findings = await probe_flag_paths(base, rate_limit=1000)
        hit = [f for f in findings if f["rule"] == "FLAG-PATH"]
        assert hit, "expected FLAG-PATH for /flag.txt on the local server"
        assert hit[0]["evidence"]["marker"] == "CTF{local-flag-live}"
        # 404 paths produce nothing beyond the two 200 flag/robots candidates;
        # robots carries no marker and its path lacks "flag" → not reported.
        assert all("404" not in f["location"] for f in findings)
    finally:
        server.shutdown()
        server.server_close()


async def test_run_flag_hunt_combines_pages_and_paths() -> None:
    server, base = _serve_flag_app()
    try:
        pages = [_page(f"{base}/", "landing flag{landing}")]
        findings = await run_flag_hunt(base, pages, rate_limit=1000)
        rules = {f["rule"] for f in findings}
        assert "FLAG-PAGE" in rules  # marker in crawled page body
        assert "FLAG-PATH" in rules  # /flag.txt reachable
    finally:
        server.shutdown()
        server.server_close()


async def test_probe_only_reports_reachable_flag_paths() -> None:
    # Only 200 responses whose body carries a marker (or whose path is a
    # known flag file) are reported; plain 404 paths produce nothing.
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _FlagHandler)
    base = f"http://127.0.0.1:{server.server_port}"
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        findings = await probe_flag_paths(base, rate_limit=1000)
        assert findings, "expected at least /flag.txt hit"
        for f in findings:
            assert f["rule"] == "FLAG-PATH"
            assert f["evidence"]["url"].endswith(("/flag.txt", "/robots.txt", "/flag"))
    finally:
        server.shutdown()
        server.server_close()


# ---------------------------------------------------------------------------
# integration: WebsiteEngine wires the flag stage only when flag_hunt=True
# ---------------------------------------------------------------------------

class _WiringSettings:
    port_scan_timeout = 1.0
    port_scan_concurrency = 5
    request_timeout = 5
    cve_online = False


async def test_website_engine_wires_flag_hunt(monkeypatch, tmp_path) -> None:
    """WebsiteEngine.run(..., flag_hunt=True) runs the flag stage and merges
    its findings; flag_hunt=False keeps the classic pipeline unchanged.
    Network-heavy sub-stages (CVE/discovery/OWASP) are stubbed so the test
    only touches the local server + the flag stage."""
    server, base = _serve_flag_app()
    try:
        from app.engines.website_engine import WebsiteEngine

        async def _no_cve(*a, **k):
            return [], False, False

        async def _empty(*a, **k):
            return []

        monkeypatch.setattr(WebsiteEngine, "_cve_lookup_stage", _no_cve)
        monkeypatch.setattr(WebsiteEngine, "_discovery_stage", _empty)
        monkeypatch.setattr(WebsiteEngine, "_owasp_stage", _empty)

        engine = WebsiteEngine(
            scan_id="wiring-flag-1", brain=None,
            reports_dir=str(tmp_path), settings=_WiringSettings(),
        )
        rep = await engine.run(
            url=base, max_depth=1, max_pages=5, rate_limit=1000,
            skip_port_scan=True, flag_hunt=True,
        )
        rules = {f["rule"] for f in rep["findings"]}
        assert "FLAG-PAGE" in rules or "FLAG-PATH" in rules
        assert rep["summary"].get("flags_found", 0) >= 1
        assert "flag" in rep["meta"]["pipeline"]

        rep_off = await engine.run(
            url=base, max_depth=1, max_pages=5, rate_limit=1000,
            skip_port_scan=True, flag_hunt=False,
        )
        assert not any(f["rule"].startswith("FLAG") for f in rep_off["findings"])
        assert "flag" not in rep_off["meta"]["pipeline"]
    finally:
        server.shutdown()
        server.server_close()
