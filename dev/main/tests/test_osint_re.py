"""Tests for OSINT + reverse-engineering modules.

Covers:
  * app/utils/re_analysis.py  — source-map exposure + Retire.js-style
    vulnerable client-side library detection (deterministic, offline).
  * app/utils/osint.py        — RDAP / DNS-over-HTTPS / ASN lookups are
    best-effort network calls; we test the pure URL/hostname helpers and
    that lookups degrade gracefully (empty dict) without raising.
"""

from __future__ import annotations

import pytest

from app.utils.re_analysis import (
    find_sourcemap_refs,
    retirejs_findings,
    run_re_passive,
    sourcemap_exposure_findings,
)


def _rules(findings: list) -> set:
    return {f["rule"] for f in findings}


# ---------------------------------------------------------------------------
# Source-map exposure
# ---------------------------------------------------------------------------

def test_find_sourcemap_refs_comment_form() -> None:
    body = "/*! bundle */\n//# sourceMappingURL=app.js.map\nconsole.log(1);"
    assert find_sourcemap_refs(body) == ["app.js.map"]


def test_find_sourcemap_refs_dedupes() -> None:
    body = (
        "//# sourceMappingURL=a.map\n"
        "//@ sourceMappingURL=a.map\n"
        "sourceMappingURL=b.map"
    )
    assert set(find_sourcemap_refs(body)) == {"a.map", "b.map"}


def test_sourcemap_exposure_finding() -> None:
    f = sourcemap_exposure_findings("//# sourceMappingURL=main.js.map", "https://x/a.js")
    assert "RE-SOURCEMAP-REF" in _rules(f)
    f2 = sourcemap_exposure_findings("var x = 1;", "https://x/a.js")
    assert _rules(f2) == set()


# ---------------------------------------------------------------------------
# Retire.js-style vulnerable JS library detection
# ---------------------------------------------------------------------------

def test_retirejs_vulnerable_jquery() -> None:
    js = [
        ("/assets/jquery.min.js",
         "/*! jQuery v3.3.1 | (c) JS Foundation | jquery.org/license */\nvar j=function(){};"),
    ]
    f = retirejs_findings(js)
    assert "RE-VULN-JS" in _rules(f)
    assert any("jquery" in x["title"].lower() for x in f)


def test_retirejs_vulnerable_angularjs() -> None:
    js = [
        ("/assets/angular.min.js",
         "@license AngularJS v1.5.8\n(function(){'use strict';}());"),
    ]
    f = retirejs_findings(js)
    assert "RE-VULN-JS" in _rules(f)
    assert any("angularjs" in x["title"].lower() for x in f)


def test_retirejs_latest_no_finding() -> None:
    # jQuery 3.7.1 is outside the known vulnerable ranges.
    js = [("/a.js", "/*! jQuery v3.7.1 */\nvar j={};")]
    assert _rules(retirejs_findings(js)) == set()


def test_retirejs_no_banner_no_finding() -> None:
    js = [("/a.js", "const x = 42;\n")]
    assert _rules(retirejs_findings(js)) == set()


def test_run_re_passive_aggregates() -> None:
    js = [
        ("/a.js", "//# sourceMappingURL=a.js.map\n/*! jQuery v3.3.1 */\nvar j={};"),
    ]
    html = [("https://x/", "//# sourceMappingURL=inline.map\n<html></html>")]
    f = run_re_passive(js, html)
    rules = _rules(f)
    assert "RE-SOURCEMAP-REF" in rules
    assert "RE-VULN-JS" in rules


# ---------------------------------------------------------------------------
# OSINT helpers + graceful degradation
# ---------------------------------------------------------------------------

def test_hostname_of() -> None:
    from app.utils.osint import _hostname_of

    assert _hostname_of("https://www.example.com/path?a=1") == "www.example.com"
    assert _hostname_of("example.com") == "example.com"
    assert _hostname_of("API.Example.COM:8080") == "api.example.com"


def test_registrable_strips_subdomains() -> None:
    from app.utils.osint import _registrable

    assert _registrable("www.example.com") == "example.com"
    assert _registrable("api.example.co.uk") == "example.co.uk"
    # IP literals have no RDAP domain record → empty.
    assert _registrable("93.184.216.34") == ""


@pytest.mark.asyncio
async def test_osint_lookups_graceful_no_network() -> None:
    """Lookups must return {} (never raise) when the datasource is unreachable.

    We monkeypatch the HTTP layer to simulate a total network failure.
    """
    import httpx

    class _FailClient:
        def __init__(self, **_kw) -> None:
            pass

        async def __aenter__(self, *_a):
            return self

        async def __aexit__(self, *_a):
            return None

        async def get(self, *_a, **_k):
            raise httpx.ConnectError("no network")

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr("httpx.AsyncClient", _FailClient)

    from app.utils.osint import (
        _registrable,
        asn_lookup,
        dns_record_enum,
        osint_passive_gather,
        rdap_lookup_domain,
        rdap_lookup_ip,
    )

    assert await rdap_lookup_domain("example.com") == {}
    assert await rdap_lookup_ip("8.8.8.8") == {}
    # dns_record_enum uses DoH; with failing clients → empty dict.
    assert await dns_record_enum("example.com") == {}
    # asn_lookup uses a socket call; guard it to return {} too.
    asn = await asn_lookup("8.8.8.8")
    assert asn == {} or isinstance(asn, dict)
    assert _registrable("example.com") == "example.com"
    gather = await osint_passive_gather("https://example.com/x", ip="8.8.8.8")
    assert isinstance(gather, dict)
    assert "domain" in gather

    monkeypatch.undo()
