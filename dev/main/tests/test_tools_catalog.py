"""Tests for the pentest tools catalog (CLI `cyense tools` + `/api/v1/tools`).

Covers:
  * Server /tools catalog serves a structured, deduplicated tool list grouped
    by category (including the added OSINT tools).
  * CLI registers the `tools` group with `list` and `categories` subcommands.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner


@pytest.fixture()
def client() -> TestClient:
    from app.main import create_app

    app = create_app()
    with TestClient(app) as test_client:
        yield test_client


def _tools_json(client) -> dict:
    r = client.get("/api/v1/tools")
    assert r.status_code == 200
    return r.json()


def _names_lower(data: dict) -> set[str]:
    return {str(t["name"]).lower() for t in data["tools"]}


def test_tools_catalog_serves_osint_and_pentest_tools(client) -> None:
    """The catalog merges the OSINT list + the Kali-style Pentest Tools list."""
    data = _tools_json(client)
    names = _names_lower(data)

    # OSINT additions from the awesome-osint list
    for want in (
        "DataSploit",
        "Spiderfoot",
        "Sn1per",
        "recon-ng",
        "wayparam",
        "Facebook Friend List Scraper",
        "Keyscope",
    ):
        assert want.lower() in names, f"OSINT tool {want} missing from /tools catalog"

    # Kali-style Pentest tool subset
    for want in (
        "whois",
        "Sublist3r",
        "Nmap | Zenmap",
        "theHarvester",
        "Nuclei",
        "WhatWeb",
        "Burpsuite",
        "ffuf",
        "Sqlmap",
        "Hydra",
        "Hashcat",
        "Metasploit",
        "WireShark",
        "GTFOBins",
        "Sliver",
        "Kali Linux",
        "DVWA",
    ):
        assert want.lower() in names, f"Pentest tool {want} missing from /tools catalog"


def test_tools_catalog_is_comprehensive(client) -> None:
    """The full Kali-style list is parsed, not just the curated subset."""
    data = _tools_json(client)
    names = _names_lower(data)

    # Tools that were NOT in the original curated subset — these can only come
    # from the embedded markdown parser.
    for want in (
        "SearchDiggity",
        "GitMiner",
        "svnExploit",
        "TXPortMap",
        "Censys-subdomain-finder",
        "gophish",
        "Xray",
        "Dirbuster",
        "MDUT",
        "HackBrowserDat",
        "wordlists",
        "JackIt",
        "Ollydbg",
        "NoSQLMap",
        "Fuxploider",
        "Oxml_xxe",
        "Ysomap",
        "Cain & abel",
        "Hoaxshell",
        "Rustcat",
        "PrintNotifyPotato",
        "Gitleaks",
        "Trivy",
        "DVWS",
        "DecoyMini",
        "Rawsec's CyberSecurity Inventory",
    ):
        assert want.lower() in names, f"tool {want} (from markdown) missing"


def test_tools_catalog_is_deduplicated_and_well_formed(client) -> None:
    data = _tools_json(client)
    names = [t["name"] for t in data["tools"]]
    assert len(names) == len(set(names)), "duplicate tool names in /tools catalog"
    assert data["total"] == len(names)

    seen_cats = {c["id"] for c in data["categories"]}
    for t in data["tools"]:
        assert t["category"] in seen_cats, f"{t['name']} has unknown category"
        # platform badges must use known keys
        for p in t.get("platforms", []):
            assert p in data["platforms"], f"{t['name']} has unknown platform {p}"

    # categories carry counts
    for c in data["categories"]:
        assert isinstance(c["count"], int)


def test_tools_have_features(client) -> None:
    """Every catalog tool carries a non-empty features list (CLI + Website)."""
    data = _tools_json(client)
    tools = data["tools"]
    assert data["total"] == len(tools)

    # Spot-check a few known tools.
    by_name = {str(t["name"]).lower(): t for t in tools}
    for name in ("Nmap | Zenmap", "Metasploit", "Sqlmap", "SpiderFoot"):
        t = by_name.get(name.lower())
        assert t is not None, name
        assert isinstance(t.get("features"), list)
        assert len(t["features"]) >= 2, f"{name} should have multiple features"

    # Coverage: every tool must have ≥1 feature so the cards are useful.
    empty = [t["name"] for t in tools if not t.get("features")]
    assert not empty, f"tools missing features: {empty[:10]}"


def test_tools_have_usage_bookmarks_related(client) -> None:
    """Every tool carries usage examples, a bookmark, and related tools."""
    data = _tools_json(client)
    tools = data["tools"]
    by_name = {str(t["name"]).lower(): t for t in tools}

    # Curated spot-checks.
    nmap = by_name["nmap | zenmap"]
    assert any("nmap -sV" in u for u in nmap["usage"]), "Nmap should have a usage example"
    assert nmap["bookmarks"], "Nmap should have bookmarks"
    assert nmap["related"], "Nmap should have related tools"

    metasploit = by_name["metasploit"]
    assert metasploit["usage"], "Metasploit should have usage examples"
    msf_related = metasploit.get("related", [])
    assert "Sliver" in msf_related or "Covenant" in msf_related, (
        "Metasploit should relate to other C2 frameworks"
    )

    # Coverage: every tool must carry all three enrichment fields.
    for t in tools:
        assert t.get("usage"), f"{t['name']} missing usage"
        assert t.get("bookmarks"), f"{t['name']} missing bookmarks"
        assert isinstance(t.get("related"), list) and t["related"], (
            f"{t['name']} missing related tools"
        )

    # All related references must resolve to existing tools.
    names = {str(t["name"]).lower() for t in tools}
    for t in tools:
        for r in t.get("related", []):
            assert r.lower() in names, f"{t['name']} → unknown related {r}"

    # Bookmarks must all be URLs.
    for t in tools:
        for b in t.get("bookmarks", []):
            assert b.startswith("http")


def test_osintradar_mirror_is_integrated(client) -> None:
    """osintradar.com library fully merged: additions + in-place enrichment."""
    data = _tools_json(client)
    assert data["total"] >= 600, "OSR additions should grow the catalog past 600"

    cats = {c["id"]: c for c in data["categories"]}
    for cid in ("osint-social", "osint-darkweb", "osint-breach", "osint-username",
                "osint-training", "osint-transport"):
        assert cid in cats, f"OSINT Radar category {cid} missing"
        assert cats[cid]["count"] > 0

    by_name = {str(t["name"]).lower(): t for t in data["tools"]}

    # An OSR addition carries the tool's original operating model verbatim.
    add = by_name["osint framework"]
    assert add["category"] == "osint-training"
    assert add["how_it_works"], "OSR tool should keep its mechanism write-up"
    assert add["source_page"].startswith("https://osintradar.com/tools/")
    assert isinstance(add["you_have"], list) and isinstance(add["you_get"], list)
    assert add["tool_status"], "published operational status should be kept"

    # A tool that already existed is enriched in place, not duplicated.
    assert sum(1 for t in data["tools"] if "ghunt" in str(t["name"]).lower()) == 1
    ghunt = by_name["ghunt"]
    assert ghunt["category"] == "osint"  # original category preserved
    assert ghunt.get("how_it_works"), "existing tool should gain OSR mechanism data"

    # Every osint-* category tool exposes the OSR fields + valid source link.
    for t in data["tools"]:
        if str(t["category"]).startswith("osint-"):
            assert t.get("how_it_works"), t["name"]
            assert t.get("source_page", "").startswith("https://osintradar.com")
            assert t.get("features") and t.get("usage") and t.get("bookmarks")


def test_methodology_layer_in_payload(client) -> None:
    """OSINT Radar methodology layer (Lapis A) ships with the catalog payload."""
    from app.program.osintradar_tools import OSR_CATEGORY_IDS

    data = _tools_json(client)

    # Pivot vocabulary — the 12 identifier types verified on the site, and
    # every catalog you_have code must fall inside it (the UI "I have" filter
    # depends on this).
    pivot_codes = {p["code"] for p in data["pivot_types"]}
    assert pivot_codes == {
        "name", "company", "username", "email", "domain", "ip",
        "url", "wallet", "location", "image", "file", "phone",
    }
    have_values = {h for t in data["tools"] for h in (t.get("you_have") or [])}
    assert have_values <= pivot_codes, f"you_have outside vocabulary: {have_values - pivot_codes}"

    # Workflows — the 6 core frameworks from OSINT Radar + 4 Cyense extensions
    # filling the categories the analysis flags as lacking an alur (§4.2).
    # Verbatim slugs, each step referencing only tools that exist in the catalog.
    slugs = [w["slug"] for w in data["workflows"]]
    assert slugs == [
        "investigate-a-username", "analyze-an-email", "research-a-domain",
        "verify-an-image", "locate-a-place", "trace-a-wallet",
        "triage-a-threat-alert", "investigate-a-darkweb-service",
        "track-a-vessel-or-flight", "verify-a-public-record",
    ]
    originals = slugs[:6]
    for w in data["workflows"]:
        assert w["question"] and w["steps"] and w["caution"], w["slug"]
        # core frameworks come from the site; the 4 new slugs must be flagged
        # (honest sourcing: UI must not represent them as OSINT-Radar-authored).
        assert bool(w.get("extension")) == (w["slug"] not in originals)
    names = _names_lower(data)
    for w in data["workflows"]:
        assert w["start_type"] in pivot_codes
        referenced = [t for s in w["steps"] for t in s["tools"]]
        assert referenced, f"{w['slug']} has no tool references"
        for tn in referenced:
            assert tn.lower() in names, f"{w['slug']} references unknown tool {tn}"

    # Reporting checkpoints + confidence scale (Reporting Checkpoints §A3).
    assert [c["id"] for c in data["reporting_checkpoints"]] == [
        "target_value", "source_and_time", "observed_result", "confidence",
    ]
    assert [c["level"] for c in data["confidence_scale"]] == [
        "confirmed", "probable", "lead", "disputed",
    ]

    # Every OSR category carries its analysis limitation; the riskiest groups
    # additionally carry an explicit risk class.
    cats = {c["id"]: c for c in data["categories"]}
    for cid in OSR_CATEGORY_IDS:
        assert cats[cid].get("note"), f"{cid} missing limitation note"
    for cid in ("osint-people", "osint-image", "osint-threat", "osint-darkweb",
                "osint-social", "osint-synthetic"):
        assert cats[cid].get("risk"), f"{cid} should carry an explicit risk class"

    # Health view — verification status totals + per-category breakdown.
    h = data["health"]
    assert h["operational"] + h["unverified"] + h["flagged"] == data["total"]
    assert sum(v for v in h["totals"].values()) == data["total"]
    assert h["by_category"]["osint-social"].get("Unverified", 0) >= 2
    # Every category in the health breakdown must be a valid category id.
    for cid in h["by_category"]:
        assert cid in cats, f"health category {cid} missing from categories"

    # Artefact types — each you_get label maps to one or more identifier codes
    # that a pivot exploration can hand off; labels not mapped are terminal.
    at = data["artefact_types"]
    assert isinstance(at, dict) and len(at) >= 30
    assert at.get("breaches") == ["email", "username", "domain"]
    assert at.get("transactions") == ["wallet"]
    assert at.get("subdomains") == ["domain", "ip"]
    # Every artefact code in the map must be a valid pivot_type code.
    all_codes = {p["code"] for p in data["pivot_types"]}
    for codes in at.values():
        for c in codes:
            assert c in all_codes, f"artefact_type code {c} not in PIVOT_TYPES"

    # Training & Reference — the gap-filling resources (§4.2).
    assert len(data["training"]) >= 10, "should have ≥10 methodology resources"
    for t in data["training"]:
        assert t["id"] and t["title"] and t["body"]

    # Per-tool risk labels + jurisdiction notes (§4.2 display enrichment).
    by_name = {str(t["name"]): t for t in data["tools"]}
    assert by_name["Face Recognition"].get("risk") == "biometrik"
    assert by_name["Face Recognition"].get("risk_why"), "biometrik label needs rationale"
    assert by_name["Gobuster"].get("risk") == "offensif"
    assert by_name["InstaLooter"].get("risk") == "mati"
    assert "AS" in by_name["US People Search"].get("coverage", "")
    risky = [t for t in data["tools"] if t.get("risk")]
    assert len(risky) >= 25, "per-tool labels should cover the flagged tools"

def test_faceted_catalog_search_api(client) -> None:
    """/api/v1/tools/search — read-only faceted machine API (§4.2, mirrors §A1
    query-param contract: category / have / pricing / status / q / page)."""
    r = client.get("/api/v1/tools/search", params={"have": "email", "pricing": "Free"})
    assert r.status_code == 200
    data = r.json()
    assert data["matched"] > 0
    for t in data["tools"]:
        assert "email" in (t.get("you_have") or [])
        assert str(t.get("pricing") or "").lower() == "free"

    r2 = client.get("/api/v1/tools/search", params={"q": "certificate transparency"})
    assert r2.status_code == 200 and r2.json()["matched"] >= 1
    assert any(
        "cert" in str(t["name"]).lower() or "crt" in str(t["name"]).lower()
        for t in r2.json()["tools"]
    )

    r3 = client.get("/api/v1/tools/search", params={"status": "Flagged"})
    assert r3.json()["matched"] == 2  # Twiangulate, Usa Official (as published)

    # pagination: page 2 disjoint from page 1, matched stays stable
    fq = {"category": "osint-domain", "page_size": 10}
    p1 = client.get("/api/v1/tools/search", params={**fq, "page": 1}).json()
    p2 = client.get("/api/v1/tools/search", params={**fq, "page": 2}).json()
    assert {t["name"] for t in p1["tools"]} & {t["name"] for t in p2["tools"]} == set()
    assert p1["matched"] == p2["matched"]
    assert len(p1["tools"]) == 10
    # unknown have/pricing filters return empty (no crash)
    assert client.get("/api/v1/tools/search", params={"have": "zip"}).json()["matched"] == 0

def test_cli_registers_tools_group() -> None:
    from app.cli.main import app

    runner = CliRunner()
    r = runner.invoke(app, ["tools", "--help"])
    assert r.exit_code == 0
    for name in ("list", "categories", "info", "usage"):
        assert name in r.stdout, f"subcommand {name} not in tools help"

    r = runner.invoke(app, ["--help"])
    assert r.exit_code == 0
    assert "tools" in r.stdout


def test_cli_tools_usage_and_info_offline_errors() -> None:
    """info/usage require the service; offline should return a clean error panel."""
    from app.cli.main import app

    runner = CliRunner()
    for args in (["tools", "info", "nmap"], ["tools", "usage", "nmap"]):
        r = runner.invoke(app, args)
        assert r.exit_code == 3, f"{args} should exit 3 when service is offline"
        assert r.stdout.strip()


def test_tools_categories_offline_invalid_id_exits() -> None:
    from app.cli.main import app

    runner = CliRunner()
    # service is not running in the test env → expect a clean error panel (3)
    r = runner.invoke(app, ["tools", "categories"])
    assert r.exit_code == 3
    assert r.stdout.strip(), "expected an error panel on offline service"
