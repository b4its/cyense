"""Tests for client-side feature coverage additions.

Covers:
  * Server /rules catalog now lists OSINT/RE/OWASP/HARVEST rules (the rules
    page + `cyense rules` read from this).
  * CLI command registration for the new client surface (delete, coverage,
    export sarif, fix-diff/apply/revert) and the offline `crypt` group.
  * Viewer static JS hardening (escapeAttr/fmtScore helpers).
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


def _rules_json(client) -> dict:
    r = client.get("/api/v1/rules")
    assert r.status_code == 200
    return r.json()


def test_rules_catalog_includes_client_surface_rules(client) -> None:
    """Scan-rule categories surfaced to CLI/web must include the new families."""
    data = _rules_json(client)
    live_rules = {x["rule"] for x in data.get("live_security", [])}
    discovery = {x["rule"] for x in data.get("discovery", [])}

    for rule in (
        "OWASP-LOGIN-GET",
        "OWASP-MIXED-CONTENT",
        "OWASP-EXTERNAL-NOSRI",
        "OWASP-DESER-MAGIC",
        "OWASP-SESSION-ENTROPY",
        "OSINT-RDAP",
        "OSINT-DNS",
        "OSINT-ASN",
        "RE-SOURCEMAP-REF",
        "RE-VULN-JS",
    ):
        assert rule in live_rules, f"rule {rule} missing from live_security catalog"
    for rule in (
        "HARVEST-SUBDOMAIN-CRTSH",
        "HARVEST-TECH-HEADER",
        "HARVEST-EMAIL",
    ):
        assert rule in discovery, f"rule {rule} missing from discovery catalog"


def test_rules_entries_have_metadata(client) -> None:
    """Each catalog entry carries rule/severity/cwe/title (used by renderer)."""
    data = _rules_json(client)
    for cat in ("live_security", "discovery"):
        for entry in data.get(cat, []):
            assert entry.get("rule")
            assert entry.get("severity")
            assert entry.get("cwe")
            assert entry.get("title")


def test_cli_registers_new_commands() -> None:
    from app.cli.main import app

    runner = CliRunner()
    # --help lists every command registered on the typer app.
    r = runner.invoke(app, ["--help"])
    assert r.exit_code == 0
    for name in ("delete", "coverage", "fix-diff", "fix-apply", "fix-revert", "crypt"):
        assert f"{name}" in r.stdout, f"command {name} not in CLI help"


def test_cli_crypt_offline_commands() -> None:
    from app.cli.main import app

    runner = CliRunner()
    r = runner.invoke(app, ["crypt", "hash", "abc", "--algo", "md5"])
    assert r.exit_code == 0
    assert "900150983cd24fb0d6963f7d28e17f72" in r.stdout

    r = runner.invoke(app, ["crypt", "identify", "0" * 64])
    assert r.exit_code == 0
    assert "SHA-256" in r.stdout


def test_cli_delete_requires_confirm() -> None:
    from app.cli.main import app

    runner = CliRunner()
    r = runner.invoke(app, ["delete", "scan_123"])
    assert r.exit_code == 3
    assert "--confirm" in r.stdout


def test_cli_fix_apply_revert_require_confirm() -> None:
    from app.cli.main import app

    runner = CliRunner()
    for args in (["fix-apply", "s1", "f1"], ["fix-revert", "s1"]):
        r = runner.invoke(app, args)
        assert r.exit_code == 3
        assert "--confirm" in r.stdout


def test_viewer_helpers_escape_attr() -> None:
    """The viewer JS must escape attribute values used inside onclick."""
    src = open("app/interface/viewer/static/app.js", encoding="utf-8").read()
    assert "escapeAttr" in src
    assert "fmtScore" in src
    assert "showFindingDetail(\"${escapeAttr(finding.finding_id)}\")" in src or \
        "showFindingDetail('${escapeAttr(finding.finding_id)}')" in src
