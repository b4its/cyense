"""Regression tests for the SARIF 2.1.0 builder.

Bugs fixed:
1. ``ruleId`` became ``null`` when a finding had ``cwe: None`` (the default
   after Pydantic model_dump) — invalid per SARIF/GitHub Code Scanning.
2. Artifact URIs kept the ``":<line>"`` suffix from finding locations
   ("app.py:42" as URI) so results never mapped to real files.
3. Sandbox prefix stripping matched the *shortest* prefix first, leaving
   ``<scan_id>/src/`` inside the URI.
4. ``versionControlProvenance`` was emitted as an explicit ``null``.
"""

from __future__ import annotations

from app.report.sarif import _normalize_path, build_sarif_report


def test_normalize_path_strips_line_suffix() -> None:
    assert _normalize_path("reports/abc123/src/app/main.py:42") == "app/main.py"


def test_normalize_path_drops_scan_id_and_src() -> None:
    assert _normalize_path("reports/abc123/src/pkg/mod.py") == "pkg/mod.py"
    assert _normalize_path("reports/abc123/README.md") == "README.md"


def test_normalize_path_absolute_sandbox() -> None:
    assert (
        _normalize_path("/app/reports/abc123/src/app/main.py:7") == "app/main.py"
    )


def test_normalize_path_keeps_plain_relative() -> None:
    assert _normalize_path("app/program/views.py:3") == "app/program/views.py"


def test_normalize_path_url_location_survives_port() -> None:
    # DAST-style URL with a port must NOT lose ":8080" to the line stripper.
    out = _normalize_path("http://host:8080/invoice/1")
    assert out == "http://host:8080/invoice/1"


def test_normalize_path_traversal_and_garbage() -> None:
    assert _normalize_path("../../../etc/passwd") == "SECURITY.md"
    assert _normalize_path("/absolute/unrelated/path.py") == "SECURITY.md"
    assert _normalize_path(None) is None


def _report(findings: list[dict]) -> dict:
    return {
        "meta": {"scan_id": "s1", "mode": "program"},
        "summary": {"total": len(findings)},
        "findings": findings,
    }


def test_sarif_rule_id_never_null_for_none_cwe() -> None:
    finding = {
        "finding_id": "s1-CY001-10",
        "rule": "CY001",
        "severity": "high",
        "title": "Unscoped .get()",
        "location": "reports/abc/src/app.py:10",
        "cwe": None,  # Finding.cwe defaults to None
    }
    doc = build_sarif_report(_report([finding]), [finding])
    result = doc["runs"][0]["results"][0]
    assert result["ruleId"] == "CY001"  # not None / "None"
    uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "app.py"  # line suffix stripped
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 10


def test_sarif_rule_id_uses_cwe_when_present() -> None:
    finding = {
        "finding_id": "s2-CY011-5",
        "rule": "CY011",
        "severity": "high",
        "title": "Data-flow IDOR",
        "location": "app/services.py:5",
        "cwe": "CWE-639",
    }
    doc = build_sarif_report(_report([finding]), [finding])
    result = doc["runs"][0]["results"][0]
    assert result["ruleId"] == "CWE-639"
    rules = {r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]}
    assert "CWE-639" in rules


def test_sarif_omits_null_version_control_provenance() -> None:
    finding = {
        "finding_id": "s3-CY001-1",
        "rule": "CY001",
        "severity": "high",
        "title": "x",
        "location": "app.py:1",
    }
    doc = build_sarif_report(_report([finding]), [finding])
    run = doc["runs"][0]
    assert "versionControlProvenance" not in run

    doc2 = build_sarif_report(
        {
            "meta": {
                "scan_id": "s4",
                "mode": "github",
                "repo": {"url": "https://github.com/o/r", "commit_sha": "abcd1234", "ref": "main"},
            },
            "summary": {"total": 1},
            "findings": [finding],
        },
        [finding],
    )
    run2 = doc2["runs"][0]
    vcp = run2["versionControlProvenance"][0]
    assert vcp["repositoryUri"] == "https://github.com/o/r"
    assert vcp["revisionId"] == "abcd1234"
