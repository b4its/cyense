"""SARIF 2.1.0 builder for Cyense vulnerability reports (ci-compliance-reporting.md §3.2).

Builds GitHub code-scanning compatible SARIF documents from Cyense findings.
Validates against official schema; integrates with upload-sarif action.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

# SARIF constants
SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
VERSION = "2.1.0"
TOOL_NAME = "Cyense"
TOOL_INFO_URI = "https://github.com/"

# Map severity levels to SARIF level (matching Strix sarif.py:81)
_SEVERITY_TO_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
    "informational": "note",
}

# Map severity to security-severity score (0.0-10.0) for GitHub ranking
_SEVERITY_TO_SCORE = {
    "critical": "9.5",
    "high": "8.0",
    "medium": "5.5",
    "low": "3.0",
    "info": "1.0",
    "informational": "1.0",
}

# CWE to STRIDE mapping (stridge tags on rules)
_CWE_TO_STRIDE = {
    "CWE-639": ["elevation-of-privilege"],
    "CWE-79": ["information-disclosure", "tampering"],
    "CWE-22": ["information-disclosure", "tampering"],
    "CWE-95": ["execution", "denial-of-service"],
}


def _normalize_path(path: str | None, tree_root: str | None = None) -> str | None:
    """Convert a finding location to a repo-relative POSIX URI.

    Handles:
      * the ``":<line>"`` suffix that finding locations carry ("app.py:42")
        — stripped only when the tail is a plain integer so URLs with a
        port (host:8080) survive;
      * sandbox prefixes ``reports/<scan_id>/src/`` (relative form) and the
        same tree inside an absolute path — the most specific prefix is
        stripped first so the URI maps to a real repo file;
      * an explicit ``tree_root`` (github sandbox) — stripped when the
        location lives under it.
    Returns a synthetic anchor ("SECURITY.md") when no repo-relative form
    can be derived (Strix design: never emit an unmappable URI).
    """
    if not path:
        return None

    # 1. DAST-style URLs (scheme://...) are already valid artifact URIs —
    #    the split/rejoin below would collapse "http://" into "http:/".
    #    Return them untouched BEFORE any ":<line>"/":<port>" stripping, so a
    #    URL that ENDS in a port (http://host:8080) keeps it.
    if "://" in path:
        return path.replace("\\", "/")

    # 2. Strip trailing ":<line>" (integer-only, keeps host:port intact).
    head, sep, tail = path.rpartition(":")
    if sep and tail.isdigit():
        path = head

    norm = path.replace("\\", "/")

    # 2. Explicit tree_root (github sandbox) wins when it prefixes the path.
    if tree_root:
        tr = str(tree_root).replace("\\", "/").rstrip("/")
        if tr and norm.startswith(tr + "/"):
            norm = norm[len(tr) + 1:]

    # 3. Absolute path: re-root at the last "/reports/" marker if present
    #    (keep the "reports/" prefix so step 4 handles it uniformly).
    if norm.startswith("/"):
        idx = norm.find("/reports/")
        if idx != -1:
            norm = norm[idx + 1:]
        else:
            return "SECURITY.md"  # cannot map to anything repo-relative

    # 4. Relative "reports/<scan_id>/src/..." or "reports/<scan_id>/..." —
    # strip the most specific sandbox prefix first.
    parts = [seg for seg in norm.split("/") if seg]
    if parts and parts[0] == "reports":
        rest = parts[1:]
        if len(rest) >= 2 and rest[1] == "src":
            parts = rest[2:]  # drop <scan_id>/src
        elif len(rest) >= 2:
            parts = rest[1:]  # drop <scan_id>
        # len(rest) == 1 → file directly under reports/ — keep as-is

    if not parts:
        return "SECURITY.md"
    if ".." in parts:
        return "SECURITY.md"
    return "/".join(parts)


def _cwe_to_tags(cwe: str) -> list[str]:
    """Convert CWE identifier to STRIDE tags for SARIF."""
    cwe_num = cwe.replace("CWE-", "").strip()
    if cwe_num.isdigit():
        tags = _CWE_TO_STRIDE.get(cwe, ["security"])
        return ["external/cwe/" + cwe.lower()] + tags
    return ["security"]


def build_sarif_report(
    report: dict[str, Any],
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build complete SARIF document from Cyense report."""

    meta = report.get("meta", {})
    repo_meta = meta.get("repo", {})

    # Build rule definitions — keyed by rule ID (CY001, etc.), NOT by CWE.
    # Previously the CWE was used as rule_id, so two rules sharing the same
    # CWE (e.g. CY001 and CY002 both CWE-639) produced only ONE SARIF rule
    # entry, silently dropping the second rule's description from the SARIF
    # output and misleading GitHub code-scanning consumers.
    rules: list[dict[str, Any]] = []
    seen_rules: set[str] = set()
    for finding in findings:
        rule = finding.get("rule") or ""
        if not rule or rule in seen_rules:
            continue
        seen_rules.add(rule)
        cwe = finding.get("cwe") or ""
        rule_id = rule
        name = f"Cyense {rule}"
        short_desc = finding.get("title", "")[:100]

        # Get severity info
        base_sev = finding.get("severity", "info").lower()
        cvss_score = finding.get("cvss_score")

        result: dict[str, Any] = {
            "id": rule_id,
            "name": name,
            "shortDescription": {"text": short_desc},
        }

        # fullDescription with CWE reference
        if cwe:
            result["fullDescription"] = {
                "text": f"{cwe} — {short_desc}",
            }

        result["properties"] = {
            "tags": ["security"] + _cwe_to_tags(cwe),
        }

        # Add security-severity (prefer CVSS, fallback to label)
        if cvss_score is not None:
            result["properties"]["security-severity"] = f"{float(cvss_score):.1f}"
        else:
            result["properties"]["security-severity"] = _SEVERITY_TO_SCORE.get(base_sev, "1.0")

        # Help URI referencing the CWE
        if cwe:
            cwe_num = cwe.replace("CWE-", "").strip()
            if cwe_num.isdigit():
                result["helpUri"] = f"https://cwe.mitre.org/data/definitions/{cwe_num}.html"

        rules.append(result)

    # Build results
    results = []
    for finding in findings:
        rule = finding.get("rule", "UNKNOWN")
        # `cwe` may be present-but-None (Finding.cwe defaults to None after
        # model_dump) — `or` keeps ruleId a string instead of null.
        cwe = finding.get("cwe") or "CWE-Unknown"
        sev = finding.get("severity", "info").lower()

        level = _SEVERITY_TO_LEVEL.get(sev, "note")

        # Normalize location
        loc = finding.get("location", "")
        repo_rel_loc = _normalize_path(loc)

        # Determine rule ID — use the Cyense rule name (CY001/CY011/...)
        # to match the rule definitions above. The CWE is stored in
        # properties for cross-referencing by SARIF consumers.
        rule_id = rule

        # Build location(s)
        locations = []
        if repo_rel_loc:
            # Parse line number from "path:line" format — but only when the
            # location is NOT a URL (a URL like "http://host:8080" would
            # otherwise misread the port as a line number).
            line_no = 1
            if ":" in loc and "://" not in loc:
                tail = loc.split(":")[-1]
                if tail.isdigit():
                    line_no = int(tail)
            regions = [{"startLine": line_no}]
            locations.append({
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": repo_rel_loc,
                    },
                    "region": regions[0] if regions else None,
                }
            })
        else:
            # No valid location - use logicalLocation for DAST-style findings
            url = finding.get("evidence", {}).get("request", {}).get("url", "")
            locations = [{
                "logicalLocations": [{
                    "name": url,
                    "kind": "url"
                }]
            }]

        # Result object
        result_obj = {
            "ruleId": rule_id,
            "level": level,
            "kind": "fail",
            "message": {"text": finding.get("title", "")},
            "locations": locations,
            "partialFingerprints": {
                "cyenseRuleLocation/v1": finding.get("finding_id", ""),
            },
"properties": {
                    "cyense": {
                        "rule": rule,
                        "severity": sev,
                        "confidence": finding.get("confidence", 0),
                        "cvss_score": finding.get("cvss_score"),
                        "cvss_vector": finding.get("cvss_vector"),
                        "cwe": cwe,
                        "finding_id": finding.get("finding_id"),
                    }
                }
        }

        results.append(result_obj)

    # Version control provenance
    vcp = None
    if repo_meta.get("url") or repo_meta.get("commit_sha"):
        vcp = [{
            "repositoryUri": repo_meta.get("url", ""),
            "revisionId": repo_meta.get("commit_sha", "")[:40] or "",
            "branch": repo_meta.get("ref", ""),
        }]

    # Build root SARIF structure
    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": TOOL_NAME,
                "version": "2.1.0",
                "informationUri": TOOL_INFO_URI,
                "rules": rules,
            }
        },
        "results": results,
        "invocations": [{
            "executionSuccessful": True,
            "properties": {
                "scope_mode": meta.get("scope_mode", "full"),
            }
        }]
    }
    # Only emit versionControlProvenance when we actually have repo info —
    # an explicit null is rejected by strict SARIF consumers.
    if vcp is not None:
        run["versionControlProvenance"] = vcp

    # Wrap in runs array
    return {
        "$schema": SCHEMA,
        "version": VERSION,
        "runs": [run],
    }


def dump_sarif_report(report: dict[str, Any], path: Path) -> Path:
    """Write SARIF report to disk atomically."""
    findings = report.get("findings", [])
    sarif_doc = build_sarif_report(report, findings)

    # Atomic write
    tmp = path.with_suffix(".tmp")
    try:
        tmp.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text(json.dumps(sarif_doc, indent=2, sort_keys=True))
        tmp.replace(path)
    except Exception:
        tmp.unlink(missing_ok=True)
        raise

    return path
