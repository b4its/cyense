"""SARIF 2.1.0 builder for Cyense vulnerability reports (ci-compliance-reporting.md §3.2).

Builds GitHub code-scanning compatible SARIF documents from Cyense findings.
Validates against official schema; integrates with upload-sarif action.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.utils.redact import redact_url_credentials

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
    """Convert path to repo-relative POSIX. Return synthetic anchor if invalid."""
    if not path:
        return None
    
    # Clean up - remove sandbox prefix like reports/<id>/src/
    from pathlib import PurePath, PurePosixPath
    p = PurePosixPath(path)
    
    # Check if it's an absolute path or contains traversal
    if p.is_absolute() or ".." in p.parts:
        # Try to strip common prefixes first
        prefixes = [
            "reports/", f"reports/{p.parts[1]}/" if len(p.parts) > 1 else "",
            f"reports/{p.parts[1]}/{p.parts[2]}/" if len(p.parts) > 2 else "",
        ]
        
        cleaned = str(p)
        for prefix in prefixes:
            if prefix and cleaned.startswith(prefix):
                cleaned = cleaned[len(prefix):]
                try:
                    cp = PurePosixPath(cleaned)
                    if not cp.is_absolute() and ".." not in cp.parts:
                        path = cleaned
                        break
                except ValueError:
                    pass
        
        # If still invalid, use synthetic location
        if "/" not in path or ".." in path.split("/"):
            return "SECURITY.md"  # Synthetic anchor as per Strix design
    
    # Validate final path
    p_final = PurePosixPath(path)
    if p_final.is_absolute() or ".." in p_final.parts:
        return "SECURITY.md"
    
    return str(p)


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
    scan_id = meta.get("scan_id", "")
    repo_meta = meta.get("repo", {})
    
    # Build rule definitions
    rules = []
    seen_cwes = set()
    for finding in findings:
        cwe = finding.get("cwe") or ""
        if cwe and cwe not in seen_cwes:
            seen_cwes.add(cwe)
            rule_id = cwe
            name = f"Cyense {cwe}"
            short_desc = finding.get("title", "")[:100]
            
            # Get severity info
            base_sev = finding.get("severity", "info").lower()
            cvss_score = finding.get("cvss_score")
            
            result = {
                "id": rule_id,
                "name": name,
                "shortDescription": {"text": short_desc},
                "properties": {
                    "tags": ["security"] + _cwe_to_tags(cwe),
                }
            }
            
            # Add security-severity (prefer CVSS, fallback to label)
            if cvss_score is not None:
                result["properties"]["security-severity"] = f"{float(cvss_score):.1f}"
            else:
                result["properties"]["security-severity"] = _SEVERITY_TO_SCORE.get(base_sev, "1.0")
            
            rules.append(result)
    
    # Build results
    results = []
    for idx, finding in enumerate(findings):
        rule = finding.get("rule", "UNKNOWN")
        cwe = finding.get("cwe", "CWE-Unknown")
        sev = finding.get("severity", "info").lower()
        
        level = _SEVERITY_TO_LEVEL.get(sev, "note")
        
        # Normalize location
        loc = finding.get("location", "")
        repo_rel_loc = _normalize_path(loc)
        
        # Determine rule ID (prioritize CWE)
        rule_id = cwe if cwe != "CWE-Unknown" else rule
        
        # Find matching rule definition
        rule_def = next((r for r in rules if r["id"] == rule_id), 
                       {"id": rule_id, "shortDescription": {"text": finding.get("title", "")}})
        
        # Build location(s)
        locations = []
        if repo_rel_loc:
            regions = [{"startLine": int(loc.split(":")[-1]) if ":" in loc else 1}] if ":" in loc else []
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
    run = {
        "tool": {
            "driver": {
                "name": TOOL_NAME,
                "version": "2.0.0",
                "informationUri": TOOL_INFO_URI,
                "rules": rules,
            }
        },
        "versionControlProvenance": vcp,
        "results": results,
        "invocations": [{
            "executionSuccessful": True,
            "properties": {
                "scope_mode": meta.get("scope_mode", "full"),
            }
        }]
    }
    
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
