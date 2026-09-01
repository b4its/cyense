"""Coverage JSON document — negative space of a scan (ci-compliance-reporting.md §3.5).

Records what was checked, distinguishing machine-observed facts from agent claims.
Ensures auditors can distinguish "tested clean" from "never examined".
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

# Schema version for future compatibility
SCHEMA_VERSION = 1


def build_coverage_document(
    report: dict[str, Any],
    scope_info: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build coverage.json content from scan results."""

    meta = report.get("meta", {})
    summary = report.get("summary", {})
    findings = report.get("findings", [])

    # Determine completeness flag.
    # Engines never write meta["status"] (default is the lowercase
    # "completed"), so normalize before comparing — previously the
    # uppercase "COMPLETED" comparison made `complete` always False and
    # every coverage.json reported an unfinished scan. Check the cap/budget
    # flags structurally instead of substring-scanning the whole report
    # (which flipped the flag when a finding text merely mentioned them).
    status = str(meta.get("status", "completed")).lower()
    complete = (
        status == "completed"
        and not (meta.get("cap_reached") or meta.get("budget_exceeded"))
    )

    # Machine-observed facts only (no LLM claims)
    machine_observed = {
        "rules_executed": sorted({f.get("rule") for f in findings}),
        "rules_with_findings": sorted(set(f.get("rule") for f in findings)),
        "files_scanned": summary.get("files_scanned") or summary.get("files_analyzed", 0),
        "findings_total": summary.get("total", len(findings)),
        "duration_ms": summary.get("duration_ms", 0),
    }

    # Add file breakdown if available
    if "files_by_language" in report:
        machine_observed["files_by_language"] = report["files_by_language"]

    # Scope information
    scope_data = {}
    if scope_info:
        scope_mode = scope_info.get("mode", "full")
        base = scope_info.get("base")

        scope_data = {
            "mode": scope_mode,
            "complete": complete,
        }

        if scope_mode != "full":
            scope_data["diff_base"] = base or "default branch"
            included = scope_info.get("included_files_count", 0)
            excluded = scope_info.get("excluded_files_count", 0)

            scope_data["files_in_scope"] = included
            scope_data["files_excluded_by_scope"] = excluded

            if excluded > 0:
                scope_data["note"] = (
                    f"Scan dibatasi pada {included} file yang berubah; "
                    f"{excluded} file lain TIDAK diperiksa."
                )

    # Build gaps analysis — deterministic detection
    gaps = _analyze_gaps(findings, scope_info)

    # Engine-reported metadata
    engine_reported = {
        "scan_types": meta.get("scan_types", ["idor"]),
        "lang": meta.get("lang", "auto"),
    }

    return {
        "schema_version": SCHEMA_VERSION,
        "scan_id": meta.get("scan_id", ""),
        "generated_at": report.get("generated_at") or _iso_timestamp(),
        "scope": scope_data,
        "machine_observed": machine_observed,
        "engine_reported": engine_reported,
        "gaps": gaps,
    }


def _analyze_gaps(
    findings: list[dict[str, Any]],
    scope_info: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    """Analyze which rules were active but found nothing."""

    rule_to_finding_count = {}
    for f in findings:
        rule = f.get("rule")
        rule_to_finding_count[rule] = rule_to_finding_count.get(rule, 0) + 1

    # Active rules based on scan metadata
    active_rules = set()

    # Check based on scan_types
    for f in findings:
        active_rules.add(f.get("rule"))

    gaps = []

    # Rule CY007-CY010 need JS/PHP files. Coerce None to "" so .endswith()
    # doesn't crash on findings whose location field is None (e.g. IDOR-LINK).
    has_js_files = any((f.get("location") or "").endswith((".js", ".ts")) for f in findings)
    has_php_files = any((f.get("location") or "").endswith(".php") for f in findings)

    if not has_js_files:
        gaps.append({
            "rule": "CY007",
            "reason": "no_js_files_in_scope",
            "detail": "Rule aktif tetapi tidak ada file .js/.ts dalam scope.",
        })
        gaps.append({
            "rule": "CY008",
            "reason": "no_js_files_in_scope",
            "detail": "Rule aktif tetapi tidak ada file .js/.ts dalam scope.",
        })

    if not has_php_files:
        gaps.append({
            "rule": "CY009",
            "reason": "no_php_files_in_scope",
            "detail": "Rule aktif tetapi tidak ada file .php dalam scope.",
        })
        gaps.append({
            "rule": "CY010",
            "reason": "no_php_files_in_scope",
            "detail": "Rule aktif tetapi tidak ada file .php dalam scope.",
        })

    return gaps


def write_coverage(report_dir: Path, document: dict[str, Any]) -> Path:
    """Write coverage.json atomically."""
    path = report_dir / "coverage.json"

    try:
        tmp = path.with_suffix(".json.tmp")
        tmp.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text(json.dumps(document, indent=2, sort_keys=True))
        tmp.replace(path)
    except Exception:
        tmp.unlink(missing_ok=True)
        raise

    return path


def _iso_timestamp() -> str:
    """ISO timestamp helper."""
    import time
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
