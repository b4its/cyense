"""Scan comparison — deterministic diff between two scan reports.

Pure stdlib module (no FastAPI/httpx deps) so it can be unit-tested hermetically
and reused by the CLI ``compare`` command and any future API endpoint.

Identity key for a finding: ``(rule, normalized_location)`` — the same key
family used by dedupe/SARIF fingerprints (ci-compliance-reporting.md §3.6).
"""

from __future__ import annotations

from typing import Any


def _finding_key(finding: dict[str, Any]) -> tuple[str, str]:
    """Stable identity: rule + location (case/whitespace-normalised)."""
    rule = str(finding.get("rule", "")).strip().upper()
    location = str(finding.get("location") or "").strip()
    return (rule, location)


def _severity_rank(severity: str) -> int:
    order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    return order.get(str(severity).lower(), 0)


def compare_reports(
    old: dict[str, Any],
    new: dict[str, Any],
) -> dict[str, Any]:
    """Compare two report dicts; returns a structured diff.

    Result shape::

        {
          "old": {scan_id, total, by_severity},
          "new": {scan_id, total, by_severity},
          "unchanged": [finding],       # same rule+location in both
          "added":     [finding],       # only in new
          "removed":   [finding],       # only in old
          "changed":   [ {old, new} ],  # same key, severity/CVSS moved
          "counts":    {unchanged, added, removed, changed},
        }
    """
    old_findings = old.get("findings", []) or []
    new_findings = new.get("findings", []) or []

    old_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for f in old_findings:
        old_by_key.setdefault(_finding_key(f), f)

    new_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for f in new_findings:
        new_by_key.setdefault(_finding_key(f), f)

    added: list[dict[str, Any]] = []
    removed: list[dict[str, Any]] = []
    unchanged: list[dict[str, Any]] = []
    changed: list[dict[str, Any]] = []

    for key, f_new in new_by_key.items():
        f_old = old_by_key.get(key)
        if f_old is None:
            added.append(f_new)
            continue

        old_sev = str(f_old.get("severity", "")).lower()
        new_sev = str(f_new.get("severity", "")).lower()
        old_score = f_old.get("cvss_score")
        new_score = f_new.get("cvss_score")
        if old_sev != new_sev or old_score != new_score:
            changed.append({"old": f_old, "new": f_new})
        else:
            unchanged.append(f_new)

    for key, f_old in old_by_key.items():
        if key not in new_by_key:
            removed.append(f_old)

    # Deterministic ordering: severity desc, then rule, then location.
    def simple_key(f: dict[str, Any]) -> tuple[int, str, str]:
        return (
            -_severity_rank(str(f.get("severity", ""))),
            str(f.get("rule", "")),
            str(f.get("location") or ""),
        )

    added.sort(key=simple_key)
    removed.sort(key=simple_key)
    unchanged.sort(key=simple_key)
    changed.sort(key=lambda c: simple_key(c["new"]))

    return {
        "old": _report_header(old),
        "new": _report_header(new),
        "unchanged": unchanged,
        "added": added,
        "removed": removed,
        "changed": changed,
        "counts": {
            "unchanged": len(unchanged),
            "added": len(added),
            "removed": len(removed),
            "changed": len(changed),
        },
    }


def _report_header(report: dict[str, Any]) -> dict[str, Any]:
    meta = report.get("meta", {})
    summary = report.get("summary", {})
    return {
        "scan_id": meta.get("scan_id", ""),
        "total": summary.get("total", len(report.get("findings", []) or [])),
        "by_severity": {
            sev: summary.get(sev, 0)
            for sev in ("critical", "high", "medium", "low", "info")
        },
    }
