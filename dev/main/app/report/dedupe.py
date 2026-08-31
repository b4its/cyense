"""Deduplication engine — deterministic key only (ci-compliance-reporting.md §3.6).

Uses (rule, path_relative, line) as identity key. No LLM judge; purely deterministic.
Also fixes the finding_id collision bug in python_rules.py.
"""

from __future__ import annotations

from typing import Any


def deduplicate_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Remove exact duplicate findings by (rule, location, line)."""
    
    seen = set()
    unique = []
    
    for f in findings:
        # Skip malformed
        rule = f.get("rule")
        loc = f.get("location", "")
        
        if not rule or not loc:
            unique.append(f)
            continue
        
        # Extract line from location "path:line"
        parts = loc.rsplit(":", 1)
        line = int(parts[-1]) if len(parts) == 2 and parts[-1].isdigit() else 0
        
        # Deterministic key
        key = (rule.lower(), loc.lower().strip("/"), line)
        
        if key not in seen:
            seen.add(key)
            unique.append(f)
    
    return unique


def generate_finding_id(scan_id: str, rule: str, lineno: int | None = None) -> str:
    """Generate unique finding ID (fixes python_rules.py bug where lineno omitted)."""
    
    if lineno is not None and lineno > 0:
        return f"{scan_id}-{rule}-{lineno}"
    
    # Fallback — but should not happen after fix
    return f"{scan_id}-{rule}"
