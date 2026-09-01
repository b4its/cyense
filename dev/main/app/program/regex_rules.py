"""Regex heuristics for JS/PHP IDOR patterns (PRD v2.0 §4.2, CY007+)."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from app.core.models import Finding, Severity, VerificationEvidence

JS_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "CY007",
        re.compile(
            r"findOne\(\s*\{\s*_id\s*:\s*req\.(params|query|body)\.([A-Za-z_][\w]*)",
        ),
        "MongoDB findOne keyed by request parameter without user scoping",
    ),
    (
        "CY008",
        re.compile(
            r"findById\(\s*req\.(params|query|body)\.([A-Za-z_][\w]*)",
        ),
        "Mongoose findById with request-controlled id — verify ownership",
    ),
]

PHP_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "CY009",
        re.compile(
            r"->where\(\s*['\"]id['\"]\s*,\s*\$(_GET|_POST|_REQUEST)\[",
        ),
        "Direct DB lookup from superglobal input without ownership filter",
    ),
    (
        "CY010",
        re.compile(
            r"User::?find\(\s*\$(_GET|_POST|_REQUEST)\[",
        ),
        "Model::find() with superglobal id — potential IDOR",
    ),
]

REMEDIATION = (
    "Scope the lookup by the authenticated user's id, or perform an explicit "
    "ownership/authorization check on the fetched object before returning it."
)


def _regex_findings(
    path: Path,
    source: str,
    scan_id: str,
    patterns: list[tuple[str, re.Pattern[str], str]],
    severity: Severity,
) -> list[Finding]:
    findings: list[Finding] = []
    for rule_id, pattern, description in patterns:
        for match in pattern.finditer(source):
            line = source.count("\n", 0, match.start()) + 1
            # Path discriminator prevents finding_id collisions when the same
            # rule+line appears in different files (remediation fix_id
            # uniqueness depends on finding_id).
            path_disc = hashlib.md5(str(path).encode("utf-8")).hexdigest()[:6]
            findings.append(
                Finding(
                    finding_id=f"{scan_id}-{rule_id}-{line}-{path_disc}",
                    rule=rule_id,
                    severity=severity,
                    confidence=0.6,
                    title=description,
                    description=(
                        f"`{match.group(0)}` uses a client-controlled identifier "
                        "as the sole lookup key (regex heuristic)."
                    ),
                    evidence={"file": str(path), "line": line, "match": match.group(0)},
                    verification=VerificationEvidence(notes="regex heuristic (js/php)"),
                    remediation=REMEDIATION,
                    location=f"{path}:{line}",
                )
            )
    return findings


def analyze_js_file(path: Path, source: str, scan_id: str) -> list[Finding]:
    return _regex_findings(path, source, scan_id, JS_PATTERNS, Severity.HIGH)


def analyze_php_file(path: Path, source: str, scan_id: str) -> list[Finding]:
    return _regex_findings(path, source, scan_id, PHP_PATTERNS, Severity.HIGH)


__all__ = ["analyze_js_file", "analyze_php_file"]
