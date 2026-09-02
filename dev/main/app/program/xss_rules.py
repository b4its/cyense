"""XSS detection rules (feature PRD: instruction/feature/xss-detection.md).

Deterministic regex heuristics XS001–XS008 with cheap false-positive guards.
Works purely on source text — repo code is never executed.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from app.core.models import Finding, Severity, VerificationEvidence

# ---------------------------------------------------------------------------
# pattern table: (rule_id, compiled_regex, title, severity, remediation)
# ---------------------------------------------------------------------------

JS_PATTERNS: list[tuple[str, re.Pattern[str], str, Severity, str]] = [
    (
        "XS001",
        re.compile(
            r"\.\s*innerHTML\s*=\s*(?![\"\'\`]\s*;?\s*$)(?![\"\'\`][\"\'\`]?\s*$)(?!\s*[\"\'\`])",
        ),
        "innerHTML assigned a dynamic value",
        Severity.HIGH,
        "Use textContent, or sanitize the value with DOMPurify before assigning "
        "to innerHTML.",
    ),
    (
        "XS002",
        re.compile(r"document\.write\s*\(\s*(?![\"\'\`])"),
        "document.write with a dynamic value",
        Severity.HIGH,
        "Replace document.write with DOM APIs (createElement/append), or "
        "sanitize the value before writing.",
    ),
    (
        "XS003",
        re.compile(
            r"dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*(?![\"\'\`])",
        ),
        "dangerouslySetInnerHTML fed a dynamic value",
        Severity.HIGH,
        "Render text instead, or sanitize the value with DOMPurify before "
        "passing it as __html.",
    ),
    (
        "XS004",
        re.compile(
            r"(?:\beval\s*\(\s*(?![\"\'\`]\s*\))|\bnew\s+Function\s*\(\s*(?![\"\'\`]))",
        ),
        "eval/new Function on dynamic input",
        Severity.CRITICAL,
        "Eliminate eval; use JSON.parse or a lookup map of allowed functions.",
    ),
    (
        "XS005",
        re.compile(r"v-html\s*=\s*[\"]([^\"]+)"),
        "v-html bound to a dynamic expression",
        Severity.HIGH,
        "Prefer text interpolation {{ }}; if HTML is required, sanitize the "
        "value before binding to v-html.",
    ),
]

PY_PATTERNS: list[tuple[str, re.Pattern[str], str, Severity, str]] = [
    (
        "XS007",
        re.compile(r"\|\s*safe\b"),
        "Jinja2 |safe filter disables auto-escaping",
        Severity.HIGH,
        "Remove the |safe filter and let Jinja2 auto-escape; sanitize explicitly "
        "if trusted HTML is truly required.",
    ),
    (
        "XS008",
        re.compile(
            r"[fF]?[\"\'](?P<body>[^\"\']*<[a-zA-Z][^\"\']*(?:\{[^\"\']*\}|%[sdf]))[^\"\']*[\"\']",
        ),
        "HTML string composed via f-string/format with interpolated values",
        Severity.MEDIUM,
        "Render through the template engine so auto-escaping applies; do not "
        "compose HTML strings manually.",
    ),
]

PHP_PATTERNS: list[tuple[str, re.Pattern[str], str, Severity, str]] = [
    (
        "XS006",
        re.compile(
            r"(?:echo|print)\s+(?:\$(_GET|_POST|_REQUEST|_COOKIE)\s*\[|[^\n;]*\$_(?:GET|POST|REQUEST|COOKIE))",
        ),
        "PHP echo/print of superglobal input",
        Severity.HIGH,
        "Wrap output with htmlspecialchars($value, ENT_QUOTES) or use a "
        "templating layer with auto-escaping.",
    ),
]

# Escape markers that neutralize XS006 on the same line
PHP_ESCAPE_MARKERS = ("htmlspecialchars", "htmlentities", "strip_tags")

# Helpers that neutralize XS001 (sanitizer call on the right-hand side)
JS_SANITIZE_MARKERS = ("DOMPurify", "sanitizeHtml", "sanitize_html", "DOMPurify.sanitize")


def _finding(
    scan_id: str,
    rule_id: str,
    severity: Severity,
    path: Path,
    line: int,
    snippet: str,
    title: str,
    remediation: str,
) -> Finding:
    # Stable path discriminator for uniqueness — see python_rules.py note.
    path_disc = hashlib.md5(str(path).encode("utf-8")).hexdigest()[:6]
    finding_id = (
        f"{scan_id}-{rule_id}-{line}-{path_disc}" if line
        else f"{scan_id}-{rule_id}-{path_disc}"
    )
    return Finding(
        finding_id=finding_id,
        rule=rule_id,
        severity=severity,
        confidence=0.6,
        title=title,
        description=f"`{snippet.strip()[:120]}` matches unsafe pattern {rule_id}.",
        evidence={"file": str(path), "line": line, "match": snippet.strip()[:200]},
        verification=VerificationEvidence(notes="xss regex heuristic"),
        remediation=remediation,
        location=f"{path}:{line}",
    )


def _scan(
    scan_id: str,
    path: Path,
    source: str,
    patterns: list[tuple[str, re.Pattern[str], str, Severity, str]],
    guard: callable | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    for rule_id, pattern, title, severity, remediation in patterns:
        for match in pattern.finditer(source):
            line = source.count("\n", 0, match.start()) + 1
            lines = source.splitlines()
            snippet = lines[line - 1] if 0 < line <= len(lines) else match.group(0)
            if guard is not None and guard(rule_id, snippet):
                continue
            findings.append(
                _finding(scan_id, rule_id, severity, path, line, snippet, title, remediation)
            )
    return findings


# -- false-positive guards ----------------------------------------------------

def _js_guard(rule_id: str, line: str) -> bool:
    if rule_id in {"XS001", "XS002", "XS003"}:
        return any(marker in line for marker in JS_SANITIZE_MARKERS)
    if rule_id == "XS004":
        # eval of a plain literal string is still flagged; no cheap guard
        return False
    return False


def _php_guard(rule_id: str, line: str) -> bool:
    if rule_id == "XS006":
        return any(marker in line for marker in PHP_ESCAPE_MARKERS)
    return False


def _py_guard(rule_id: str, line: str) -> bool:
    if rule_id == "XS007":
        # a commented-out |safe is not a real sink
        return line.strip().startswith("#")
    if rule_id == "XS008":
        # static strings without braces/format markers never match; nothing to do
        return False
    return False


# -- public per-file entrypoints ----------------------------------------------

def analyze_js_file(path: Path, source: str, scan_id: str) -> list[Finding]:
    return _scan(scan_id, path, source, JS_PATTERNS, _js_guard)


def analyze_py_html_file(path: Path, source: str, scan_id: str) -> list[Finding]:
    return _scan(scan_id, path, source, PY_PATTERNS, _py_guard)


def analyze_php_xss_file(path: Path, source: str, scan_id: str) -> list[Finding]:
    return _scan(scan_id, path, source, PHP_PATTERNS, _php_guard)


def analyze_html_file(path: Path, source: str, scan_id: str) -> list[Finding]:
    """HTML templates: only v-html applies in MVP."""
    return _scan(
        scan_id,
        path,
        source,
        [p for p in JS_PATTERNS if p[0] == "XS005"],
        _js_guard,
    )


__all__ = [
    "analyze_js_file",
    "analyze_py_html_file",
    "analyze_php_xss_file",
    "analyze_html_file",
]
