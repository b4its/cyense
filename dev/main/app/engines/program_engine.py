"""Program engine — static analysis entry (PRD v2.0 §4.2 + xss-detection feature).

Runs one or more analysis passes over the source tree:
* idor — python AST rules CY001–CY006 + js/php regex CY007–CY010
* xss  — regex rules XS001–XS008 (instruction/feature/xss-detection.md)
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from app.program import xss_rules
from app.program.python_rules import analyze_python_file
from app.program.regex_rules import analyze_js_file, analyze_php_file

DEFAULT_SCAN_TYPES = ("idor", "xss")

# File suffixes supported per language (and for the "auto" aggregator)
SUFFIX_MAP = {"python": {".py"}, "js": {".js", ".ts"}, "php": {".php"}}
AUTO_SUFFIXES = {".py", ".js", ".ts", ".php"}


def resolve_source_dir(source_type: str, workspace_dir: str) -> Path:
    if source_type == "sample":
        sample = Path(__file__).resolve().parents[1] / "program" / "sample"
        return sample
    return Path(workspace_dir)


def _lang_for_suffix(path: Path, lang: str) -> str:
    """Resolve the language label for a given file under a given lang setting."""
    if lang in ("python", "js", "php"):
        return lang
    # lang == "auto": map suffix → language
    if path.suffix == ".py":
        return "python"
    if path.suffix in {".js", ".ts"}:
        return "js"
    if path.suffix == ".php":
        return "php"
    return ""


def run_program_scan(
    lang: str,
    source_dir: Path | str,
    scan_id: str,
    scan_types: tuple[str, ...] | list[str] | None = None,
    include_paths: set[str] | None = None,  # diff-scope filter (ci-compliance-reporting.md §3.3)
    max_files: int | None = None,
    level: str = "medium",
) -> dict[str, Any]:
    """Walk source tree and apply rules; returns report-shaped dict.

    Args:
        lang: Language to analyze (python, js, php, auto)
        source_dir: Root directory to scan
        scan_id: Scan identifier for finding IDs
        scan_types: Tuple/list of scan types (idor, xss) or None for default
        include_paths: Optional set of relative paths to include (diff-scope filter)
        max_files: Optional cap on files scanned (scan mode support). When
            ``None``, the cap is taken from the scan ``level`` profile so a
            ``--level low`` scan is automatically bounded.
        level: Analysis depth (low|medium|high|max). Controls which rules
            run (high/max-only rules are gated) and, when ``max_files`` is
            not provided explicitly, the file cap.

    Returns:
        Dict with files_scanned, findings list, level, and files_read_errors
    """
    from app.engines.scan_levels import get_level

    level_profile = get_level(level)

    if scan_types is None:
        scan_types = DEFAULT_SCAN_TYPES
    scan_types = tuple(scan_types)
    run_idor = "idor" in scan_types
    run_xss = "xss" in scan_types

    # Level-aware file cap: explicit max_files wins, otherwise use profile.
    if max_files is None:
        max_files = level_profile.max_files if level_profile.max_files > 0 else None

    # Coerce source_dir to Path — github mode passes a str tree_root
    source_dir = Path(source_dir) if not isinstance(source_dir, Path) else source_dir

    findings: list[dict[str, Any]] = []
    files_scanned = 0
    files_read_errors = 0  # track for coverage.complete flag

    suffixes = AUTO_SUFFIXES if lang == "auto" else SUFFIX_MAP.get(lang, {".py"})

    # Collect files first so we can apply level-specific rules that need the
    # full file set (cross-file analysis at max level).
    files_to_scan: list[Path] = []
    for path in sorted(source_dir.rglob("*")):
        if not path.is_file() or path.suffix not in suffixes:
            continue
        # sandbox discipline: skip junk dirs (PRD §11 zip bomb / traversal)
        parts = {p.lower() for p in path.parts}
        if parts & {"node_modules", ".git", "venv", ".venv", "__pycache__", "dist", "build"}:
            continue

        # Apply diff-scope filter (ci-compliance-reporting.md §3.3)
        if include_paths is not None:
            try:
                rel = path.relative_to(source_dir)
                rel_str = str(rel).replace("\\", "/")  # normalize to POSIX
                if rel_str not in include_paths:
                    continue
            except ValueError:
                continue

        files_to_scan.append(path)
        if max_files is not None and len(files_to_scan) >= max_files:
            break

    for path in files_to_scan:
        files_scanned += 1
        try:
            source = path.read_text(errors="replace")
        except OSError:
            files_read_errors += 1
            continue

        resolved_lang = _lang_for_suffix(path, lang)

        if resolved_lang == "python":
            if run_idor:
                findings.extend(analyze_python_file(path, source, scan_id))
                # High/max deep IDOR rules (CY011, CY012) — gated by level
                findings.extend(
                    _run_deep_idor_rules(path, source, scan_id, level_profile)
                )
            if run_xss:
                findings.extend(xss_rules.analyze_py_html_file(path, source, scan_id))
                findings.extend(
                    _run_deep_xss_rules(path, source, scan_id, level_profile, resolved_lang)
                )
        elif resolved_lang == "js":
            if run_idor:
                findings.extend(analyze_js_file(path, source, scan_id))
            if run_xss:
                findings.extend(xss_rules.analyze_js_file(path, source, scan_id))
                findings.extend(
                    _run_deep_xss_rules(path, source, scan_id, level_profile, resolved_lang)
                )
        elif resolved_lang == "php":
            if run_idor:
                findings.extend(analyze_php_file(path, source, scan_id))
            if run_xss:
                findings.extend(xss_rules.analyze_php_xss_file(path, source, scan_id))
                findings.extend(
                    _run_deep_xss_rules(path, source, scan_id, level_profile, resolved_lang)
                )

    return {
        "files_scanned": files_scanned,
        "findings": findings,
        "files_read_errors": files_read_errors,  # for coverage.complete flag
        "level": level_profile.name,
        "level_rules_active": _active_rule_ids(level_profile, run_idor, run_xss),
    }


# ---------------------------------------------------------------------------
# Level-aware deep rule dispatchers
# ---------------------------------------------------------------------------

def _active_rule_ids(level_profile, run_idor: bool, run_xss: bool) -> list[str]:
    """Return the rule IDs that will run at this level (for report metadata)."""
    base_idor = ["CY001", "CY002", "CY003", "CY004", "CY005", "CY006",
                 "CY007", "CY008", "CY009", "CY010"]
    base_xss = ["XS001", "XS002", "XS003", "XS004", "XS005", "XS006",
                "XS007", "XS008"]
    deep_idor = ["CY011", "CY012", "CY013"]
    deep_xss = ["XS009", "XS010", "XS011"]

    all_rules: list[str] = []
    if run_idor:
        all_rules.extend(base_idor)
        all_rules.extend(deep_idor)
    if run_xss:
        all_rules.extend(base_xss)
        all_rules.extend(deep_xss)

    from app.engines.scan_levels import rules_for_level
    return rules_for_level(all_rules, level_profile.name)


def _run_deep_idor_rules(
    path: Path,
    source: str,
    scan_id: str,
    level_profile,
) -> list[dict[str, Any]]:
    """Dispatch high/max-only IDOR rules (CY011, CY012, CY013)."""
    findings: list[dict[str, Any]] = []
    if not level_profile.should_run_rule("CY011") and not level_profile.should_run_rule("CY012"):
        return findings
    try:
        from app.program.deep_rules import analyze_deep_idor
        findings.extend(
            analyze_deep_idor(path, source, scan_id, level_profile)
        )
    except ImportError:
        # deep_rules not yet shipped; silently skip
        pass
    return findings


def _run_deep_xss_rules(
    path: Path,
    source: str,
    scan_id: str,
    level_profile,
    lang: str,
) -> list[dict[str, Any]]:
    """Dispatch high/max-only XSS rules (XS009, XS010, XS011)."""
    findings: list[dict[str, Any]] = []
    any_deep_xss = any(
        level_profile.should_run_rule(r) for r in ("XS009", "XS010", "XS011")
    )
    if not any_deep_xss:
        return findings
    try:
        from app.program.deep_rules import analyze_deep_xss
        findings.extend(
            analyze_deep_xss(path, source, scan_id, level_profile, lang)
        )
    except ImportError:
        pass
    return findings
