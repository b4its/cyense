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
) -> dict[str, Any]:
    """Walk source tree and apply rules; returns report-shaped dict."""
    if scan_types is None:
        scan_types = DEFAULT_SCAN_TYPES
    scan_types = tuple(scan_types)
    run_idor = "idor" in scan_types
    run_xss = "xss" in scan_types

    # Coerce source_dir to Path — github mode passes a str tree_root
    source_dir = Path(source_dir) if not isinstance(source_dir, Path) else source_dir

    findings: list[dict[str, Any]] = []
    files_scanned = 0

    suffixes = AUTO_SUFFIXES if lang == "auto" else SUFFIX_MAP.get(lang, {".py"})

    for path in sorted(source_dir.rglob("*")):
        if not path.is_file() or path.suffix not in suffixes:
            continue
        # sandbox discipline: skip junk dirs (PRD §11 zip bomb / traversal)
        parts = {p.lower() for p in path.parts}
        if parts & {"node_modules", ".git", "venv", ".venv", "__pycache__", "dist", "build"}:
            continue
        files_scanned += 1
        try:
            source = path.read_text(errors="replace")
        except OSError:
            continue

        resolved_lang = _lang_for_suffix(path, lang)

        if resolved_lang == "python":
            if run_idor:
                findings.extend(analyze_python_file(path, source, scan_id))
            if run_xss:
                findings.extend(xss_rules.analyze_py_html_file(path, source, scan_id))
        elif resolved_lang == "js":
            if run_idor:
                findings.extend(analyze_js_file(path, source, scan_id))
            if run_xss:
                findings.extend(xss_rules.analyze_js_file(path, source, scan_id))
        elif resolved_lang == "php":
            if run_idor:
                findings.extend(analyze_php_file(path, source, scan_id))
            if run_xss:
                findings.extend(xss_rules.analyze_php_xss_file(path, source, scan_id))

    return {"files_scanned": files_scanned, "findings": findings}
