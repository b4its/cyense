"""Program engine — static analysis entry (PRD v2.0 §4.2)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from app.program.python_rules import analyze_python_file
from app.program.regex_rules import analyze_js_file, analyze_php_file


def resolve_source_dir(source_type: str, workspace_dir: str) -> Path:
    if source_type == "sample":
        sample = Path(__file__).resolve().parents[1] / "program" / "sample"
        return sample
    return Path(workspace_dir)


def run_program_scan(
    lang: str,
    source_dir: Path,
    scan_id: str,
) -> dict[str, Any]:
    """Walk source tree and apply rules; returns report-shaped dict."""
    findings: list[dict[str, Any]] = []
    files_scanned = 0

    suffix_map = {"python": {".py"}, "js": {".js", ".ts"}, "php": {".php"}}
    suffixes = suffix_map.get(lang, {".py"})

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
        if lang == "python" and path.suffix == ".py":
            findings.extend(analyze_python_file(path, source, scan_id))
        elif lang in ("js",) and path.suffix in {".js", ".ts"}:
            findings.extend(analyze_js_file(path, source, scan_id))
        elif lang == "php" and path.suffix == ".php":
            findings.extend(analyze_php_file(path, source, scan_id))

    return {"files_scanned": files_scanned, "findings": findings}
