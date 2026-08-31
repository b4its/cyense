"""Fix applier dengan backup/revert/same-origin guard (PRD §6 - keamanan wajib).

Module ini menangani penulisan file yang aman:
1. Same-origin validation: hanya file di dalam source root scan yang boleh diubah
2. Backup otomatis sebelum tulis: <file>.bak-cyense
3. Revert capability: restore byte-identik dari backup
4. Verify loop: re-scan setelah patch untuk bukti temuan hilang
"""

from __future__ import annotations

import hashlib
from pathlib import Path


def is_same_origin(target_path: str, source_root: Path) -> tuple[bool, str]:
    """Validate bahwa target_path berada di dalam source_root (same-origin).

    Returns (is_valid, error_message).

    Security: mencegah path traversal / anti-writable-outside-source-root.
    """
    try:
        # Resolve to absolute path
        target = Path(target_path).resolve()
        root_resolved = source_root.resolve()

        # Check containment
        if not target.is_relative_to(root_resolved):
            return False, f"Path outside source root: {target} not under {root_resolved}"

        # Reject symlinks that escape source root
        for parent in target.parents:
            if parent.is_symlink():
                real_parent = parent.resolve()
                if not real_parent.is_relative_to(root_resolved):
                    return False, "Symlink escapes source root"

        return True, ""

    except Exception as exc:
        return False, f"Validation error: {exc}"


def create_backup(file_path: Path, backup_suffix: str = ".bak-cyense") -> Path | None:
    """Create backup before patching."""
    try:
        backup_path = Path(str(file_path) + backup_suffix)
        content = file_path.read_bytes()
        backup_path.write_bytes(content)
        return backup_path
    except OSError as exc:
        print(f"Backup failed: {exc}")
        return None


def apply_patch(
    file_path: Path,
    diff_text: str,
    source_root: Path,
) -> tuple[bool, str, Path | None]:
    """Apply a simple line-replacement diff safely.

    The diff format produced by Cyense strategies is a lightweight line diff:
        - <original line>
        + <replacement line>
    Each `-`/`+` pair identifies one line to replace. Lines without a marker
    are ignored (context is not required). The function replaces the first
    matching original line with the replacement line for each pair.
    """
    # Validate same-origin first
    is_valid, error = is_same_origin(str(file_path), source_root)
    if not is_valid:
        return False, error, None

    # Create backup
    backup = create_backup(file_path)
    if not backup:
        return False, "Failed to create backup", None

    # Parse diff into replacement pairs
    replacements: list[tuple[str, str]] = []
    diff_lines = diff_text.splitlines()
    i = 0
    while i < len(diff_lines):
        line = diff_lines[i]
        if line.startswith("- ") and not line.startswith("---"):
            old_line = line[2:].rstrip()
            # Look ahead for matching + line
            new_line = ""
            if i + 1 < len(diff_lines):
                next_line = diff_lines[i + 1]
                if next_line.startswith("+ ") and not next_line.startswith("+++"):
                    new_line = next_line[2:].rstrip()
                    i += 1
            replacements.append((old_line, new_line))
        i += 1

    if not replacements:
        return False, "No valid replacements found in diff", backup

    # Apply replacements to file content
    try:
        original_lines = file_path.read_text().splitlines()
    except OSError as exc:
        return False, f"Failed to read file: {exc}", backup

    patched_lines = list(original_lines)
    applied_count = 0
    for old_line, new_line in replacements:
        for idx, file_line in enumerate(patched_lines):
            if file_line.rstrip() == old_line:
                patched_lines[idx] = new_line
                applied_count += 1
                break
        else:
            # Could not find the line to replace; abort to avoid partial patch
            return False, f"Could not find line to replace: {old_line!r}", backup

    # Write patched file atomically via temp + replace
    try:
        patched_content = "\n".join(patched_lines)
        # Preserve trailing newline if original had one
        if original_lines and original_lines[-1].endswith("\n"):
            patched_content += "\n"
        elif file_path.read_text().endswith("\n"):
            patched_content += "\n"

        tmp_path = Path(str(file_path) + ".tmp-cyense")
        tmp_path.write_text(patched_content)
        tmp_path.replace(file_path)
        return True, f"Applied {applied_count} replacement(s)", backup
    except OSError as exc:
        # Restore from backup on failure
        try:
            file_path.write_bytes(backup.read_bytes())
        except OSError:
            pass
        return False, f"Write failed: {exc}", backup


def revert_patch(
    file_path: Path,
    backup_path: Path | None,
) -> bool:
    """Revert to backup state."""
    if not backup_path or not backup_path.exists():
        return False

    try:
        backup_content = backup_path.read_bytes()
        file_path.write_bytes(backup_content)
        return True
    except OSError:
        return False


def compute_file_hash(file_path: Path) -> str:
    """Compute SHA256 hash of file contents (for idempotency verification)."""
    content = file_path.read_bytes()
    return hashlib.sha256(content).hexdigest()


def check_if_unchanged(before_hash: str, after_hash: str) -> bool:
    """Check if patch application was actually noop."""
    return before_hash == after_hash


# --- Verify loop components ---

async def verify_after_apply(
    patch_id: str,
    file_path: Path,
    fix_store,
    program_engine_runner: any,
    max_file_kb: int = 1024,
) -> dict[str, any]:
    """Run re-scan to verify fix was successful (bukti keamanan)."""
    # Check size limit
    if file_path.stat().st_size > max_file_kb * 1024:
        return {"patch_id": patch_id, "verified": False, "reason": "File too large"}

    # Parse AST first (syntax check)
    try:
        import ast
        source = file_path.read_text()
        ast.parse(source)  # syntax gate — raise before re-scan
    except SyntaxError:
        return {"patch_id": patch_id, "verified": False, "reason": "Syntax error introduced"}
    except OSError:
        return {"patch_id": patch_id, "verified": False, "reason": "Cannot read file"}

    # Run targeted re-scan
    try:
        result = program_engine_runner.run_program_scan(
            lang="python" if file_path.suffix == ".py" else "js",
            source_dir=file_path.parent,
            scan_id=f"verify-{patch_id}",
        )

        findings_count = result.get("total_findings", 0)
        new_findings = result.get("new_findings", 0)

        verified = findings_count == 0

        return {
            "patch_id": patch_id,
            "verified": verified,
            "original_resolved": result.get("original_resolved", False),
            "new_findings": new_findings,
            "syntax_ok": True,
            "delta_summary": f"Before: {result.get('before_count', 0)}, After: {findings_count}",
        }
    except Exception as exc:
        return {
            "patch_id": patch_id,
            "verified": False,
            "reason": f"Verification failed: {str(exc)}",
        }
