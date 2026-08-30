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
    unified_diff: str,
    source_root: Path,
) -> tuple[bool, str, Path | None]:
    """Apply unified diff patch safely."""
    # Validate same-origin first
    is_valid, error = is_same_origin(str(file_path), source_root)
    if not is_valid:
        return False, error, None
    
    # Create backup
    backup = create_backup(file_path)
    if not backup:
        return False, "Failed to create backup", None
    
    # Parse unified diff and apply line substitutions
    lines = file_path.read_text().split("\n")
    
    # Simple approach: find and replace matching lines
    # This assumes diff format has "- old" and "+ new" markers
    
    patched_lines = []
    skip_until_next_hunk = False
    
    for i, line in enumerate(lines):
        # Remove trailing whitespace for comparison
        original_clean = line.rstrip()
        
        # Handle removal
        if line.startswith("- ") and not line.startswith("---"):
            if original_clean == line.lstrip("- ")[1:].rstrip():
                continue  # Skip removed line
        
        # Handle addition
        elif line.startswith("+ ") and not line.startswith("+++"):
            patched_lines.append(line.lstrip("+ ").rstrip())
        else:
            patched_lines.append(line)
    
    patched_content = "\n".join(patched_lines)
    
    # Write patched file
    try:
        file_path.write_text(patched_content)
        return True, "", backup
    except OSError as exc:
        # Restore from backup on failure
        file_path.write_bytes(backup.read_bytes())
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
        tree = ast.parse(source)
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
