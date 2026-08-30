"""Secure tarball extraction sandbox (PRD §6.2 - anti zip-bomb/path traversal/symlink).

This module implements streaming extraction with guard counters for github-scan mode,
rejecting malicious entries before they touch filesystem.
"""

from __future__ import annotations

import tarfile
import io
from pathlib import Path


class SandboxViolation(Exception):
    """Raised when tarball entry violates security policy."""
    pass


class TooLargeArchive(SandboxViolation):
    """Total uncompressed size exceeds cap."""
    pass


class TooManyFiles(SandboxViolation):
    """File count exceeds cap."""
    pass


class PathTraversal(SandboxViolation):
    """Entry path contains absolute paths or '..' components."""
    pass


class SymlinkEntry(SandboxViolation):
    """Symlink/hardlink entries are rejected."""
    pass


def validate_member_path(member_name: str, dest_resolved: Path) -> None:
    """Validate a single member name against traversal & security rules."""
    # Absolute path check
    if member_name.startswith("/"):
        raise PathTraversal(f"absolute path rejected: {member_name}")
    
    # Resolve and verify containment
    candidate = (dest_resolved / member_name).resolve()
    if not candidate.is_relative_to(dest_resolved):
        raise PathTraversal(f"path traversal detected: {member_name}")
    
    # Double-check no .. escape after normalization
    parts = Path(member_name).parts
    if ".." in parts:
        raise PathTraversal(f"dot-dot component rejected: {member_name}")


def is_safe_tarball(tar_obj: tarfile.TarFile) -> bool:
    """Quick pre-scan: reject symlinks/devices without full extract."""
    for member in tar_obj.getmembers():
        if member.issym() or member.islnk() or member.isdev():
            return False
    return True


class SafeTarExtractor:
    """Streaming tarball extractor with guard counters and validation."""
    
    def __init__(
        self,
        dest: Path,
        max_bytes: int = 50_000_000,   # 50 MB default
        max_files: int = 3000,
    ):
        self.dest = dest.resolve()
        self.max_bytes = max_bytes
        self.max_files = max_files
        self.bytes_total = 0
        self.files_count = 0
    
    def extract_stream(self, fileobj: io.BytesIO) -> None:
        """Extract tarball from file-like object with streaming guards."""
        if not self.dest.exists():
            self.dest.mkdir(parents=True, exist_ok=True)
        
        dest_resolved = self.dest
        
        with tarfile.open(fileobj=fileobj, mode="r:gz") as tar:
            # Quick symlink/device rejection pre-check
            if not is_safe_tarball(tar):
                members = list(tar.getmembers())
                for m in members:
                    if m.issym() or m.islnk() or m.isdev():
                        raise SymlinkEntry(f"symlink device rejected: {m.name}")
            
            # Extract with stream counting
            for member in tar.getmembers():
                # Count checks before extract
                self.files_count += 1
                if self.files_count > self.max_files:
                    raise TooManyFiles(
                        f"too many files ({self.files_count} > {self.max_files})"
                    )
                
                # Size estimate check (tar header gives us this)
                self.bytes_total += member.size
                if self.bytes_total > self.max_bytes:
                    raise TooLargeArchive(
                        f"archive too large ({self.bytes_total:,} bytes > {self.max_bytes:,})"
                    )
                
                # Path validation
                validate_member_path(member.name, dest_resolved)
                
                # Python 3.12+ has filter='data'; fall back to manual on 3.11
                try:
                    tar.extract(member, self.dest, filter="data")
                except AttributeError:
                    # Manual extraction for older pythons
                    tar.extract(member, self.dest)


def sanitize_sandbox(sandbox_dir: Path) -> None:
    """Remove all artifacts from sandbox directory (cleanup on failure)."""
    if sandbox_dir.exists():
        import shutil
        shutil.rmtree(sandbox_dir, ignore_errors=True)
