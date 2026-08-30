"""Unit/integration tests for github-scan feature (PRD instruction/feature/github-repo-audit.md).

Hermetic: zero network calls via httpx MockTransport or local file:// tarballs.
Per PRD §7 testing strategy.
"""

from __future__ import annotations

import io
import tarfile
from pathlib import Path
from typing import Any

import pytest


# =============================================================================
# URL parsing tests
# =============================================================================

def test_parse_github_url_valid_formats() -> None:
    """Parse various GitHub URL variants."""
    from app.agents.fetcher import parse_github_url
    
    # Direct repo form
    result = parse_github_url("https://github.com/acme/repo")
    assert result == {"owner": "acme", "repo": "repo", "ref": None, "path": None}
    
    # With tree ref
    result = parse_github_url("https://github.com/acme/repo/tree/main/backend")
    assert result["owner"] == "acme" and result["repo"] == "repo"
    assert result["ref"] == "main"
    assert result["path"] == "backend"
    
    # Blob variant
    result = parse_github_url("https://github.com/acme/repo/blob/v1.0/app.py")
    assert result["ref"] == "v1.0"
    
    # .git suffix stripped
    result = parse_github_url("https://github.com/acme/repo.git")
    assert result["repo"] == "repo"


def test_parse_github_url_rejects_non_github() -> None:
    """Reject non-github.com hosts (SSRF guard)."""
    from app.agents.fetcher import parse_github_url
    
    with pytest.raises(ValueError, match="invalid github url format"):
        parse_github_url("https://gitlab.com/evil/repo")
    
    with pytest.raises(ValueError, match="invalid github url format"):
        parse_github_url("http://github.com/insecure/repo")  # http not https


# =============================================================================
# Sandbox extraction tests
# =============================================================================

def test_sandbox_accepts_normal_tarball(tmp_path: Path) -> None:
    """Normal tarball extracts successfully."""
    from app.utils.sandbox import SafeTarExtractor, sanitize_sandbox
    
    # Create fake tarball
    tar_io = io.BytesIO()
    with tarfile.open(fileobj=tar_io, mode="w:gz") as tar:
        data = b"print('hello')"
        info = tarfile.TarInfo(name="app.py")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    
    tar_io.seek(0)
    extractor = SafeTarExtractor(tmp_path / "sandbox", max_bytes=10_000, max_files=10)
    extractor.extract_stream(tar_io)
    
    assert (tmp_path / "sandbox" / "app.py").exists()
    assert (tmp_path / "sandbox" / "app.py").read_text() == "print('hello')"


def test_sandbox_rejects_absolute_paths(tmp_path: Path) -> None:
    """Absolute path in tarball raises exception."""
    from app.utils.sandbox import SafeTarExtractor, TooLargeArchive, PathTraversal
    
    tar_io = io.BytesIO()
    with tarfile.open(fileobj=tar_io, mode="w:gz") as tar:
        info = tarfile.TarInfo(name="/etc/passwd")
        info.size = 100
        tar.addfile(info, io.BytesIO(b"x"*100))
    
    tar_io.seek(0)
    extractor = SafeTarExtractor(tmp_path / "sandbox")
    
    with pytest.raises(PathTraversal):
        extractor.extract_stream(tar_io)


def test_sandbox_rejects_symlinks(tmp_path: Path) -> None:
    """Symlink entries rejected before extract."""
    from app.utils.sandbox import SafeTarExtractor, SymlinkEntry
    
    tar_io = io.BytesIO()
    with tarfile.open(fileobj=tar_io, mode="w:gz") as tar:
        # Normal file
        data = b"test"
        info = tarfile.TarInfo(name="safe.txt")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
        
        # Symlink pointing outside
        link_info = tarfile.TarInfo(name="bad_link")
        link_info.type = tarfile.SYMTYPE
        link_info.linkname = "../../../../etc/passwd"
        tar.addfile(link_info)
    
    tar_io.seek(0)
    extractor = SafeTarExtractor(tmp_path / "sandbox")
    
    with pytest.raises(SymlinkEntry):
        extractor.extract_stream(tar_io)


def test_sandbox_enforces_size_cap(tmp_path: Path) -> None:
    """Large tarball rejected by size cap."""
    from app.utils.sandbox import TooLargeArchive, SafeTarExtractor
    
    tar_io = io.BytesIO()
    with tarfile.open(fileobj=tar_io, mode="w:gz") as tar:
        # Single big file
        big_data = b"x" * 60_000_000  # 60MB > default 50MB cap
        info = tarfile.TarInfo(name="big.txt")
        info.size = len(big_data)
        tar.addfile(info, io.BytesIO(big_data))
    
    tar_io.seek(0)
    # Use smaller cap to trigger quickly
    extractor = SafeTarExtractor(tmp_path / "sandbox", max_bytes=10_000_000)
    
    with pytest.raises(TooLargeArchive):
        extractor.extract_stream(tar_io)


# =============================================================================
# Token redaction tests
# =============================================================================

def test_token_redaction_in_client() -> None:
    """Token masked for logging (never appears in reports)."""
    from app.utils.github_client import GithubClient
    
    # Short token
    assert GithubClient.redact_token("abc123") == "[REDACTED]"
    
    # Medium token
    assert GithubClient.redact_token("a" * 8) == "[REDACTED]"
    
    # Long token - show first/last chars
    secret = "ghp_" + "x" * 40
    masked = GithubClient.redact_token(secret)
    assert masked.startswith(secret[:4])
    assert masked.endswith(secret[-4:])
    assert "[REDACTED]" not in masked


# =============================================================================
# Language auto-detection tests
# =============================================================================

def test_lang_detect_python_dominant(tmp_path: Path) -> None:
    """Auto-detect dominant language from file list."""
    from app.utils.lang_detect import detect_language_from_files
    
    # Pure Python dir
    (tmp_path / "main.py").touch()
    (tmp_path / "utils.py").touch()
    assert detect_language_from_files(list(tmp_path.iterdir())) == "python"
    
    # Mixed - python dominant (2 py, 1 js)
    (tmp_path / "app.js").touch()
    assert detect_language_from_files(list(tmp_path.iterdir())) == "python"
    
    # Mixed - js equal (2 py, 2 js) -> py wins on tie-break
    (tmp_path / "module.js").touch()
    assert detect_language_from_files(list(tmp_path.iterdir())) == "python"


# =============================================================================
# Integration test fixture (local mock server)
# =============================================================================

@pytest.fixture
def sample_tarball():
    """Create a minimal tarball containing vulnerable code snippets."""
    tar_io = io.BytesIO()
    with tarfile.open(fileobj=tar_io, mode="w:gz") as tar:
        # Python file with IDOR pattern
        content = b"""
from flask import Flask, request

app = Flask(__name__)

@app.route('/invoice/<int:id>')
def invoice_detail(id):
    # Vulnerable: no ownership check
    inv = Invoice.objects.get(id=id)
    return inv
"""
        info = tarfile.TarInfo(name="app.py")
        info.size = len(content)
        tar.addfile(info, io.BytesIO(content))
    tar_io.seek(0)
    return tar_io


@pytest.fixture
def temp_sandbox(tmp_path: Path):
    """Extract sample tarball into sandbox directory."""
    sandbox_dir = tmp_path / "src"
    safe_extract(sample_tarball(), sandbox_dir, max_bytes=10_000_000)
    return sandbox_dir


def safe_extract(tar_io: io.BytesIO, dest: Path, max_bytes: int) -> None:
    """Helper: extract with guards."""
    from app.utils.sandbox import SafeTarExtractor
    extractor = SafeTarExtractor(dest, max_bytes=max_bytes)
    extractor.extract_stream(tar_io)
