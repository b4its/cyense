"""End-to-end test for github mode (PRD feature: github-repo-audit.md v2.0).

Proves the full pipeline: user posts a github link → fetcher fetches tarball
into sandbox → program_engine scans with lang='auto' → findings include BOTH
IDOR and XSS rules across python/js/php files in the fetched repo.

Network is mocked via httpx MockTransport (hermetic — no github.com calls).
"""

from __future__ import annotations

import io
import tarfile
from pathlib import Path

import httpx
import pytest

# Fixture sources embedded in the fake repo — mix of IDOR + XSS patterns
REPO_FILES: dict[str, bytes] = {
    # Python: IDOR CY001 + XSS XS007 + XS008
    "vuln/app.py": (
        b"from flask import request\n"
        b"def invoice(id):\n"
        b"    inv = Invoice.objects.get(id=request.GET['id'])\n"
        b"    return render(request, {'body': x|safe})\n"
        b"def greet(name):\n"
        b'    return f"<b>{name}</b>"\n'
    ),
    # JS: XSS XS001 + XS002 + XS004
    "vuln/comment.js": (
        b"el.innerHTML = window.location.hash.slice(1);\n"
        b"document.write(decodeURI(fragment));\n"
        b"eval(customScript);\n"
    ),
    # PHP: IDOR CY009 + XSS XS006
    "vuln/notes.php": (
        b'<?php\n'
        b'echo $_GET["message"];\n'
        b'->where("id", $_GET["q"]);\n'
    ),
}


def build_repo_tarball() -> bytes:
    """Build an in-memory tarball matching what codeload would return."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data in REPO_FILES.items():
            info = tarfile.TarInfo(name=f"owner-repo-abc/{name}")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


TARBALL_BYTES = build_repo_tarball()


def fake_github_handler(request: httpx.Request) -> httpx.Response:
    """Mock responses for api.github.com and codeload.github.com."""
    host = request.url.host
    path = request.url.path
    # metadata
    if host == "api.github.com" and path.startswith("/repos/"):
        return httpx.Response(
            200,
            json={
                "full_name": "owner/repo",
                "default_branch": "main",
                "size": 10,  # KB
                "private": False,
                "sha": "abc12345",
            },
            headers={"X-RateLimit-Remaining": "59"},
        )
    # tarball
    if host == "codeload.github.com":
        return httpx.Response(
            200,
            content=TARBALL_BYTES,
            headers={"Content-Type": "application/gzip"},
        )
    return httpx.Response(404, text="not found")


@pytest.fixture
def github_client_patch(monkeypatch: pytest.MonkeyPatch) -> None:
    """Patch httpx.AsyncClient so all outbound HTTP hits the mock handler."""
    original_init = httpx.AsyncClient.__init__

    def patched_init(self, *args, **kwargs):
        kwargs.pop("transport", None)
        original_init(self, *args, transport=httpx.MockTransport(fake_github_handler), **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "__init__", patched_init)


@pytest.mark.asyncio
async def test_github_mode_detects_idor_and_xss_from_fetched_repo(
    tmp_path: Path, github_client_patch
):
    """The primary feature: paste a github link, get IDOR + XSS findings."""
    from app.agents.brain import Brain
    from app.engines.github_engine import GithubEngine

    class Settings:
        github_max_mb = 50
        github_max_files = 3000
        github_timeout = 10.0

    brain = Brain(tmp_path / "brain")
    engine = GithubEngine(
        scan_id="gh-test-001",
        brain=brain,
        reports_dir=str(tmp_path / "reports"),
        settings=Settings(),
    )

    result = await engine.run(repo_url="https://github.com/owner/repo")

    # Pipeline completed successfully
    assert result["meta"]["mode"] == "github"
    assert result["meta"]["engine"] == "github-static"
    assert "error" not in result["meta"]

    # Repo metadata captured
    repo_meta = result["meta"]["repo"]
    assert repo_meta["owner"] == "owner"
    assert repo_meta["repo"] == "repo"

    # Files were scanned (python + js + php = 3)
    assert result["summary"]["files_analyzed"] == 3

    # Both IDOR and XSS rules triggered across languages
    rules = {f["rule"] for f in result["findings"]}
    # IDOR rules (python + php)
    assert "CY001" in rules  # Python IDOR
    assert "CY009" in rules  # PHP IDOR
    # XSS rules (js + python + php)
    assert "XS001" in rules  # JS innerHTML
    assert "XS006" in rules  # PHP echo
    assert "XS007" in rules  # Python |safe
    assert "XS008" in rules  # Python f-string HTML
    # XSS rules in JS
    assert "XS002" in rules  # document.write
    assert "XS004" in rules  # eval (critical)

    # Severity distribution reasonable. CY004 (FastAPI-specific) does NOT
    # double-report the Flask-style `def invoice(id)` view (already CY001), so
    # 8 is the correct baseline for this fixture.
    assert result["summary"]["total"] >= 8
    assert result["summary"]["critical"] >= 1  # eval → critical


@pytest.mark.asyncio
async def test_github_mode_rejects_non_github_host(github_client_patch):
    """SSRF guard: only github.com is accepted."""
    import tempfile
    from pathlib import Path

    from app.agents.brain import Brain
    from app.engines.github_engine import GithubEngine

    class Settings:
        github_max_mb = 50
        github_max_files = 3000
        github_timeout = 10.0

    tmp = Path(tempfile.mkdtemp())
    brain = Brain(tmp / "brain")
    engine = GithubEngine(
        scan_id="gh-ssrf",
        brain=brain,
        reports_dir=str(tmp / "reports"),
        settings=Settings(),
    )

    result = await engine.run(repo_url="https://evil.com/owner/repo")
    # Fetcher rejects non-github host → empty report
    assert result["findings"] == []
    assert "non-github" in result["meta"].get("error", ""), (
        f"Expected 'non-github' in error, got: {result['meta'].get('error')!r}"
    )


@pytest.mark.asyncio
async def test_github_mode_permission_gate_on_request():
    """POST without i_have_permission returns 422."""
    from pydantic import ValidationError

    from app.core.models_github import GithubScanRequest

    with pytest.raises(ValidationError):
        GithubScanRequest(mode="github", repo_url="https://github.com/a/b")

    # With permission gate set → succeeds
    req = GithubScanRequest(
        mode="github", repo_url="https://github.com/a/b", i_have_permission=True
    )
    assert req.mode == "github"
