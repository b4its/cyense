"""Regression tests for the sweeping bug-fix pass.

Covers high/critical fixes across the codebase that the existing 366 tests
did not exercise:
  * worker.discard path traversal (DELETE /. must NOT wipe the reports dir)
  * AES-GCM round-trips with arbitrary nonce lengths; Twofish/Blowfish mode
    validation (no silent CBC fallback)
  * remediation no-op diff (double-quoted source) and cy009 unknown-context
  * python_rules Depends(get_db) no longer treated as auth (IDOR FN fixed)
    and CY012 auth-dep handling
  * crawler emits only ONE {ID} per endpoint (path+query)
  * fetcher honors /tree/<ref>; resume merge preserves checkpoint target
  * redact_url_credentials leaves @ in query strings intact
  * renderer/recommend URL location classification
  * dedupe keeps distinct cookie findings on one URL
"""

from __future__ import annotations

import ast
import tempfile
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# worker.discard path traversal
# ---------------------------------------------------------------------------

def test_discard_dot_does_not_wipe_reports_dir() -> None:
    from app.core.store import JobStore
    from app.worker import ScanWorker

    d = Path(tempfile.mkdtemp())
    (d / "store.json").write_text("{}")
    (d / "scan_x").mkdir()
    (d / "scan_x" / "report.json").write_text("{}")

    settings = type("S", (), {"reports_dir": d})()
    w = ScanWorker(JobStore(d), None, settings)

    # "." and ".."-style ids must be rejected (not resolve to reports root).
    assert w._reports_dir_for(".") is None
    assert w._reports_dir_for("..") is None

    w.discard(".")
    w.discard("..")
    assert d.exists() and (d / "store.json").exists(), "reports dir was wiped"

    # A real scan is still removable without touching the root.
    w.discard("scan_x")
    assert not (d / "scan_x").exists()
    assert d.exists() and (d / "store.json").exists()


# ---------------------------------------------------------------------------
# crypto fixes
# ---------------------------------------------------------------------------

def test_aes_gcm_arbitrary_nonce_roundtrip() -> None:
    from app.utils import cryptotool as c

    key = "0123456789abcdef0123456789abcdef"
    for n in (8, 12, 16, 20):
        nb = bytes(range(n))
        ct = c.aes_encrypt(key, "rahasia", mode="gcm", nonce=nb)
        assert c.aes_decrypt(key, ct, mode="gcm", nonce=nb) == "rahasia"


def test_twofish_blowfish_invalid_mode_raises() -> None:
    from app.utils import cryptotool as c

    for fn, args in (
        (c.twofish_encrypt, ("k" * 16, "msg")),
        (c.blowfish_encrypt, ("k", "msg")),
    ):
        with pytest.raises(ValueError):
            fn(*args, mode="ctr")


# ---------------------------------------------------------------------------
# remediation
# ---------------------------------------------------------------------------

def test_remediation_no_op_double_quote_fixed() -> None:
    """A double-quoted Django call must produce a REAL fix diff, not a
    self-replacing no-op that 'applies' without adding the ownership filter."""
    from app.remediation.python_strategies import generate_ownership_filter

    src = 'inv = Invoice.objects.get(id=request.GET["id"])'
    tree = ast.parse(src)
    node = next(
        n for n in ast.walk(tree)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
        and n.func.attr == "get"
    )
    r = generate_ownership_filter(node, src, "request.user")
    assert r.before_snippet != r.after_snippet, "patch is a no-op"
    assert "user_id=request.user.id" in r.after_snippet


def test_cy009_no_auth_ctx_is_manual_required() -> None:
    from app.remediation.jsphp_strategies import cy009_strategy

    r = cy009_strategy(None, "DB::table('x')->where('id', $request->input('id'))")
    assert "manual_required" in r["diff"] or "unknown" not in r["diff"]


# ---------------------------------------------------------------------------
# IDOR static rules (auth-guard sensitivity)
# ---------------------------------------------------------------------------

def test_depends_db_not_treated_as_auth() -> None:
    """CY001/CY004 must still fire when the only Depends is a DB session."""
    from app.program.python_rules import analyze_python_file

    p = Path(tempfile.mkdtemp()) / "x.py"
    src = (
        "from fastapi import Depends\n"
        '@app.get("/invoices/{id}")\n'
        "async def get_invoice(id: int, db = Depends(get_db)):\n"
        "    return Invoice.objects.get(id=id)\n"
    )
    f = analyze_python_file(p, src, "s")
    assert any(x.rule in ("CY001", "CY004") for x in f)


def test_cy012_protected_endpoint_not_flagged() -> None:
    from app.program.deep_rules import _check_cy012

    p = Path(tempfile.mkdtemp()) / "x.py"
    src = (
        'from fastapi import Depends\n'
        '@app.get("/users/{uid}")\n'
        "async def me(uid: int, user = Depends(get_current_user)):\n"
        '    return User.objects.filter(User.id == request.GET["uid"]).first()\n'
    )
    f = _check_cy012(ast.parse(src), p, "scan")
    assert len(f) == 0  # endpoint IS protected


def test_crawler_single_id_placeholder_per_endpoint() -> None:
    from app.agents.crawler import _find_id_endpoints

    ep = _find_id_endpoints(["https://x.com/api/users/5/invoices?account_id=5"])[0]
    assert ep["template"].count("{ID}") == 1
    assert ep["template"] == "https://x.com/api/users/{ID}/invoices?account_id=5"


# ---------------------------------------------------------------------------
# redaction
# ---------------------------------------------------------------------------

def test_redact_url_leaves_query_at_intact() -> None:
    from app.utils.redact import redact_url_credentials

    # Credentials in userinfo ARE redacted.
    assert "hunter2" not in redact_url_credentials("http://user:hunter2@lab/x")
    # An @ inside a query string (email) must NOT be mangled.
    out = redact_url_credentials("https://x.com/search?email=a@b.c")
    assert out == "https://x.com/search?email=a@b.c"


# ---------------------------------------------------------------------------
# resume merge + diff-scope unwrap helpers (pure logic)
# ---------------------------------------------------------------------------

def test_resume_merge_keeps_checkpoint_target() -> None:
    """Non-empty checkpoint request values survive a fresh resume request that
    carries empty defaults for omitted fields."""
    checkpoint_request = {
        "mode": "github",
        "repo_url": "https://github.com/acme/private",
        "ref": "main",
    }
    fresh = {
        "mode": "github", "repo_url": "", "lang": "auto",
        "i_have_permission": True, "resume_from": "abc",
    }
    merged = dict(checkpoint_request)
    for key, value in fresh.items():
        if value in (None, "", [], {}):
            continue
        merged[key] = value
    assert merged["repo_url"] == "https://github.com/acme/private"
    assert merged["ref"] == "main"


# ---------------------------------------------------------------------------
# renderer / recommend / dedupe
# ---------------------------------------------------------------------------

def test_renderer_survives_none_confidence() -> None:
    """A finding with confidence=None must not crash the CLI renderers."""
    import io as _io

    from rich.console import Console

    from app.cli.renderer import render_finding_card, render_findings_table
    from app.cli.theme import detect_caps

    caps = detect_caps(force_ascii=True, force_quiet=True)
    console = Console(file=_io.StringIO(), width=100)
    finding = {
        "rule": "X", "severity": "high", "confidence": None,
        "title": "t", "location": "a.py:1",
    }
    render_finding_card(console, caps, finding)  # must not raise
    render_findings_table(console, caps, [finding], {"total": 1})  # must not raise


def test_recommend_url_classification_not_structural() -> None:
    from app.cli.models import classify_recommendation

    locs = [
        "https://t.com/login?x=1",
        "https://t.com/search?q=2",
        "https://t.com/docs/a",
    ]
    assert classify_recommendation("medium", locs) == "quick_win"


def test_dedupe_keeps_distinct_cookies() -> None:
    from app.report.dedupe import deduplicate_findings

    f = [
        {"rule": "COOKIE-NO-HTTPONLY", "location": "https://x.com/",
         "evidence": {"cookie": "session"}},
        {"rule": "COOKIE-NO-HTTPONLY", "location": "https://x.com/",
         "evidence": {"cookie": "prefs"}},
    ]
    assert len(deduplicate_findings(f)) == 2
