"""Unit tests for AST rules CY001–CY006 and regex rules CY007+."""

from __future__ import annotations

from pathlib import Path

from app.program.python_rules import analyze_python_file
from app.program.regex_rules import analyze_js_file, analyze_php_file


def _scan(tmp_path: Path, code: str) -> set[str]:
    f = tmp_path / "sample.py"
    f.write_text(code)
    findings = analyze_python_file(f, code, "s1")
    return {x.rule for x in findings}


def test_cy001_django_unscoped_get(tmp_path) -> None:
    code = (
        "def view(request):\n"
        "    inv = Invoice.objects.get(id=request.GET['id'])\n"
        "    return inv\n"
    )
    assert "CY001" in _scan(tmp_path, code)


def test_cy001_skipped_when_ownership_present(tmp_path) -> None:
    code = (
        "def view(request):\n"
        "    inv = Invoice.objects.get(id=request.GET['id'], user_id=request.user.id)\n"
        "    return inv\n"
    )
    assert "CY001" not in _scan(tmp_path, code)


def test_cy002_filter_first_unscoped(tmp_path) -> None:
    code = (
        "def view(request):\n"
        "    inv = Invoice.objects.filter(id=request.GET['id']).first()\n"
        "    return inv\n"
    )
    assert "CY002" in _scan(tmp_path, code)


def test_cy003_flask_route_int_id(tmp_path) -> None:
    code = (
        "@app.route('/invoice/<int:inv_id>')\n"
        "def invoice(inv_id):\n"
        "    inv = Invoice.objects.get(id=inv_id)\n"
        "    return inv\n"
    )
    assert "CY003" in _scan(tmp_path, code)


def test_cy004_fastapi_path_param(tmp_path) -> None:
    code = (
        "@app.get('/invoice/{invoice_id}')\n"
        "async def read_invoice(invoice_id: int):\n"
        "    inv = Invoice.objects.get(id=invoice_id)\n"
        "    return inv\n"
    )
    assert "CY004" in _scan(tmp_path, code)


def test_cy005_get_object_or_404_unscoped(tmp_path) -> None:
    code = (
        "def view(request):\n"
        "    inv = get_object_or_404(Invoice, pk=request.GET['pk'])\n"
        "    return inv\n"
    )
    assert "CY005" in _scan(tmp_path, code)


def test_cy006_open_with_request_param(tmp_path) -> None:
    code = (
        "def view(request):\n"
        "    f = open(f'/uploads/{request.GET[\"name\"]}')\n"
        "    return f.read()\n"
    )
    assert "CY006" in _scan(tmp_path, code)


def test_clean_code_has_no_findings(tmp_path) -> None:
    code = (
        "from django.contrib.auth.decorators import login_required\n"
        "@login_required\n"
        "def view(request):\n"
        "    inv = Invoice.objects.get(id=request.GET['id'], user_id=request.user.id)\n"
        "    return inv\n"
    )
    assert _scan(tmp_path, code) == set()


def test_cy007_js_findone(tmp_path) -> None:
    code = "app.get('/u', (req, res) => { User.findOne({_id: req.params.id}) })\n"
    f = tmp_path / "app.js"
    f.write_text(code)
    findings = analyze_js_file(f, code, "s1")
    assert any(x.rule == "CY007" for x in findings)


def test_cy009_php_where_superglobal(tmp_path) -> None:
    code = "<?php $u = $db->table('users')->where('id', $_GET['id'])->first();\n"
    f = tmp_path / "app.php"
    f.write_text(code)
    findings = analyze_php_file(f, code, "s1")
    assert any(x.rule == "CY009" for x in findings)
