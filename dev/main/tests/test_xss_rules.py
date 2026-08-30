"""Hermetic tests for XSS rules (feature PRD: instruction/feature/xss-detection.md).

Covers per-rule positive/negative cases, false-positive guards, engine
integration with scan_types, and file-type distribution.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.engines.program_engine import run_program_scan
from app.program import xss_rules


def rules_of(findings: list) -> set[str]:
    return {f.rule for f in findings}


# =============================================================================
# XS001 — innerHTML
# =============================================================================

def test_xs001_innerhtml_dynamic(tmp_path: Path) -> None:
    src = "el.innerHTML = location.hash.slice(1);\n"
    findings = xss_rules.analyze_js_file(tmp_path / "a.js", src, "s1")
    assert "XS001" in rules_of(findings)
    assert findings[0].severity.value == "high"


def test_xs001_negative_static_and_sanitized(tmp_path: Path) -> None:
    src = (
        'el.innerHTML = "<b>static</b>";\n'
        "x.innerHTML = DOMPurify.sanitize(input);\n"
    )
    findings = xss_rules.analyze_js_file(tmp_path / "a.js", src, "s1")
    assert "XS001" not in rules_of(findings)


# =============================================================================
# XS002 — document.write
# =============================================================================

def test_xs002_document_write(tmp_path: Path) -> None:
    src = "document.write(userInput);\n"
    findings = xss_rules.analyze_js_file(tmp_path / "a.js", src, "s1")
    assert "XS002" in rules_of(findings)


def test_xs002_negative_literal(tmp_path: Path) -> None:
    src = 'document.write("<p>hello</p>");\n'
    findings = xss_rules.analyze_js_file(tmp_path / "a.js", src, "s1")
    assert "XS002" not in rules_of(findings)


# =============================================================================
# XS003 — dangerouslySetInnerHTML
# =============================================================================

def test_xs003_react_sink(tmp_path: Path) -> None:
    src = "<C dangerouslySetInnerHTML={{__html: html}} />\n"
    findings = xss_rules.analyze_js_file(tmp_path / "a.jsx", src, "s1")
    assert "XS003" in rules_of(findings)


def test_xs003_negative_literal(tmp_path: Path) -> None:
    src = 'const props = { dangerouslySetInnerHTML: { __html: "<b>ok</b>" } };\n'
    findings = xss_rules.analyze_js_file(tmp_path / "a.jsx", src, "s1")
    assert "XS003" not in rules_of(findings)


# =============================================================================
# XS004 — eval / new Function
# =============================================================================

def test_xs004_eval_and_function(tmp_path: Path) -> None:
    src = "eval(userInput);\nnew Function(payload);\n"
    findings = xss_rules.analyze_js_file(tmp_path / "a.js", src, "s1")
    assert rules_of(findings) == {"XS004"}
    assert len(findings) == 2
    assert findings[0].severity.value == "critical"


# =============================================================================
# XS005 — v-html
# =============================================================================

def test_xs005_vue_directive(tmp_path: Path) -> None:
    src = '<span v-html="userContent"></span>\n'
    findings = xss_rules.analyze_html_file(tmp_path / "t.html", src, "s1")
    assert "XS005" in rules_of(findings)


def test_xs005_negative_interpolation(tmp_path: Path) -> None:
    src = "<p>{{ safeText }}</p>\n"
    findings = xss_rules.analyze_html_file(tmp_path / "t.html", src, "s1")
    assert findings == []


# =============================================================================
# XS006 — PHP echo superglobals
# =============================================================================

def test_xs006_echo_superglobal(tmp_path: Path) -> None:
    src = 'echo $_GET["q"];\nprint $row[$_POST["name"]];\n'
    findings = xss_rules.analyze_php_xss_file(tmp_path / "a.php", src, "s1")
    assert "XS006" in rules_of(findings)


def test_xs006_negative_escaped_line(tmp_path: Path) -> None:
    src = 'echo htmlspecialchars($_GET["q"]);\necho htmlentities($_POST["n"]);\n'
    findings = xss_rules.analyze_php_xss_file(tmp_path / "a.php", src, "s1")
    assert findings == []


def test_xs006_negative_non_superglobal(tmp_path: Path) -> None:
    src = 'echo $local["k"];\n'
    findings = xss_rules.analyze_php_xss_file(tmp_path / "a.php", src, "s1")
    assert findings == []


# =============================================================================
# XS007 — Jinja |safe
# =============================================================================

def test_xs007_safe_filter(tmp_path: Path) -> None:
    src = "body = render(value|safe)\n"
    findings = xss_rules.analyze_py_html_file(tmp_path / "a.py", src, "s1")
    assert "XS007" in rules_of(findings)


def test_xs007_negative_commented(tmp_path: Path) -> None:
    src = "# value|safe in a comment\n"
    findings = xss_rules.analyze_py_html_file(tmp_path / "a.py", src, "s1")
    assert findings == []


# =============================================================================
# XS008 — python HTML composition
# =============================================================================

def test_xs008_fstring_html(tmp_path: Path) -> None:
    src = 'tpl = f"<div>{name}</div>"\n'
    findings = xss_rules.analyze_py_html_file(tmp_path / "a.py", src, "s1")
    assert "XS008" in rules_of(findings)
    assert findings[0].severity.value == "medium"


def test_xs008_percent_format(tmp_path: Path) -> None:
    src = 'greet = "<p>%s</p>" % username\n'
    findings = xss_rules.analyze_py_html_file(tmp_path / "a.py", src, "s1")
    assert "XS008" in rules_of(findings)


def test_xs008_negative_static_html(tmp_path: Path) -> None:
    src = 'static_html = "<div>hello</div>"\n'
    findings = xss_rules.analyze_py_html_file(tmp_path / "a.py", src, "s1")
    assert findings == []


# =============================================================================
# Engine integration & scan_types
# =============================================================================

@pytest.fixture
def mixed_tree(tmp_path: Path) -> Path:
    (tmp_path / "vuln.py").write_text(
        'def v(request):\n    x = f"<b>{name}</b>"\n'
        "    return Invoice.objects.get(id=request.GET['id'])\n"
    )
    (tmp_path / "vuln.js").write_text("el.innerHTML = location.hash;\n")
    (tmp_path / "vuln.php").write_text('echo $_GET["q"];\n')
    return tmp_path


def test_engine_reports_both_categories(mixed_tree: Path) -> None:
    result = run_program_scan("python", mixed_tree, "s1")
    rules = {f.rule for f in result["findings"]}
    assert "XS008" in rules  # xss pass runs
    assert "CY001" in rules  # idor pass still runs


def test_engine_scan_types_backward_compatible(mixed_tree: Path) -> None:
    idor_only = run_program_scan("python", mixed_tree, "s1", scan_types=["idor"])
    assert rules_of(idor_only["findings"]) and "XS008" not in rules_of(
        idor_only["findings"]
    )

    xss_only = run_program_scan("python", mixed_tree, "s1", scan_types=["xss"])
    rules = rules_of(xss_only["findings"])
    assert "XS008" in rules and "CY001" not in rules


def test_engine_js_tree_xss_detection(tmp_path: Path) -> None:
    (tmp_path / "vuln.js").write_text(
        "el.innerHTML = location.hash;\ndocument.write(data);\neval(x);\n"
    )
    result = run_program_scan("js", tmp_path, "s1")
    rules = rules_of(result["findings"])
    assert {"XS001", "XS002", "XS004"} <= rules


def test_engine_php_tree_xss_detection(tmp_path: Path) -> None:
    (tmp_path / "vuln.php").write_text(
        '->where("id", $_GET["q"]);\necho $_POST["k"];\n'
    )
    result = run_program_scan("php", tmp_path, "s1")
    rules = rules_of(result["findings"])
    assert "CY009" in rules and "XS006" in rules


# =============================================================================
# Finding shape parity with IDOR findings
# =============================================================================

def test_xss_finding_shape_matches_idor_contract(tmp_path: Path) -> None:
    src = 'el.innerHTML = location.hash;\n'
    findings = xss_rules.analyze_js_file(tmp_path / "a.js", src, "s1")
    f = findings[0]
    # same contract as IDOR findings (report/html compatible)
    assert f.finding_id.startswith("s1-XS001-")
    assert f.location.endswith("a.js:1")
    assert f.remediation
    assert f.evidence["line"] == 1
    assert f.verification.notes == "xss regex heuristic"
