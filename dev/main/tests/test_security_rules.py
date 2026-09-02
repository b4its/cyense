"""Tests for the CWE-broad security rule class (app/program/security_rules.py).

Covers detection, finding shape, language gating, and catalog exposure.
"""

from __future__ import annotations

from pathlib import Path

from app.engines.program_engine import run_program_scan
from app.program import security_rules


def rules_of(findings: list) -> set[str]:
    return {getattr(f, "rule", None) or f.get("rule") for f in findings}


def test_catalog_present_and_cwe_tagged() -> None:
    catalog = security_rules.security_rule_catalog()
    assert len(catalog) >= 30
    assert {c["rule"] for c in catalog} >= {
        "DES001", "CRYPTO001", "PW001", "PROC001", "XXE001", "TRAN001",
        "CSV001", "FILE001", "RACE001",
    }
    # every rule carries a CWE id and severity
    assert all(c["cwe"].startswith("CWE-") for c in catalog)
    assert all(c["severity"] in ("critical", "high", "medium", "low") for c in catalog)


def test_python_security_detection(tmp_path: Path) -> None:
    (tmp_path / "vuln.py").write_text(
        "import hashlib, pickle, os\n"
        "from flask import request\n"
        "password = 'hunter2secret'\n"
        "data = pickle.loads(request.data)\n"
        "os.system('ping ' + request.args['host'])\n"
        "m = hashlib.md5(b'x')\n"
    )
    result = run_program_scan("python", tmp_path, "s1")
    rules = rules_of(result["findings"])
    assert {"DES001", "CRYPTO001", "PROC001", "PW001"} <= rules


def test_php_and_js_detection(tmp_path: Path) -> None:
    (tmp_path / "vuln.php").write_text(
        "$obj = unserialize($_POST['data']);\n"
        "include $_GET['page'];\n"
    )
    (tmp_path / "vuln.js").write_text(
        "const x = eval(req.query.code);\n"
        "http.get('http://api.example/token=x');\n"
    )
    php = run_program_scan("php", tmp_path, "s1")
    assert {"DES002", "PATH001"} <= rules_of(php["findings"])

    js = run_program_scan("js", tmp_path, "s1")
    assert {"DATA001", "TRAN001"} <= rules_of(js["findings"])


def test_results_are_finding_objects(tmp_path: Path) -> None:
    (tmp_path / "vuln.py").write_text("import pickle\npickle.loads(x)\n")
    result = run_program_scan("python", tmp_path, "s1")
    for f in result["findings"]:
        # finding objects (not plain dicts) expose attribute access
        assert hasattr(f, "rule") and hasattr(f, "severity")
        assert f.cwe.startswith("CWE-")


def test_rule_ids_unique_and_path_scoped(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("import pickle\npickle.loads(x)\n")
    (tmp_path / "b.py").write_text("import pickle\npickle.loads(x)\n")
    result = run_program_scan("python", tmp_path, "s1")
    ids = [f.finding_id for f in result["findings"]]
    assert len(ids) == len(set(ids))
