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
    assert len(catalog) >= 40
    assert {c["rule"] for c in catalog} >= {
        "DES001", "CRYPTO001", "PW001", "PROC001", "XXE001", "TRAN001",
        "CSV001", "FILE001", "RACE001", "ELI001", "NUM001", "SESS002",
        "AUTH001", "EXT001", "RES001", "FIN001",
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


def test_return_in_finally_detected(tmp_path: Path) -> None:
    (tmp_path / "f.py").write_text(
        "def foo():\n"
        "    try:\n"
        "        return 1\n"
        "    finally:\n"
        "        return 2\n"
    )
    result = run_program_scan("python", tmp_path, "s1")
    assert "FIN001" in rules_of(result["findings"])


def test_resource_leak_detected_and_with_suppressed(tmp_path: Path) -> None:
    leak_dir = tmp_path / "leak"
    safe_dir = tmp_path / "safe"
    leak_dir.mkdir()
    safe_dir.mkdir()
    (leak_dir / "leak.py").write_text(
        "def f():\n    h = open('/tmp/x')\n    return h.read()\n"
    )
    (safe_dir / "safe.py").write_text(
        "def f():\n    with open('/tmp/x') as h:\n        return h.read()\n"
    )
    leak = {f.rule for f in run_program_scan("python", leak_dir, "s1")["findings"]}
    safe = {f.rule for f in run_program_scan("python", safe_dir, "s1")["findings"]}
    assert "RES001" in leak
    assert "RES001" not in safe


def test_el_auth_ext_detection(tmp_path: Path) -> None:
    (tmp_path / "vuln.js").write_text(
        "const t = `" + "${req.query.name}" + "`;\n"
        "fetch(userUrl);\n"
    )
    (tmp_path / "vuln.php").write_text(
        "$role = $_POST['role'];\n"
        "if ($role == 'admin') { grant(); }\n"
    )
    js = rules_of(run_program_scan("js", tmp_path, "s1")["findings"])
    assert "ELI001" in js
    php = rules_of(run_program_scan("php", tmp_path, "s1")["findings"])
    assert "AUTH001" in php
