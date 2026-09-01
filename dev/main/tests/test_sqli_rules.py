"""Tests for SQL injection detection — static (SQLI001–SQLI006) + live helpers.

Covers:
  * Python AST rules: execute()/executemany() with f-string/%, Django raw()/
    extra(), SQLAlchemy text(), raw f-string SQL
  * JS regex rules: query/execute with template literals / concatenation
  * PHP regex rules: superglobal input / concatenation into query functions
  * Anti-false-positive: parameterized queries are NOT flagged
  * Live helpers: detect_sql_errors, is_boolean_differential
"""

from __future__ import annotations

from pathlib import Path

from app.program.sqli_rules import (
    analyze_js_sqli,
    analyze_php_sqli,
    analyze_python_sqli,
)


def _rules(findings) -> set[str]:
    return {f.rule for f in findings}


# ---------------------------------------------------------------------------
# Python — execute()/executemany()
# ---------------------------------------------------------------------------

def test_python_execute_fstring_detected() -> None:
    src = (
        "import sqlite3\n"
        "conn = sqlite3.connect('db')\n"
        "cur = conn.cursor()\n"
        "cur.execute(f\"SELECT * FROM users WHERE id = {uid}\")\n"
    )
    rules = _rules(analyze_python_sqli(Path("app.py"), src, "s1"))
    assert "SQLI001" in rules


def test_python_execute_percent_detected() -> None:
    src = 'cur.execute("SELECT * FROM users WHERE id = %s" % uid)\n'
    rules = _rules(analyze_python_sqli(Path("app.py"), src, "s1"))
    assert "SQLI001" in rules


def test_python_execute_parameterized_not_flagged() -> None:
    """Parameterized queries (values passed separately) are safe."""
    src = 'cur.execute("SELECT * FROM users WHERE id = %s", (uid,))\n'
    rules = _rules(analyze_python_sqli(Path("app.py"), src, "s1"))
    assert "SQLI001" not in rules


def test_python_executemany_concat_detected() -> None:
    src = 'cur.executemany("INSERT INTO logs VALUES (" + payload + ")")\n'
    rules = _rules(analyze_python_sqli(Path("app.py"), src, "s1"))
    assert "SQLI001" in rules


# ---------------------------------------------------------------------------
# Python — Django raw()/extra(), SQLAlchemy text()
# ---------------------------------------------------------------------------

def test_python_django_raw_detected() -> None:
    src = 'rows = Invoice.objects.raw(f"SELECT * FROM inv WHERE id = {i}")\n'
    rules = _rules(analyze_python_sqli(Path("models.py"), src, "s1"))
    assert "SQLI002" in rules


def test_python_sqlalchemy_text_detected() -> None:
    src = 'q = text(f"SELECT * FROM p WHERE name = \'{term}\'")\n'
    rules = _rules(analyze_python_sqli(Path("db.py"), src, "s1"))
    assert "SQLI003" in rules


def test_python_raw_fstring_sql_detected() -> None:
    """Raw f-string SQL stored in a variable (SQLI006)."""
    src = 'sql = f"SELECT secret FROM flags WHERE token = \'{tok}\'"\n'
    rules = _rules(analyze_python_sqli(Path("app.py"), src, "s1"))
    assert "SQLI006" in rules


def test_python_constant_sql_not_flagged() -> None:
    src = 'cur.execute("SELECT * FROM users")\n'
    rules = _rules(analyze_python_sqli(Path("app.py"), src, "s1"))
    assert not rules


# ---------------------------------------------------------------------------
# JS
# ---------------------------------------------------------------------------

def test_js_template_literal_sql_detected() -> None:
    src = (
        "const rows = await db.query(\n"
        "  `SELECT * FROM users WHERE id = ${userId}`\n"
        ");\n"
    )
    rules = _rules(analyze_js_sqli(Path("app.js"), src, "s1"))
    assert "SQLI004" in rules


def test_js_concat_sql_detected() -> None:
    src = 'const sql = "SELECT * FROM users WHERE id = " + userId;'
    rules = _rules(analyze_js_sqli(Path("app.js"), src, "s1"))
    assert "SQLI004" in rules


# ---------------------------------------------------------------------------
# PHP
# ---------------------------------------------------------------------------

def test_php_superglobal_sql_detected() -> None:
    src = (
        "$result = mysqli_query($conn, "
        "\"SELECT * FROM users WHERE id = \" . $_GET['id']);"
    )
    rules = _rules(analyze_php_sqli(Path("app.php"), src, "s1"))
    assert "SQLI005" in rules


def test_php_pdo_query_interpolation_detected() -> None:
    src = (
        "$stmt = $pdo->query("
        "\"SELECT * FROM orders WHERE id = {$_REQUEST['id']}\");"
    )
    rules = _rules(analyze_php_sqli(Path("app.php"), src, "s1"))
    assert "SQLI005" in rules


# ---------------------------------------------------------------------------
# Live SQLi helpers
# ---------------------------------------------------------------------------

def test_detect_sql_errors_mysql() -> None:
    from app.engines.live_sqli import detect_sql_errors

    body = "You have an error in your SQL syntax near '1'' at line 1"
    assert "mysql" in detect_sql_errors(body)


def test_detect_sql_errors_postgres() -> None:
    from app.engines.live_sqli import detect_sql_errors

    body = "PostgreSQL ERROR: syntax error at or near \"--\""
    assert "postgres" in detect_sql_errors(body)


def test_detect_sql_errors_oracle() -> None:
    from app.engines.live_sqli import detect_sql_errors

    body = "ORA-01756: quoted string not properly terminated"
    assert "oracle" in detect_sql_errors(body)


def test_detect_sql_errors_none() -> None:
    from app.engines.live_sqli import detect_sql_errors

    assert detect_sql_errors("<html>ok</html>") == []


def test_boolean_differential() -> None:
    from app.engines.live_sqli import is_boolean_differential

    # True branch: rows present → big body; False branch: no rows → small body
    big = "<html>" + "A" * 500 + "</html>"
    small = "<html>no rows</html>"
    assert is_boolean_differential(big, small) is True
    assert is_boolean_differential(big, big) is False
