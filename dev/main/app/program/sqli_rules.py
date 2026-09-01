"""SQL Injection detection rules — static analysis (SQLI001–SQLI006).

Deterministic detection of SQL injection sinks across source code:

  * **SQLI001** (Python, high)  — ``cursor.execute()/executemany()`` with
    f-string / ``%`` / ``format()`` / ``+`` concatenation of request data
  * **SQLI002** (Python, high)  — Django ``Model.objects.raw()`` / ``.extra()``
    with user-controlled formatting
  * **SQLI003** (Python, high)  — SQLAlchemy ``text()`` / ``exec_driver_sql``
    with f-string / ``%`` interpolation
  * **SQLI004** (JS, high)      — ``query()/execute()`` on a template-literal
    or concatenated SQL string built from variables
  * **SQLI005** (PHP, high)     — ``mysqli_query`` / ``pg_query`` /
    ``PDO::query`` receiving a string built with superglobals
    (``$_GET/$_POST/$_REQUEST``) or string concatenation
  * **SQLI006** (all, medium)   — raw ``SELECT/INSERT/UPDATE/DELETE`` string
    interpolating a variable (``f"...{var}"``, ``"...'\" + var + ..."``)

Rules are purely static — the repo code is never executed. Reported findings
use the standard Cyense ``Finding`` shape so they flow through the report,
SARIF, coverage, and remediation pipelines unchanged.

Anti-false-positive guards:
  * parameterized queries (``?`` / ``%s`` placeholders fed via a tuple/args
    parameter) are NOT reported
  * constant SQL strings without interpolation are NOT reported
"""

from __future__ import annotations

import ast
import hashlib
import re
from pathlib import Path

from app.core.models import Finding, Severity, VerificationEvidence

# Python call targets that execute SQL.
_PY_EXEC_FUNCS = {
    "execute": "SQLI001",
    "executemany": "SQLI001",
    "raw": "SQLI002",
    "extra": "SQLI002",
    "text": "SQLI003",
    "exec_driver_sql": "SQLI003",
}

# JS: a SQL keyword followed (within the statement) by interpolation markers
# (template-literal ${} or string concatenation) — the classic JS SQLi shape.
_JS_SQLI_RE = re.compile(
    r"\b(?:SELECT|INSERT|UPDATE|DELETE|WITH)\s+[^;]*?"
    r"(?:\$\{|\"\s*\+|\+\s*\"|'\s*\+|\+\s*')",
    re.I | re.S,
)

# PHP: mysqli/pg/PDO query with superglobal or concatenation
_PHP_SQLI_RE = re.compile(
    r"""(?:mysqli_query|pg_query|pg_exec|->query|->exec|->prepare|exec)\s*\("""
    r"""[^\n]*?(?:\$_(?:GET|POST|REQUEST|COOKIE)\[|\"|')"""
    r"""[^\n]*?(?:SELECT|INSERT|UPDATE|DELETE|WITH)""",
    re.I,
)
_PHP_CONCAT_RE = re.compile(
    r"""(?:SELECT|INSERT|UPDATE|DELETE|WITH)[^;]*?\$\w+[^;]*?"""
    r"""(?:\"\s*\.\s*\$|'\s*\.\s*\$|\{\$|\.\s*\$_)""",
    re.I,
)

# Python: "%s" style formatting with user input passed inline
_PY_PERCENT_SQL_RE = re.compile(
    r"""(?:SELECT|INSERT|UPDATE|DELETE|WITH)[^"'\n]*%[sdqr]""",
    re.I,
)
# SQL keywords used to guard against false positives
_SQL_KEYWORDS_RE = re.compile(
    r"\b(?:SELECT|INSERT|UPDATE|DELETE|WITH|DROP|ALTER|CREATE)\b", re.I
)


def analyze_python_sqli(path: Path, source: str, scan_id: str) -> list[Finding]:
    """Analyze a Python file for SQL injection (returns Finding objects)."""
    return _analyze_python(path, source, scan_id)


def analyze_js_sqli(path: Path, source: str, scan_id: str) -> list[Finding]:
    """Analyze a JS/TS file for SQL injection sinks."""
    return _analyze_js(path, source, scan_id)


def analyze_php_sqli(path: Path, source: str, scan_id: str) -> list[Finding]:
    """Analyze a PHP file for SQL injection sinks."""
    return _analyze_php(path, source, scan_id)


# ---------------------------------------------------------------------------
# Python (AST-based)
# ---------------------------------------------------------------------------

def _analyze_python(path: Path, source: str, scan_id: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return findings

    # Track JoinedStr AST nodes already reported via the execute/raw/text
    # call path so the raw f-string pass (SQLI006) does not double-report.
    reported_joined: set[int] = set()

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = _callee_name(node.func)
        if func is None:
            continue
        rule = _PY_EXEC_FUNCS.get(func)
        if rule is None:
            continue
        # The SQL statement is usually the first positional arg or a keyword.
        sql_arg = _sql_argument(node)
        if sql_arg is None:
            continue
        if _is_unsafe_sql_python(sql_arg):
            line = getattr(node, "lineno", 0)
            findings.append(_finding(
                rule=rule,
                severity=Severity.HIGH,
                confidence=0.75,
                path=path,
                scan_id=scan_id,
                line=line,
                title=f"{func}() with dynamically built SQL",
                description=(
                    f"`{func}(...)` receives SQL constructed from variables "
                    "(f-string / format / % / concatenation). If any part is "
                    "user-controlled, this is a SQL injection sink."
                ),
                remediation=(
                    "Use parameterized queries / prepared statements and pass "
                    "values as separate parameters — never interpolate them "
                    "into the SQL text."
                ),
            ))
            if isinstance(sql_arg, ast.JoinedStr):
                reported_joined.add(id(sql_arg))

    # Raw f-string SQL with interpolation (SQLI006, medium) — catches
    # `sql = f"SELECT ... {var}"` stored in a variable or returned.
    # AST-based: any JoinedStr (f-string) containing formatted values AND a
    # SQL keyword in its constant text is a dynamic-SQL sink.
    for node in ast.walk(tree):
        if not isinstance(node, ast.JoinedStr):
            continue
        if id(node) in reported_joined:
            continue  # already reported via execute/raw/text call
        has_formatted = any(
            isinstance(v, ast.FormattedValue) for v in node.values
        )
        if not has_formatted:
            continue
        const_text = "".join(
            v.value for v in node.values
            if isinstance(v, ast.Constant) and isinstance(v.value, str)
        )
        if _SQL_KEYWORDS_RE.search(const_text):
            line = getattr(node, "lineno", 0)
            findings.append(_finding(
                rule="SQLI006",
                severity=Severity.MEDIUM,
                confidence=0.6,
                path=path,
                scan_id=scan_id,
                line=line,
                title="Raw SQL string interpolating a variable (f-string/format)",
                description=(
                    "A SQL statement is built with an f-string or format "
                    "placeholder. If the interpolated value comes from user input "
                    "this is a SQL injection risk."
                ),
                remediation=(
                    "Pass values to parameterized queries instead of "
                    "interpolating them into the SQL text."
                ),
            ))

    return findings


def _callee_name(func: ast.AST) -> str | None:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _sql_argument(call: ast.Call) -> ast.AST | None:
    if call.args:
        return call.args[0]
    for kw in call.keywords:
        if kw.arg in ("sql", "query", "sql_query", "statement"):
            return kw.value
    return None


def _is_unsafe_sql_python(arg: ast.AST) -> bool:
    """Return True if the SQL arg is built dynamically (f-string, %, concat)."""
    if isinstance(arg, ast.JoinedStr):  # f"SELECT ... {x} ..."
        # A JoinedStr containing non-constant parts is dynamic.
        for value in arg.values:
            if isinstance(value, ast.FormattedValue):
                return True
        return False
    if isinstance(arg, ast.BinOp) and isinstance(arg.op, (ast.Mod, ast.Add)):
        return True  # "SELECT %s" % x   or   "SELECT " + x
    if isinstance(arg, ast.Call):
        # "SELECT %s".format(...)
        if isinstance(arg.func, ast.Attribute) and arg.func.attr == "format":
            return bool(arg.args or arg.keywords)
        return False
    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
        return False  # constant SQL — safe
    # Variable reference to a string that might be built dynamically:
    # flag conservatively (e.g. sql = "SELECT " + q; cursor.execute(sql))
    if isinstance(arg, (ast.Name, ast.Attribute)):
        return True
    return False


# ---------------------------------------------------------------------------
# JS (regex)
# ---------------------------------------------------------------------------

def _analyze_js(path: Path, source: str, scan_id: str) -> list[Finding]:
    findings: list[Finding] = []

    # SQL statement with template literal / concatenation interpolation
    for m in _JS_SQLI_RE.finditer(source):
        line = source.count("\n", 0, m.start()) + 1
        findings.append(_finding(
            rule="SQLI004",
            severity=Severity.HIGH,
            confidence=0.7,
            path=path,
            scan_id=scan_id,
            line=line,
            title="SQL query built with string interpolation / concatenation",
            description=(
                "A SQL statement is assembled with template literals or "
                "concatenation — if any interpolated value is user-controlled "
                "this is a SQL injection sink."
            ),
            remediation=(
                "Use parameterized queries (e.g. `db.query(sql, [params])` or "
                "an ORM) and never concatenate user input into SQL text."
            ),
        ))
        break  # one finding per file is enough for this class

    return findings


# ---------------------------------------------------------------------------
# PHP (regex)
# ---------------------------------------------------------------------------

def _analyze_php(path: Path, source: str, scan_id: str) -> list[Finding]:
    findings: list[Finding] = []

    # superglobal ($_GET/$_POST/...) flowing into a query function
    for m in _PHP_SQLI_RE.finditer(source):
        if not _SQL_KEYWORDS_RE.search(m.group(0)):
            continue
        line = source.count("\n", 0, m.start()) + 1
        findings.append(_finding(
            rule="SQLI005",
            severity=Severity.HIGH,
            confidence=0.75,
            path=path,
            scan_id=scan_id,
            line=line,
            title="SQL query built with superglobal input or concatenation",
            description=(
                "A SQL statement is built with $_GET/$_POST/$_REQUEST or "
                "string concatenation — direct SQL injection vector."
            ),
            remediation=(
                "Use PDO prepared statements with bound parameters; never "
                "concatenate superglobal values into SQL text."
            ),
        ))
        break

    # concatenation of a variable into a SQL literal
    for m in _PHP_CONCAT_RE.finditer(source):
        if not _SQL_KEYWORDS_RE.search(m.group(0)):
            continue
        line = source.count("\n", 0, m.start()) + 1
        findings.append(_finding(
            rule="SQLI005",
            severity=Severity.HIGH,
            confidence=0.65,
            path=path,
            scan_id=scan_id,
            line=line,
            title="SQL string interpolating a PHP variable",
            description=(
                "A SQL literal interpolates a PHP variable via concatenation "
                "or interpolation — potential SQL injection sink."
            ),
            remediation=(
                "Bind values via prepared statements (PDO) instead of "
                "concatenating them into the query."
            ),
        ))
        break

    return findings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _finding(
    *,
    rule: str,
    severity: Severity,
    confidence: float,
    path: Path,
    scan_id: str,
    line: int,
    title: str,
    description: str,
    remediation: str,
) -> Finding:
    disc = hashlib.md5(str(path).encode("utf-8")).hexdigest()[:6]
    return Finding(
        finding_id=f"{scan_id}-{rule}-{line}-{disc}",
        rule=rule,
        severity=severity,
        confidence=confidence,
        title=title,
        description=description,
        evidence={"file": str(path), "line": line},
        verification=VerificationEvidence(notes="static analysis (sql injection)"),
        remediation=remediation,
        location=f"{path}:{line}",
    )
