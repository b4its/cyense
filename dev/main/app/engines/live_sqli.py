"""Live SQL injection detection for fetched pages / probed URLs.

Works alongside the live XSS module: for each HTML page with query
parameters (and the discovered ID-bearing endpoints), sends **SQLi probe
payloads** via GET and looks for:

  * SQL error signatures leaked in the response (error-based detection)
  * abnormal response sizes / status changes between boolean probes
    (``' AND 1=1`` vs ``' AND 1=2``) — a light boolean-differential check

Detection is **read-only** (GET only) and deterministic — no DB mutation,
no stacked statements, no data exfiltration. Payloads are the industry
standard test vectors.
"""

from __future__ import annotations

import re

# SQLi probe payloads (GET-safe, non-destructive).
SQLI_PAYLOADS: list[tuple[str, str]] = [
    ("'", "single-quote"),
    ('"', "double-quote"),
    ("' OR '1'='1", "boolean-tautology"),
    ("' OR '1'='1' --", "comment-tautology"),
    ("' UNION SELECT NULL --", "union-null"),
    ("' AND 1=1 --", "and-true"),
    ("' AND 1=2 --", "and-false"),
    ("1' ORDER BY 1 --", "order-by-1"),
    ("1' ORDER BY 999 --", "order-by-exhaust"),
    ("1 AND 1=1", "int-tautology"),
    ("1 AND 1=2", "int-contradiction"),
]

# SQL engine error signatures commonly leaked by vulnerable apps.
SQL_ERROR_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            r"SQL syntax.*MySQL|MySQLSyntaxErrorException|valid MySQL result",
            re.I,
        ),
        "mysql",
    ),
    (
        re.compile(
            r"PostgreSQL.*(ERROR|syntax)|valid PostgreSQL result|pg_query\(\)",
            re.I,
        ),
        "postgres",
    ),
    (
        re.compile(r"ORA-\d{5}|Oracle error|OracleDatabaseException", re.I),
        "oracle",
    ),
    (
        re.compile(r"SQLite(JDB|\.|_)Exception|unrecognized token|near \"", re.I),
        "sqlite",
    ),
    (
        re.compile(
            r"Unclosed quotation mark|\[SQL Server\]|Microsoft OLE DB|SqlException",
            re.I,
        ),
        "mssql",
    ),
    (
        re.compile(r"SQLSTATE|DB2 SQL error|ibm_db_dbi", re.I),
        "db2",
    ),
    (
        re.compile(r"mysql_fetch|You have an error in your SQL syntax|mysqli_", re.I),
        "mysql",
    ),
    (
        re.compile(
            r"Syntax error.*(?:query|SQL)|QUERY FAILED|PDOException.*SQLSTATE",
            re.I,
        ),
        "generic",
    ),
]

# Length delta threshold for the boolean-differential check (bytes).
_BOOL_DIFF_THRESHOLD = 150


def detect_sql_errors(body: str) -> list[str]:
    """Return SQL-engine names whose error signature appears in ``body``."""
    if not body:
        return []
    hits: list[str] = []
    for pattern, engine in SQL_ERROR_PATTERNS:
        if pattern.search(body):
            hits.append(engine)
    return hits


def is_boolean_differential(true_body: str, false_body: str) -> bool:
    """Return True if two responses differ enough to suggest boolean-based SQLi.

    ``true``/``false`` bodies come from probing the same param with
    ``' AND 1=1`` vs ``' AND 1=2``. A meaningful size/shape difference while
    both stay HTTP 200 is the classic blind-boolean signal.
    """
    if not true_body or not false_body:
        return False
    diff = abs(len(true_body) - len(false_body))
    return diff >= _BOOL_DIFF_THRESHOLD


def _snippet(body: str, needle: str, width: int = 120) -> str:
    idx = body.find(needle)
    if idx == -1:
        return body[:width]
    return body[max(idx - 40, 0):idx + width][:200]
