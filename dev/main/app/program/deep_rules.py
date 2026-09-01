"""Deep analysis rules — run only at high/max scan levels.

These rules perform more expensive analysis than the standard rule set:

  * **Data flow tracking** (CY011, XS010): trace user input through
    local variables and into sinks (DB queries, eval, network requests).
  * **Context-aware analysis** (CY012): look at route decorators and
    auth guards to find endpoints that access user data without auth.
  * **Cross-file analysis** (CY013, XS011): inspect imports and call
    graphs across files — only at ``max`` level.

All rules here are gated via :data:`app.engines.scan_levels.LEVEL_RULE_REQUIREMENTS`.
The dispatcher in :mod:`app.engines.program_engine` calls
``analyze_deep_idor()`` / ``analyze_deep_xss()`` and the profile's
``should_run_rule()`` decides per-rule whether to execute.

The interface intentionally mirrors the existing ``analyze_python_file``
and friends (path, source, scan_id) plus the level profile. Findings are
returned as plain dicts for consistency with the rest of the engine;
callers may wrap them in ``Finding`` if they need Pydantic validation.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

# Common Django/Flask/FastAPI request attribute names.
_REQUEST_ATTRS = frozenset({
    "GET", "POST", "args", "form", "data", "json", "query_params",
    "path_params", "values", "params", "FILES",
})


def _finding(
    rule: str,
    severity: str,
    path: Path,
    line: int,
    title: str,
    description: str,
    remediation: str,
    scan_id: str = "",
    evidence: dict | None = None,
    cwe: str | None = None,
    confidence: float = 0.80,
) -> dict[str, Any]:
    finding_id = f"{scan_id}-{rule}-{line}" if (scan_id and line) else f"{scan_id}-{rule}"
    return {
        "finding_id": finding_id,
        "rule": rule,
        "severity": severity,
        "confidence": confidence,
        "title": title,
        "description": description,
        "evidence": evidence or {"file": str(path), "line": line},
        "remediation": remediation,
        "location": f"{path}:{line}" if line else str(path),
        "cwe": cwe,
    }


# ---------------------------------------------------------------------------
# CY011 — Data-flow IDOR
# ---------------------------------------------------------------------------

_DB_SINK_PATTERNS = (
    r"\.objects\.get\s*\(",
    r"\.objects\.filter\s*\(",
    r"\.objects\.exclude\s*\(",
    r"get_object_or_404\s*\(",
    r"\.find_one\s*\(",
    r"\.find\s*\(",
    r"\.findOne\s*\(",
    r"\.findById\s*\(",
    r"\.where\s*\(",
)
_DB_SINK_RE = re.compile("|".join(_DB_SINK_PATTERNS))

# Function-scoped ownership indicators (kwarg names or attribute reads).
_OWNERSHIP_HINTS = frozenset({
    "user_id", "owner_id", "user", "owner", "created_by", "account_id",
    "author_id", "tenant_id", "organization_id", "request.user",
    "current_user",
})


def _is_request_access(node: ast.AST) -> bool:
    """True when ``node`` reads from the request object (request.GET[...], etc.)."""
    if isinstance(node, ast.Attribute):
        if node.attr in _REQUEST_ATTRS and isinstance(node.value, ast.Name):
            if node.value.id == "request":
                return True
    if isinstance(node, ast.Subscript):
        return _is_request_access(node.value)
    return False


def _request_vars_in_function(func: ast.FunctionDef | ast.AsyncFunctionDef) -> dict[str, int]:
    """Map local-name -> assignment lineno for locals assigned from request."""
    result: dict[str, int] = {}
    for node in ast.walk(func):
        if not isinstance(node, ast.Assign):
            continue
        # Check the RHS for request access
        if not _has_request_access(node.value):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name):
                result[target.id] = node.lineno
    return result


def _has_request_access(node: ast.AST) -> bool:
    for sub in ast.walk(node):
        if _is_request_access(sub):
            return True
    return False


def _call_has_ownership(call: ast.Call) -> bool:
    """True if a DB call already scopes by an ownership hint."""
    for kw in call.keywords:
        if kw.arg and kw.arg.lower() in _OWNERSHIP_HINTS:
            return True
    # Heuristic: `user=request.user` as positional is rare; look in source.
    src = ast.unparse(call) if hasattr(ast, "unparse") else ""
    return any(h in src for h in ("user_id=", "owner_id=", "request.user", "current_user"))


def _mentions_tracked_var(node: ast.AST, tracked: set[str]) -> bool:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name) and sub.id in tracked:
            return True
    return False


def _check_cy011(tree: ast.AST, path: Path, scan_id: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        tracked = set(_request_vars_in_function(node))
        if not tracked:
            continue
        # Also track direct `request.X` usage by looking for Attribute nodes.
        for sub in ast.walk(node):
            if not isinstance(sub, ast.Call):
                continue
            if not _DB_SINK_RE.search(ast.unparse(sub) if hasattr(ast, "unparse") else ""):
                continue
            if _call_has_ownership(sub):
                continue
            # Did the call use a tracked var or request.* directly?
            args_source_user = _mentions_tracked_var(sub, tracked) or _has_request_access(sub)
            if not args_source_user:
                continue
            line = getattr(sub, "lineno", 0)
            src = ast.unparse(sub) if hasattr(ast, "unparse") else "<unparseable>"
            findings.append(_finding(
                rule="CY011",
                severity="high",
                path=path,
                line=line,
                title="Data-flow IDOR: user input flows into DB query without ownership",
                description=(
                    f"Function `{node.name}` receives user input (via request.* "
                    f"or a local assigned from it) and passes it into `{src}` "
                    f"without an ownership filter. An attacker who controls the "
                    f"input can fetch arbitrary rows."
                ),
                remediation=(
                    "Scope the lookup by the authenticated user "
                    "(e.g. `.filter(user_id=request.user.id, id=...)`), or "
                    "verify `obj.owner_id == current_user.id` after retrieval."
                ),
                scan_id=scan_id,
                evidence={
                    "file": str(path),
                    "line": line,
                    "function": node.name,
                    "sink_call": src[:200],
                    "tracked_vars": sorted(tracked)[:5],
                },
                cwe="CWE-639",
            ))
    return findings


# ---------------------------------------------------------------------------
# CY012 — Unauthenticated endpoint accessing user data
# ---------------------------------------------------------------------------

_AUTH_DECORATORS = frozenset({
    "login_required", "authenticated", "requires_auth", "auth_required",
    "permission_required", "permission_classes", "IsAuthenticated",
    "jwt_required", "token_required", "require_user", "authorize",
    "current_user", "get_current_user", "Depends",
})
_ROUTE_DECORATORS = frozenset({
    "route", "get", "post", "put", "delete", "patch", "api_view", "action",
})
_USER_MODELS = frozenset({
    "User", "Profile", "Account", "Customer", "Member", "Patient", "Student",
    "Employee", "Staff",
})


def _decorator_name(dec: ast.expr) -> str | None:
    if isinstance(dec, ast.Call):
        return _decorator_name(dec.func)
    if isinstance(dec, ast.Name):
        return dec.id
    if isinstance(dec, ast.Attribute):
        return dec.attr
    return None


def _function_has_auth(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for dec in func.decorator_list:
        name = _decorator_name(dec)
        if name and name in _AUTH_DECORATORS:
            return True
    # FastAPI `Depends(...)` inside a parameter default
    for arg in list(func.args.args) + list(func.args.kwonlyargs):
        if arg.annotation and _has_name(arg.annotation, "Depends"):
            return True
    return False


def _has_name(node: ast.AST, name: str) -> bool:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name) and sub.id == name:
            return True
        if isinstance(sub, ast.Call):
            if isinstance(sub.func, ast.Name) and sub.func.id == name:
                return True
    return False


def _function_is_route(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for dec in func.decorator_list:
        name = _decorator_name(dec)
        if name and name in _ROUTE_DECORATORS:
            return True
    return False


def _function_accesses_user_data(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for sub in ast.walk(func):
        if not isinstance(sub, ast.Call):
            continue
        src = ast.unparse(sub) if hasattr(ast, "unparse") else ""
        if not (".objects" in src or ".find" in src or ".where" in src):
            continue
        if any(model in src for model in _USER_MODELS):
            return True
    return False


def _function_reads_request(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for sub in ast.walk(func):
        if _is_request_access(sub):
            return True
    return False


def _check_cy012(tree: ast.AST, path: Path, scan_id: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not _function_is_route(node):
            continue
        if _function_has_auth(node):
            continue
        if not (_function_reads_request(node) and _function_accesses_user_data(node)):
            continue
        findings.append(_finding(
            rule="CY012",
            severity="high",
            path=path,
            line=node.lineno,
            title="Unauthenticated endpoint accesses user-specific data",
            description=(
                f"Route `{node.name}` accepts request input and queries a "
                f"user-specific model without any visible authentication or "
                f"authorization guard."
            ),
            remediation=(
                "Add an auth decorator (`@login_required`, `@jwt_required`, "
                "`Depends(get_current_user)`) and scope the query by the "
                "authenticated user."
            ),
            scan_id=scan_id,
            evidence={
                "file": str(path),
                "line": node.lineno,
                "function": node.name,
                "decorators": [
                    _decorator_name(d) or ast.unparse(d) for d in node.decorator_list
                ][:5],
            },
            cwe="CWE-306",
        ))
    return findings


# ---------------------------------------------------------------------------
# XS009 — document.cookie leaked to external origins
# ---------------------------------------------------------------------------

_COOKIE_LEAK_PATTERNS = [
    (r"fetch\s*\([^)]*\bdocument\.cookie\b", "fetch() carrying document.cookie"),
    (r"\.send\s*\([^)]*\bdocument\.cookie\b", "XHR.send() carrying document.cookie"),
    (r"navigator\.sendBeacon\s*\([^)]*\bdocument\.cookie\b",
     "navigator.sendBeacon() carrying document.cookie"),
    (r"(?:location\.href|location\.assign)\s*=\s*[^;]*\bdocument\.cookie\b",
     "navigation URL including document.cookie"),
]


def _check_xs009(source: str, path: Path, scan_id: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for pattern, desc in _COOKIE_LEAK_PATTERNS:
        for match in re.finditer(pattern, source, re.I | re.S):
            line_no = source[:match.start()].count("\n") + 1
            findings.append(_finding(
                rule="XS009",
                severity="high",
                path=path,
                line=line_no,
                title=f"document.cookie leaked via {desc}",
                description=(
                    f"Cookies are included in a {desc.split('(')[0].strip()} call "
                    f"which can send them to attacker-controlled origins."
                ),
                remediation=(
                    "Never pass `document.cookie` to network APIs. If the server "
                    "needs a session identifier, let it read the cookie header "
                    "itself; do not echo it into JS."
                ),
                scan_id=scan_id,
                evidence={
                    "file": str(path),
                    "line": line_no,
                    "snippet": match.group(0)[:200],
                },
                cwe="CWE-200",
                confidence=0.85,
            ))
    return findings


# ---------------------------------------------------------------------------
# XS010 — eval/exec of user-controlled input (data flow)
# ---------------------------------------------------------------------------

_DANGEROUS_EVAL_FUNCS = frozenset({"eval", "exec", "compile"})


def _check_xs010(tree: ast.AST, path: Path, scan_id: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        tracked = set(_request_vars_in_function(node))
        if not tracked:
            continue
        for sub in ast.walk(node):
            if not isinstance(sub, ast.Call):
                continue
            if not (isinstance(sub.func, ast.Name) and sub.func.id in _DANGEROUS_EVAL_FUNCS):
                continue
            # Did any argument come from request data (directly or via tracked var)?
            user_controlled = False
            for arg in sub.args + [kw.value for kw in sub.keywords]:
                if _has_request_access(arg) or _mentions_tracked_var(arg, tracked):
                    user_controlled = True
                    break
            if not user_controlled:
                continue
            line = getattr(sub, "lineno", 0)
            findings.append(_finding(
                rule="XS010",
                severity="critical",
                path=path,
                line=line,
                title=f"{sub.func.id}() called with user-controlled input (data flow)",
                description=(
                    f"`{sub.func.id}()` at line {line} executes a value that "
                    f"traces back to `request.*`. An attacker who controls the "
                    f"request can achieve arbitrary code execution."
                ),
                remediation=(
                    "Replace eval/exec with a safe parser (ast.literal_eval, "
                    "json.loads, schema validators). Never execute "
                    "request-supplied strings."
                ),
                scan_id=scan_id,
                evidence={
                    "file": str(path),
                    "line": line,
                    "function": node.name,
                    "call": sub.func.id,
                    "tracked_vars": sorted(tracked)[:5],
                },
                cwe="CWE-95",
                confidence=0.90,
            ))
    return findings


# ---------------------------------------------------------------------------
# CY013 / XS011 — Cross-file analysis (max level only)
# ---------------------------------------------------------------------------
#
# True cross-file analysis needs import resolution and a call graph, which
# requires loading many files. To keep this tractable within one scan we do
# a lightweight, *per-file* proxy of cross-file analysis: any function that
# imports a helper and then forwards a request-derived value into it is
# flagged as a potential cross-file IDOR/XSS, with a recommendation to
# audit the helper's definition.
#
# This is not a full call graph but it catches the common "thin view that
# delegates to a service function" pattern without the cost of building
# a whole-program graph.

_IMPORT_RE = re.compile(
    r"^\s*(?:from\s+[\w.]+\s+import\s+"
    r"\(?\s*([\w\s,]+)\s*\)?"  # handle parens: from x import (a, b)
    r"|import\s+([\w.]+(?:\s+as\s+\w+)?))",
    re.M,
)


def _check_cy013(tree: ast.AST, source: str, path: Path, scan_id: str) -> list[dict[str, Any]]:
    """Thin-view IDOR: route forwards request input into an imported helper."""
    findings: list[dict[str, Any]] = []
    # Collect imported names
    imported: set[str] = set()
    for match in _IMPORT_RE.finditer(source):
        names_part = match.group(1) or ""
        for chunk in names_part.split(","):
            name = chunk.strip().split(" as ")[0].strip()
            if name:
                imported.add(name)
        module_part = match.group(2) or ""
        if module_part:
            imported.add(module_part.split(".")[-1])
    if not imported:
        return findings

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not _function_is_route(node):
            continue
        tracked = set(_request_vars_in_function(node))
        has_request = _has_request_access(node)  # type: ignore[arg-type]
        if not (tracked or has_request):
            continue
        # Look for calls to imported names that receive request data
        for sub in ast.walk(node):
            if not isinstance(sub, ast.Call):
                continue
            callee = None
            if isinstance(sub.func, ast.Name):
                callee = sub.func.id
            elif isinstance(sub.func, ast.Attribute):
                callee = sub.func.attr  # method name, not object name (bug fix)
            if not callee or callee not in imported:
                continue
            args_user_input = False
            for arg in sub.args + [kw.value for kw in sub.keywords]:
                if _has_request_access(arg) or _mentions_tracked_var(arg, tracked):
                    args_user_input = True
                    break
            if not args_user_input:
                continue
            line = getattr(sub, "lineno", 0)
            findings.append(_finding(
                rule="CY013",
                severity="medium",
                path=path,
                line=line,
                title=f"Cross-file IDOR risk: route forwards request input to imported `{callee}`",
                description=(
                    f"Route `{node.name}` passes user input into imported helper "
                    f"`{callee}()`. Without seeing the helper, we cannot confirm "
                    f"whether it enforces an ownership filter."
                ),
                remediation=(
                    f"Audit `{callee}`'s definition to ensure it either scopes "
                    f"DB lookups by the authenticated user or that the caller "
                    f"does so before delegating."
                ),
                scan_id=scan_id,
                evidence={
                    "file": str(path),
                    "line": line,
                    "function": node.name,
                    "helper": callee,
                },
                cwe="CWE-639",
                confidence=0.65,
            ))
    return findings


def _check_xs011(tree: ast.AST, source: str, path: Path, scan_id: str) -> list[dict[str, Any]]:
    """Cross-file XSS: route renders a template using an imported helper with user input."""
    findings: list[dict[str, Any]] = []
    imported: set[str] = set()
    for match in _IMPORT_RE.finditer(source):
        names_part = match.group(1) or ""
        for chunk in names_part.split(","):
            name = chunk.strip().split(" as ")[0].strip()
            if name:
                imported.add(name)
    if not imported:
        return findings

    # Render helpers commonly used to produce HTML
    render_helpers = {"render_template", "render", "render_to_string", "Template", "Markup"}

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not _function_is_route(node):
            continue
        tracked = set(_request_vars_in_function(node))
        for sub in ast.walk(node):
            if not isinstance(sub, ast.Call):
                continue
            callee = None
            if isinstance(sub.func, ast.Name):
                callee = sub.func.id
            elif isinstance(sub.func, ast.Attribute):
                callee = sub.func.attr
            if not callee or callee not in (imported | render_helpers):
                continue
            if callee not in render_helpers:
                continue
            args_user_input = False
            for arg in sub.args + [kw.value for kw in sub.keywords]:
                if _has_request_access(arg) or _mentions_tracked_var(arg, tracked):
                    args_user_input = True
                    break
            if not args_user_input:
                continue
            line = getattr(sub, "lineno", 0)
            findings.append(_finding(
                rule="XS011",
                severity="medium",
                path=path,
                line=line,
                title=f"Cross-file XSS risk: route renders user input via `{callee}`",
                description=(
                    f"Route `{node.name}` renders output through `{callee}()` "
                    f"using request-derived data. Without auto-escaping guarantees "
                    f"in the helper, this is an XSS sink."
                ),
                remediation=(
                    "Ensure the template engine auto-escapes by default "
                    "(Jinja2 does; Django does). Avoid passing raw request "
                    "values into helpers that disable escaping (e.g. `|safe`)."
                ),
                scan_id=scan_id,
                evidence={
                    "file": str(path),
                    "line": line,
                    "function": node.name,
                    "helper": callee,
                },
                cwe="CWE-79",
                confidence=0.60,
            ))
    return findings


# ---------------------------------------------------------------------------
# Public dispatchers called by program_engine
# ---------------------------------------------------------------------------

def analyze_deep_idor(
    path: Path,
    source: str,
    scan_id: str,
    level_profile: Any,
) -> list[dict[str, Any]]:
    """Run CY011/CY012/CY013 as allowed by the active level."""
    findings: list[dict[str, Any]] = []
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return findings

    if level_profile.should_run_rule("CY011"):
        findings.extend(_check_cy011(tree, path, scan_id))
    if level_profile.should_run_rule("CY012"):
        findings.extend(_check_cy012(tree, path, scan_id))
    if level_profile.should_run_rule("CY013"):
        findings.extend(_check_cy013(tree, source, path, scan_id))
    return findings


def analyze_deep_xss(
    path: Path,
    source: str,
    scan_id: str,
    level_profile: Any,
    lang: str,
) -> list[dict[str, Any]]:
    """Run XS009/XS010/XS011 as allowed by the active level and language."""
    findings: list[dict[str, Any]] = []

    # XS009 is JS-only (browser document.cookie)
    if lang == "js" and level_profile.should_run_rule("XS009"):
        findings.extend(_check_xs009(source, path, scan_id))

    # XS010 is Python-only (eval/exec/compile)
    if lang == "python" and level_profile.should_run_rule("XS010"):
        try:
            tree = ast.parse(source)
        except SyntaxError:
            tree = None
        if tree is not None:
            findings.extend(_check_xs010(tree, path, scan_id))

    # XS011 is Python-only (template rendering via imported helpers)
    if lang == "python" and level_profile.should_run_rule("XS011"):
        try:
            tree = ast.parse(source)
        except SyntaxError:
            tree = None
        if tree is not None:
            findings.extend(_check_xs011(tree, source, path, scan_id))

    return findings
