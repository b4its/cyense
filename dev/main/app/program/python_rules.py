"""AST-based IDOR rules for Python (PRD v2.0 §4.2, CY001–CY006).

Each rule implements the IdorRule protocol: check(node, ctx) -> list[Finding].

Rules detect *unscoped object lookups*: queries keyed only by a
request-supplied id, with no ownership filter and no authorization guard
visible in the enclosing function.
"""

from __future__ import annotations

import ast
import hashlib
from typing import Any

from app.core.models import Finding, Severity, VerificationEvidence

REQUEST_ATTRS = {"request", "self", "session"}
OWNERSHIP_HINTS = {
    "user_id",
    "owner_id",
    "user",
    "owner",
    "created_by",
    "account_id",
    "customer_id",
    "author_id",
}
AUTH_GUARDS = {
    "login_required",
    "permission_required",
    "current_user",
    "get_current_user",
    "Depends",
    "require_user",
    "authorize",
    "is_authenticated",
}


def _finding(
    scan_id: str,
    rule: str,
    severity: Severity,
    path: str,
    node: ast.AST,
    title: str,
    description: str,
    remediation: str,
) -> Finding:
    """Create finding with unique ID including lineno (fixes collision bug)."""

    lineno = getattr(node, "lineno", 0)

    # Include line number AND a stable path discriminator for uniqueness.
    # Without the path, two findings of the same rule at the same line in
    # different files collide (same finding_id → same remediation fix_id,
    # making the second fix unreachable via FixStore.get_proposal).
    path_disc = hashlib.md5(path.encode("utf-8")).hexdigest()[:6]
    if lineno:
        finding_id = f"{scan_id}-{rule}-{lineno}-{path_disc}"
    else:
        finding_id = f"{scan_id}-{rule}-{path_disc}"

    return Finding(
        finding_id=finding_id,
        rule=rule,
        severity=severity,
        confidence=0.7,
        title=title,
        description=description,
        evidence={"file": path, "line": lineno},
        verification=VerificationEvidence(notes="static analysis (AST)"),
        remediation=remediation,
        location=f"{path}:{lineno}",
    )


def _has_ownership(node: ast.AST) -> bool:
    """True if any keyword/arg/compare mentions ownership hints."""
    for sub in ast.walk(node):
        if isinstance(sub, ast.keyword) and isinstance(sub.arg, str):
            if sub.arg.lower() in OWNERSHIP_HINTS:
                return True
        if isinstance(sub, ast.Name) and sub.id.lower() in OWNERSHIP_HINTS:
            return True
        if isinstance(sub, ast.Attribute) and sub.attr.lower() in OWNERSHIP_HINTS:
            return True
    return False


class _FunctionCollector(ast.NodeVisitor):
    """Collect (function def, contained call nodes) pairs."""

    def __init__(self) -> None:
        self.calls_in_functions: list[tuple[ast.FunctionDef | ast.AsyncFunctionDef, ast.Call]] = []
        self.route_decorated: set[int] = set()

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        for dec in node.decorator_list:
            src = ast.unparse(dec) if hasattr(ast, "unparse") else ""
            if "route" in src or "get(" in src or "post(" in src:
                self.route_decorated.add(node.lineno)
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call):
                self.calls_in_functions.append((node, sub))

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)
        self.generic_visit(node)


def _function_has_auth_guard(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for dec in func.decorator_list:
        src = ast.unparse(dec) if hasattr(ast, "unparse") else ""
        if any(guard in src for guard in AUTH_GUARDS):
            return True
    for sub in ast.walk(func):
        if isinstance(sub, ast.Name) and sub.id in AUTH_GUARDS:
            return True
        if isinstance(sub, ast.Call):
            name = ""
            if isinstance(sub.func, ast.Name):
                name = sub.func.id
            elif isinstance(sub.func, ast.Attribute):
                name = sub.func.attr
            if name in AUTH_GUARDS:
                return True
    return False


def analyze_python_file(path: Any, source: str, scan_id: str) -> list[Finding]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []

    collector = _FunctionCollector()
    collector.visit(tree)
    findings: list[Finding] = []

    for func, call in collector.calls_in_functions:
        guarded = _function_has_auth_guard(func)
        path_str = str(path)

        # track locals assigned from request data (for CY006 indirection)
        _REQUEST_ASSIGNED_VARS.clear()
        _REQUEST_ASSIGNED_VARS.update(_request_assigned_vars(func))

        # ---- call shape extraction -----------------------------------------
        call_src = ast.unparse(call) if hasattr(ast, "unparse") else ""

        # CY001: Model.objects.get(id=request.X) etc. unscoped
        if _matches_orm_get(call):
            if not _has_ownership(call) and not guarded:
                findings.append(
                    _finding(
                        scan_id, "CY001", Severity.HIGH, path_str, call,
                        "Unscoped .get() by request-controlled id",
                        f"`{call_src}` fetches an object using a client-supplied "
                        "identifier without an ownership filter or visible "
                        "authorization guard — potential IDOR.",
                        "Scope the lookup by the authenticated user "
                        "(e.g. get(user=request.user, id=...)) or add an explicit "
                        "authorization check after fetching.",
                    )
                )

        # CY002: Model.objects.filter(...).first() without user scoping
        if _matches_filter_first(call):
            if not _has_ownership(call) and not guarded:
                findings.append(
                    _finding(
                        scan_id, "CY002", Severity.HIGH, path_str, call,
                        "Unscoped filter(...).first() by request id",
                        f"`{call_src}` returns the first row matching a "
                        "request-controlled id without user scoping.",
                        "Add user_id/owner filter to the queryset or verify "
                        "object.owner == current_user before returning data.",
                    )
                )

        # CY005: get_object_or_404 without user kw
        if _matches_get_object_or_404(call):
            if not _has_ownership(call) and not guarded:
                findings.append(
                    _finding(
                        scan_id, "CY005", Severity.HIGH, path_str, call,
                        "get_object_or_404 without ownership filter",
                        f"`{call_src}` resolves an object by client-supplied pk "
                        "without scoping to the requesting user.",
                        "Include user=request.user (or equivalent) in the lookup "
                        "kwargs, or check ownership after retrieval.",
                    )
                )

        # CY006: open() with f-string/path containing request param
        if _matches_open_request_param(call):
            findings.append(
                _finding(
                    scan_id, "CY006", Severity.CRITICAL, path_str, call,
                    "File access built from request-controlled path",
                    f"`{call_src}` opens a file whose path includes a "
                    "request-supplied parameter — arbitrary file read / IDOR.",
                    "Validate against an allow-list of file ids; never interpolate "
                    "request data into filesystem paths.",
                )
            )

    # CY003: flask route with <int:id> + unscoped query using the route param
    for func in ast.walk(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in func.decorator_list:
            src = ast.unparse(dec) if hasattr(ast, "unparse") else ""
            if "route" not in src or "<int:" not in src:
                continue
            if _function_has_auth_guard(func):
                continue
            params = {a.arg for a in func.args.args}
            for sub in ast.walk(func):
                if not isinstance(sub, ast.Call):
                    continue
                if not _is_orm_lookup(sub):
                    continue
                if not _uses_client_controlled_id(sub, params):
                    continue
                if _has_ownership(sub):
                    continue
                findings.append(
                    _finding(
                        scan_id, "CY003", Severity.HIGH, str(path), sub,
                        "Flask route uses <int:id> with unscoped query",
                        f"Route `{src}` passes `<int:id>` straight into "
                        f"`{ast.unparse(sub)}` without ownership check.",
                        "Fetch within a user-scoped query, e.g. "
                        "Invoice.query.filter_by(id=invoice_id, user_id=current_user.id).",
                    )
                )
                break

    # CY004: FastAPI path param -> DB query directly
    for func in ast.walk(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if _function_has_auth_guard(func):
            continue
        # CY004 is FastAPI-specific: require a FastAPI-style signal so a
        # Django view (`def view(request): .get(id=request.GET['id'])`) or a
        # Flask route is NOT double-reported as CY004 (it is already CY001/
        # CY003). FastAPI routes are typically `async def` with an HTTP-method
        # decorator or use Depends().
        if not _is_fastapi_style(func, source):
            continue
        params = {
            a.arg for a in list(func.args.args) + list(func.args.kwonlyargs)
        }
        for sub in ast.walk(func):
            if not isinstance(sub, ast.Call):
                continue
            if not _is_orm_lookup(sub):
                continue
            if not _uses_client_controlled_id(sub, params):
                continue
            if _has_ownership(sub):
                continue
            findings.append(
                _finding(
                    scan_id, "CY004", Severity.HIGH, str(path), sub,
                    "FastAPI path parameter used in unscoped DB lookup",
                    f"`{ast.unparse(sub)}` queries with the path parameter "
                    "directly; FastAPI does not authorize object access.",
                    "Scope the query by the authenticated user id or add a "
                    "dependency-based authorization check.",
                )
            )

    return findings


# -- FastAPI style detection ------------------------------------------------

_FASTAPI_HTTP_DECORATORS = frozenset({"get", "post", "put", "delete", "patch", "api_route"})


def _is_fastapi_style(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
    source: str,
) -> bool:
    """True if the function looks like a FastAPI route.

    Signals: ``async def`` + an HTTP-method decorator (``@app.get``), or a
    ``Depends(...)`` in the signature, or the source references ``fastapi``
    / ``APIRouter``. Excludes Django views (sync ``def view(request)``) and
    Flask routes (sync ``def``) so CY004 does not double-report them.
    """
    # Depends() is a strong FastAPI-only signal.
    sig = ast.unparse(func.args) if hasattr(ast, "unparse") else ""
    if "Depends" in sig or "BackgroundTasks" in sig:
        return True
    # Async def + HTTP-method decorator.
    is_async = isinstance(func, ast.AsyncFunctionDef)
    if not is_async:
        return False
    for dec in func.decorator_list:
        name = _decorator_name(dec)
        if name in _FASTAPI_HTTP_DECORATORS:
            return True
    # Async route via @app.route(...) is ambiguous — require fastapi import.
    return "fastapi" in source or "APIRouter" in source


def _decorator_name(dec: ast.expr) -> str | None:
    """Best-effort decorator base name, e.g. @app.get(...) -> 'get'."""
    if isinstance(dec, ast.Call):
        return _decorator_name(dec.func)
    if isinstance(dec, ast.Attribute):
        return dec.attr
    if isinstance(dec, ast.Name):
        return dec.id
    return None


# -- call-shape matchers -----------------------------------------------------

def _is_orm_lookup(call: ast.Call) -> bool:
    """Any ORM-style object fetch: .objects.get/filter, get_object_or_404."""
    src = ast.unparse(call) if hasattr(ast, "unparse") else ""
    if ".objects.get(" in src or ".objects.filter(" in src:
        return True
    if isinstance(call.func, ast.Name) and call.func.id == "get_object_or_404":
        return True
    return False


def _uses_client_controlled_id(call: ast.Call, params: set[str]) -> bool:
    """True if a lookup kw/arg references a route/path parameter or request data."""
    if _has_request_kw(call):
        return True
    for kw in call.keywords:
        if isinstance(kw.value, ast.Name) and kw.value.id in params:
            return True
    for arg in call.args:
        if isinstance(arg, ast.Name) and arg.id in params:
            return True
    return False


def _request_assigned_vars(func: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Local names assigned from request.* data (e.g. name = request.GET['n'])."""
    names: set[str] = set()
    for node in ast.walk(func):
        if not isinstance(node, ast.Assign):
            continue
        if _mentions_request(node.value):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    names.add(target.id)
    return names

def _matches_orm_get(call: ast.Call) -> bool:
    src = ast.unparse(call) if hasattr(ast, "unparse") else ""
    if ".objects.get(" not in src:
        return False
    return _has_request_kw(call)


def _matches_filter_first(call: ast.Call) -> bool:
    """Match ``Model.objects.filter(id=request...).first()`` chains.

    The request keyword lives on the inner ``filter(...)`` call, so check
    both the outer call and its argument sub-calls.
    """
    src = ast.unparse(call) if hasattr(ast, "unparse") else ""
    if ".objects.filter(" not in src or ".first()" not in src:
        return False
    candidates: list[ast.Call] = [call]
    for arg in call.args:
        if isinstance(arg, ast.Call):
            candidates.append(arg)
    for kw in call.keywords:
        if isinstance(kw.value, ast.Call):
            candidates.append(kw.value)
    # walk one level into attribute chains (a.b.filter(...).first())
    if isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Call):
        candidates.append(call.func.value)
    return any(_has_request_kw(c) for c in candidates)


def _matches_get_object_or_404(call: ast.Call) -> bool:
    if not isinstance(call.func, ast.Name):
        return False
    return call.func.id == "get_object_or_404" and _has_request_kw(call)


def _matches_open_request_param(call: ast.Call) -> bool:
    """open() whose path is an f-string/template referencing a local variable
    that was assigned from request data, or directly mentions request."""
    if not (isinstance(call.func, ast.Name) and call.func.id == "open"):
        return False
    if not call.args:
        return False
    path_node = call.args[0]

    # direct mention: open(f"/x/{request.GET['n']}")
    if _mentions_request(path_node):
        return True

    # indirection: name = request.GET['x']; open(f"/uploads/{name}")
    for sub in ast.walk(path_node):
        if isinstance(sub, ast.Name) and sub.id in _REQUEST_ASSIGNED_VARS:
            return True
    return False


# populated per-function during analysis (see analyze_python_file)
_REQUEST_ASSIGNED_VARS: set[str] = set()


def _has_request_kw(call: ast.Call) -> bool:
    for kw in call.keywords:
        if kw.arg and kw.arg.lower() in {"id", "pk", "user_id", "object_id", "invoice_id",
                                         "order_id", "doc_id", "file_id", "record_id"}:
            if _mentions_request(kw.value):
                return True
    for arg in call.args:
        if _mentions_request(arg):
            return True
    return False


def _mentions_request(node: ast.AST) -> bool:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Attribute) and sub.attr in {"GET", "POST", "params", "query_params",
                                                           "path_params", "json", "data", "args",
                                                           "values", "form", "cookies", "headers"}:
            if isinstance(sub.value, ast.Name) and sub.value.id == "request":
                return True
        if isinstance(sub, ast.Attribute) and sub.attr in {"id", "pk"}:
            if isinstance(sub.value, ast.Attribute) and sub.value.attr in {"GET", "POST", "params",
                                                                           "query_params", "args",
                                                                           "values", "form"}:
                return True
    return False


__all__ = ["analyze_python_file"]
