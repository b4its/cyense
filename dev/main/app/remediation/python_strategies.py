"""Fix strategies untuk kerentanan IDOR Python rules (CY001–CY006, PRD §4).

Strategi ini menggunakan AST-based transformation yang deterministik — tidak ada LLM.
Masing-masing strategy menghasilkan unified diff + verification patch.
"""

from __future__ import annotations

import ast
from typing import Any


class PatchResult:
    """Hasil transformasi satu rule."""

    def __init__(
        self,
        diff: str,
        before_snippet: str,
        after_snippet: str,
        risk: str,
        notes: str = "",
    ):
        self.diff = diff
        self.before_snippet = before_snippet
        self.after_snippet = after_snippet
        self.risk = risk
        self.notes = notes

    def to_dict(self) -> dict[str, Any]:
        return {
            "diff": self.diff,
            "before_snippet": self.before_snippet,
            "after_snippet": self.after_snippet,
            "risk": self.risk,
            "notes": self.notes,
        }


def generate_ownership_filter(
    node: ast.Call,
    source: str,
    auth_var: str,
) -> PatchResult:
    """Generate patch untuk ORM query tanpa ownership filter.

    Contoh:
      BEFORE: inv = Invoice.objects.get(id=request.GET["id"])
      AFTER:  inv = Invoice.objects.get(id=request.GET["id"], user_id={auth_var}.id)
    """
    # Generate patched kwargs
    kwarg_names = [k.arg for k in node.keywords if k.arg]

    new_kwargs = []
    has_user_kw = False
    for kw in node.keywords:
        if kw.arg in ["user_id", "user", "owner_id"]:
            has_user_kw = True
            break
        new_kwargs.append(ast.unparse(kw))

    if not has_user_kw:
        if auth_var == "unknown":
            return PatchResult(
                diff="manual_required: cannot detect auth context",
                before_snippet="",
                after_snippet="",
                risk="HIGH",
                notes="Auth variable tidak terdeteksi di scope",
            )

        patch_arg = f"user_id={auth_var}.id"

        if node.args:
            args_str = ast.unparse(node.args[0])
            new_args = f"{args_str}, {patch_arg}"
        else:
            new_args = ""
            if kwarg_names:
                new_args = ", ".join(new_kwargs + [patch_arg])

        # Use the ORIGINAL source text of the call (ast.get_source_segment),
        # not ast.unparse — unparse normalizes string literals to single
        # quotes, so .replace() silently no-ops on double-quoted sources and
        # the patch "applies" while leaving the vulnerability in place.
        before_src = ast.get_source_segment(source, node)
        if not before_src:
            before_src = ast.unparse(node)
        # Use ast.unparse on the full call so we don't assume .func is a Name
        func_src = ast.unparse(node.func)
        after_src = f"{func_src}({new_args})"

        lines = source.split("\n")
        line_num = getattr(node, "lineno", 0)
        if 0 < line_num <= len(lines):
            before_snippet = lines[line_num - 1].strip()
            after_snippet = before_snippet.replace(before_src, after_src)
            if after_snippet == before_snippet:
                # Fallback: replace from the raw unparsed call if the source
                # segment contains line-wrapped expressions.
                after_snippet = before_snippet.replace(
                    ast.unparse(node), after_src
                )
        else:
            before_snippet = before_src
            after_snippet = after_src

        diff_lines = [
            f"- {before_snippet}",
            f"+ {after_snippet}",
        ]

        return PatchResult(
            diff="\n".join(diff_lines),
            before_snippet=before_snippet,
            after_snippet=after_snippet,
            risk="LOW",
            notes=f"Added ownership filter with {patch_arg}",
        )

    return PatchResult(
        diff="skipped: already has ownership check",
        before_snippet="",
        after_snippet="",
        risk="LOW",
        notes="Query sudah memiliki filter ownership",
    )


# --- Strategy implementations per rule ---


def cy001_strategy(finding, source, tree):
    """CY001: Model.objects.get(id=X) unscoped."""
    from app.remediation.fixer import find_auth_context

    # Find auth context
    auth_var = find_auth_context(tree)

    # Find the problematic .get() call
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if hasattr(node.func, "attr") and node.func.attr == "get":
                if hasattr(node.func.value, "attr") and node.func.value.attr == "objects":
                    # This is the vulnerable pattern
                    result = generate_ownership_filter(node, source, auth_var)
                    return result.to_dict()

    return {
        "diff": "pattern_match_failed",
        "before_snippet": "",
        "after_snippet": "",
        "risk": "MEDIUM",
        "notes": "Could not locate exact pattern; manual review required",
    }


def cy002_strategy(finding, source, tree):
    """CY002: Model.objects.filter(...).first() unscoped."""
    from app.remediation.fixer import find_auth_context

    auth_var = find_auth_context(tree)

    # Find .filter().first() chain
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if hasattr(node.func, "attr") and node.func.attr == "first":
                if hasattr(node.func.value, "func"):
                    inner = node.func.value
                    if hasattr(inner, "func") and inner.func.attr == "filter":
                        if hasattr(inner.func.value, "attr") and inner.func.value.attr == "objects":
                            result = generate_ownership_filter(inner, source, auth_var)
                            return result.to_dict()

    return {
        "diff": "pattern_match_failed",
        "before_snippet": "",
        "after_snippet": "",
        "risk": "MEDIUM",
        "notes": "Filter pattern not matched",
    }


def cy003_strategy(finding, source, tree):
    """CY003: Flask route with <int:id> unscoped."""
    from app.remediation.fixer import find_auth_context

    auth_var = find_auth_context(tree)

    # Find function body queries
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # Find inside this function
            for sub in ast.walk(node):
                if isinstance(sub, ast.Call):
                    if hasattr(sub.func, "attr") and sub.func.attr == "get":
                        if hasattr(sub.func.value, "attr") and sub.func.value.attr == "objects":
                            result = generate_ownership_filter(sub, source, auth_var)
                            return result.to_dict()

    return {
        "diff": "pattern_match_failed",
        "before_snippet": "",
        "after_snippet": "",
        "risk": "MEDIUM",
        "notes": "Flask route pattern not detected",
    }


def cy004_strategy(finding, source, tree):
    """CY004: FastAPI path param → DB query."""
    from app.remediation.fixer import find_auth_context

    auth_var = find_auth_context(tree)

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if hasattr(node.func, "attr") and node.func.attr == "get":
                if hasattr(node.func.value, "attr") and node.func.value.attr == "objects":
                    result = generate_ownership_filter(node, source, auth_var)
                    return result.to_dict()

    return {
        "diff": "pattern_match_failed",
        "before_snippet": "",
        "after_snippet": "",
        "risk": "MEDIUM",
        "notes": "FastAPI path pattern not detected",
    }


def cy005_strategy(finding, source, tree):
    """CY005: get_object_or_404 without user kwarg."""
    from app.remediation.fixer import find_auth_context

    auth_var = find_auth_context(tree)

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id == "get_object_or_404":
                # Check if user kw exists
                has_user_kw = any(kw.arg == "user" for kw in node.keywords)

                if not has_user_kw:
                    diff_lines = [f"- {ast.unparse(node)}"]

                    # Add user kwarg
                    if node.args:
                        args_str = ast.unparse(node.args[0])
                        after_code = f"get_object_or_404({args_str}, user={auth_var})"
                    else:
                        kwarg_list = [ast.unparse(kw) for kw in node.keywords]
                        after_code = f"get_object_or_404({', '.join(kwarg_list)}, user={auth_var})"

                    diff_lines.append(f"+ {after_code}")

                    return PatchResult(
                        diff="\n".join(diff_lines),
                        before_snippet=ast.unparse(node),
                        after_snippet=after_code,
                        risk="LOW",
                        notes="Added user kwarg to get_object_or_404",
                    )
                else:
                    return {
                        "diff": "already_secured",
                        "before_snippet": "",
                        "after_snippet": "",
                        "risk": "LOW",
                        "notes": "Already has user kwarg",
                    }

    return {
        "diff": "pattern_not_found",
        "before_snippet": "",
        "after_snippet": "",
        "risk": "MEDIUM",
        "notes": "get_object_or_404 pattern not found",
    }


def cy006_strategy(finding, source, tree):
    """CY006: open() with request-param in path (critical - requires architectural change)."""
    # This requires allow-list lookup instead of direct path construction
    # Cannot auto-generate safe code without knowing the actual data structure

    return {
        "diff": "manual_required: cannot safely auto-patch open() calls",
        "before_snippet": "See location for file path access",
        "after_snippet": "Replace with allow-list lookup: UPLOADS = {...}; UPLOADS.get(name)",
        "risk": "HIGH",
        "notes": "Requires architectural review - cannot auto-remediate path traversal",
    }


# Registry decorators
STRATEGIES = {
    "CY001": {"name": "cy001_unscoped_get", "strategy": cy001_strategy, "risk": "LOW"},
    "CY002": {"name": "cy002_unscoped_first", "strategy": cy002_strategy, "risk": "LOW"},
    "CY003": {"name": "cy003_flask_route", "strategy": cy003_strategy, "risk": "MEDIUM"},
    "CY004": {"name": "cy004_fastapi_path", "strategy": cy004_strategy, "risk": "MEDIUM"},
    "CY005": {"name": "cy005_get_object_404", "strategy": cy005_strategy, "risk": "LOW"},
    "CY006": {"name": "cy006_path_traversal", "strategy": cy006_strategy, "risk": "HIGH"},
}
