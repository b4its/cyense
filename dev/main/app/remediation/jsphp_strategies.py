"""Fix strategies untuk JS/PHP rules (CY007-CY010, PRD §4).

Line-based transformation dengan regex substitution — tidak seperti Python yang
membutuhkan AST parse karena kita gunakan pattern matching pada baris tertentu.
"""

import re


class LinePatchResult:
    """Hasil patch berbasis line."""
    
    def __init__(
        self,
        old_line: str,
        new_line: str,
        risk: str,
        notes: str = "",
    ):
        self.old_line = old_line
        self.new_line = new_line
        self.risk = risk
        self.notes = notes
    
    def to_dict(self) -> dict[str, any]:
        return {
            "diff": f"- {self.old_line}\n+ {self.new_line}",
            "before_snippet": self.old_line.strip(),
            "after_snippet": self.new_line.strip(),
            "risk": self.risk,
            "notes": self.notes,
        }


def find_auth_context_js(source: str) -> str:
    """Deteksi user ID context di kode JS."""
    patterns = [
        r"req\.user\.id",
        r"request\.user\.id",
        r"user\.id",
        r"context\.userId",
    ]
    
    for pattern in patterns:
        if re.search(pattern, source):
            return "req.user.id"
    
    return "unknown"


def find_auth_context_php(source: str) -> str:
    """Deteksi user ID context di kode PHP."""
    patterns = [
        r"\$currentUserId",
        r"\$auth->id()",
        r"\Auth::id\(\)",
        r"\$_SESSION\[['\"]user_id['\"]\]",
    ]
    
    for pattern in patterns:
        if re.search(pattern, source):
            return "$currentUserId"
    
    return "unknown"


# --- CY007: findOne({_id: req.params.id}) unscoped ---
def cy007_strategy(finding, source, tree=None):
    """CY007: JS MongoDB findOne tanpa userId check."""
    auth_ctx = find_auth_context_js(source)
    
    # Pattern: findOne({_id: <something>})
    pattern = r"findOne\s*\(\s*\{\s*_id:\s*(.+?)\s*\}\s*\)"
    match = re.search(pattern, source)
    
    if match:
        param_expr = match.group(1).strip()
        
        if auth_ctx == "unknown":
            return {
                "diff": "manual_required: cannot detect user context",
                "before_snippet": match.group(0),
                "after_snippet": "/* Manual: add .where({ownerId: <auth_variable>.id}) */",
                "risk": "HIGH",
                "notes": "Tidak dapat mendeteksi context user untuk filtering",
            }
        
        # Add owner check before query
        diff_lines = [
            f"- const doc = {match.group(0)};",
            f"+ const doc = await {match.group(0)}.orFail().then(d => {{",
            f+">>  if (!d.owner.equals({auth_ctx})) throw new Error('Unauthorized');",
            f">>  return d;",
            f+">> }});",
        ]
        
        return {
            "diff": "\n".join(diff_lines),
            "before_snippet": f"const doc = {match.group(0)};",
            "after_snippet": "// See patched version",
            "risk": "MEDIUM",
            "notes": "Added ownerId check with guard clause",
        }
    
    return {
        "diff": "pattern_not_found",
        "before_snippet": "",
        "after_snippet": "",
        "risk": "MEDIUM",
        "notes": "MongoDB findOne pattern not matched",
    }


# --- CY008: findById(req.params.id) unscoped ---
def cy008_strategy(finding, source, tree=None):
    """CY008: JS findById tanpa ownership check."""
    auth_ctx = find_auth_context_js(source)
    
    # Pattern: findById(<param>)
    pattern = r"findById\s*\(\s*(.+?)\s*\)"
    match = re.search(pattern, source)
    
    if match:
        if auth_ctx == "unknown":
            return {
                "diff": "manual_required: need user context variable name",
                "before_snippet": match.group(0),
                "after_snippet": "/* Manual: add ownership check after fetch */",
                "risk": "HIGH",
                "notes": "Perlu tambahkan validasi owner setelah fetch",
            }
        
        # After-find validation
        diff_lines = [
            f"- const doc = Model.findById({match.group(1)});",
            f"+ const doc = await Model.findById({match.group(1)});",
            f"+ if (!doc || !doc.owner.toString() === {auth_ctx}.toString()) return res.sendStatus(403);",
        ]
        
        return {
            "diff": "\n".join(diff_lines),
            "before_snippet": f"const doc = Model.findById({match.group(1)});",
            "after_snippet": "See patched version with guard",
            "risk": "MEDIUM",
            "notes": "Post-fetch ownership guard added",
        }
    
    return {
        "diff": "pattern_not_found",
        "before_snippet": "",
        "after_snippet": "",
        "risk": "MEDIUM",
        "notes": "findById pattern not found",
    }


# --- CY009: PHP where('id', $_GET) unscoped ---
def cy009_strategy(finding, source, tree=None):
    """CY009: PHP where('id', $_GET[id]) unscoped."""
    auth_ctx = find_auth_context_php(source)
    
    # Pattern: ->where('id', $var)
    pattern = r"->where\s*\(\s*'id'\s*,\s*([^\)]+)\s*\)"
    match = re.search(pattern, source)
    
    if match:
        var_name = match.group(1).strip()
        
        # Add user scope
        diff_lines = [
            f"- ->where('id', {var_name})",
            f"+ ->where('id', {var_name})",
            f"+ ->where('user_id', {auth_ctx})",
        ]
        
        return {
            "diff": "\n".join(diff_lines),
            "before_snippet": f"->where('id', {var_name})",
            "after_snippet": "->where('id', {var_name})->where('user_id', {auth_ctx})",
            "risk": "LOW",
            "notes": "User ID scoping added to query chain",
        }
    
    return {
        "diff": "pattern_not_found",
        "before_snippet": "",
        "after_snippet": "",
        "risk": "MEDIUM",
        "notes": "PHP where pattern not detected",
    }


# --- CY010: PHP Model::find($_GET) unscoped ---
def cy010_strategy(finding, source, tree=None):
    """CY010: PHP Model::find($_GET[id]) unscoped."""
    auth_ctx = find_auth_context_php(source)
    
    # Pattern: ::find( or ->find(
    pattern = r"(?:Model|)\s*::?\s*find\s*\(\s*([^\)]+)\s*\)"
    match = re.search(pattern, source)
    
    if match:
        param_expr = match.group(1).strip()
        
        if auth_ctx == "unknown":
            return {
                "diff": "manual_required: add owner check after fetch",
                "before_snippet": match.group(0),
                "after_snippet": "/* Manual: verify owner after finding model */",
                "risk": "HIGH",
                "notes": "Perlu verifikasi owner setelah fetch",
            }
        
        # After-find validation
        diff_lines = [
            f"- $model = Model::find({param_expr});",
            f"+ $model = Model::find({param_expr});",
            f"+ if (!$model || $model->user_id !== {auth_ctx}) abort(403);",
        ]
        
        return {
            "diff": "\n".join(diff_lines),
            "before_snippet": f"$model = Model::find({param_expr});",
            "after_snippet": "See patched version with guard",
            "risk": "MEDIUM",
            "notes": "Ownership validation post-fetch",
        }
    
    return {
        "diff": "pattern_not_found",
        "before_snippet": "",
        "after_snippet": "",
        "risk": "MEDIUM",
        "notes": "PHP Model::find pattern not found",
    }


# Registry
JS_PHP_STRATEGIES = {
    "CY007": {"name": "cy007_js_findone", "strategy": cy007_strategy, "risk": "MEDIUM"},
    "CY008": {"name": "cy008_js_findbyid", "strategy": cy008_strategy, "risk": "MEDIUM"},
    "CY009": {"name": "cy009_php_where", "strategy": cy009_strategy, "risk": "LOW"},
    "CY010": {"name": "cy010_php_model_find", "strategy": cy010_strategy, "risk": "MEDIUM"},
}
