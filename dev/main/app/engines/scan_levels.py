"""Scan levels — control analysis depth for source code vulnerability detection.

Four levels of analysis thoroughness:

  * **low**    — Quick check: critical rules only, limited files, fast patterns
  * **medium** — Standard (default): all rules, balanced coverage
  * **high**   — Thorough: deeper AST analysis, basic data flow, more files
  * **max**    — Exhaustive: cross-file analysis, call graph, full data flow

The level is orthogonal to ``scan_mode`` (idor/xss selection) and
``scope_mode`` (full vs diff). It controls *how deeply* each rule analyzes
the code, not *which* rules run or *which* files are analyzed.

Rules opt into higher levels via :data:`LEVEL_RULE_REQUIREMENTS`:
  * Rules not listed run at every level
  * Rules listed under ``high`` run at high and max
  * Rules listed under ``max`` run only at max

This keeps the existing CY001–CY010 and XS001–XS008 rules running at every
level, while new deep rules (CY011, CY012, XS009, XS010, CY013, XS011) are
gated to the level where their analysis cost is justified.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# Rules grouped by minimum level required.
# A rule listed under "high" runs at "high" AND "max" levels.
# A rule listed under "max" runs ONLY at "max" level.
# Rules not listed here run at every level (low, medium, high, max).
LEVEL_RULE_REQUIREMENTS: dict[str, set[str]] = {
    "high": {
        # Data flow + context-aware IDOR/XSS rules
        "CY011",  # data flow: request → DB query without ownership
        "CY012",  # unauthenticated endpoint accessing user data
        "XS009",  # document.cookie leaked to external origin
        "XS010",  # eval/exec of user-controlled input (data flow)
    },
    "max": {
        # Most expensive rules — cross-file + call graph
        "CY013",  # cross-file IDOR via imports
        "XS011",  # cross-file XSS via imported templates
    },
}

# Ordered level names (also used for validation)
LEVEL_ORDER = ("low", "medium", "high", "max")


@dataclass(frozen=True)
class ScanLevelProfile:
    """Configuration for one scan level."""

    name: str
    description: str
    max_files: int            # -1 = unlimited
    ast_max_depth: int        # how deep to traverse AST; -1 = unlimited
    enable_data_flow: bool = False
    enable_cross_file: bool = False
    target_time_seconds: int | None = None

    def should_run_rule(self, rule_id: str) -> bool:
        """Check whether a rule should execute at this level."""
        if rule_id in LEVEL_RULE_REQUIREMENTS.get("max", set()):
            return self.name == "max"
        if rule_id in LEVEL_RULE_REQUIREMENTS.get("high", set()):
            return self.name in ("high", "max")
        return True


LEVELS: dict[str, ScanLevelProfile] = {
    "low": ScanLevelProfile(
        name="low",
        description=(
            "Quick scan — critical rules only (CY001, CY006, XS004, SQLI001–SQLI005), "
            "fast patterns, limited to 100 files"
        ),
        max_files=100,
        ast_max_depth=5,
        target_time_seconds=10,
    ),
    "medium": ScanLevelProfile(
        name="medium",
        description=(
            "Standard scan — all IDOR + XSS + SQLi rules (CY001–CY010, "
            "XS001–XS008, SQLI001–SQLI006), balanced coverage, up to 1000 files"
        ),
        max_files=1000,
        ast_max_depth=10,
        target_time_seconds=60,
    ),
    "high": ScanLevelProfile(
        name="high",
        description=(
            "Thorough scan — all rules + data-flow rules (CY011, CY012, "
            "XS009, XS010), deeper AST, up to 5000 files"
        ),
        max_files=5000,
        ast_max_depth=20,
        enable_data_flow=True,
        target_time_seconds=300,
    ),
    "max": ScanLevelProfile(
        name="max",
        description=(
            "Exhaustive scan — all rules + cross-file analysis (CY013, XS011), "
            "full data flow, call graph, unlimited files"
        ),
        max_files=-1,
        ast_max_depth=-1,
        enable_data_flow=True,
        enable_cross_file=True,
    ),
}


def get_level(name: str) -> ScanLevelProfile:
    """Return the profile for a level name.

    Falls back to ``medium`` for unknown names so a typo never makes a scan
    silently exhaustive or silently empty.
    """
    return LEVELS.get(name, LEVELS["medium"])


def is_valid_level(name: str) -> bool:
    """Return True if ``name`` is one of the supported levels."""
    return name in LEVELS


def rules_for_level(rule_ids: list[str] | set[str], level_name: str) -> list[str]:
    """Filter a collection of rule IDs to those active at a given level.

    Preserves input order when given a list; returns a sorted list when
    given a set.
    """
    level = get_level(level_name)
    if isinstance(rule_ids, set):
        rule_ids = sorted(rule_ids)
    return [rid for rid in rule_ids if level.should_run_rule(rid)]


def describe_levels() -> list[dict[str, Any]]:
    """Return a JSON-friendly summary of all levels (used by CLI /api)."""
    return [
        {
            "name": p.name,
            "description": p.description,
            "max_files": p.max_files,
            "ast_max_depth": p.ast_max_depth,
            "enable_data_flow": p.enable_data_flow,
            "enable_cross_file": p.enable_cross_file,
            "target_time_seconds": p.target_time_seconds,
            "exclusive_rules": sorted(
                LEVEL_RULE_REQUIREMENTS.get(p.name, set())
            ),
        }
        for p in LEVELS.values()
    ]
