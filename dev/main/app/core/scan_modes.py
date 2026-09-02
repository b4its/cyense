"""Scan mode presets (ci-compliance-reporting.md §3.4).

Defines quick|standard|deep modes as combinations of rule set, scope mode, and file caps.
"""

from dataclasses import dataclass


@dataclass
class ScanModeProfile:
    """Configuration preset for a scan mode."""
    name: str
    scan_types: tuple[str, ...]
    default_scope_mode: str
    max_files: int
    description: str
    target_time_seconds: int | None = None


# Mode profiles — explicitly documented (unlike Strix which leaves it implicit)
SCAN_MODES: dict[str, ScanModeProfile] = {
    "quick": ScanModeProfile(
        name="quick",
        scan_types=("idor", "sqli"),  # IDOR + SQLi only
        default_scope_mode="auto",  # enable diff-scope by default
        max_files=500,  # cap file count
        description="Quick check for CI/pre-commit; IDOR + SQLi rules only",
        target_time_seconds=5,
    ),
    "standard": ScanModeProfile(
        name="standard",
        scan_types=("idor", "xss", "sqli", "sec"),  # default: all rule classes
        default_scope_mode="auto",
        max_files=3000,
        description="Routine testing; balanced speed vs coverage",
        target_time_seconds=30,
    ),
    "deep": ScanModeProfile(
        name="deep",
        scan_types=("idor", "xss", "sqli", "sec"),
        default_scope_mode="full",  # disable diff-scope (slower)
        max_files=-1,  # use global cap
        description="Thorough review for release audits",
        target_time_seconds=None,  # no target
    ),
}


def get_profile(mode: str) -> ScanModeProfile | None:
    """Fetch profile by name."""
    return SCAN_MODES.get(mode)


def resolve_config(
    cli_mode: str | None = None,
    cli_scan_types: list[str] | None = None,
    cli_scope_mode: str | None = None,
) -> tuple[list[str], str]:
    """Resolve final configuration from CLI args + presets."""

    # Start with preset or default
    mode = cli_mode or "standard"
    profile = get_profile(mode)

    if not profile:
        raise ValueError(f"Invalid scan mode: {mode}")

    # CLI flags override presets (explicit always wins)
    scan_types = tuple(cli_scan_types) if cli_scan_types else profile.scan_types
    scope_mode = cli_scope_mode or profile.default_scope_mode

    return list(scan_types), scope_mode
