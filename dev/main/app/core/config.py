"""Cyense service configuration (pydantic-settings, PRD v2.0 §5.3).

All values are read from environment variables prefixed with ``CYENSE_``
(see ``.env.example``).
"""

from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="CYENSE_", env_file=".env", extra="ignore")

    # service
    log_level: str = "INFO"

    # probing behaviour (PRD §9 non-functional requirements)
    max_concurrency: int = 10
    rate_limit: int = 50  # max requests per second-ish budget
    request_timeout: float = 10.0

    # verification (PRD §4.1)
    similarity_threshold: float = 0.80
    verify_retries: int = 2
    control_id: str = "99999999"

    # id candidate generation (PRD §4.1 stage 2)
    probe_max: int = 50

    # filesystem
    reports_dir: Path = Path("reports")
    brain_dir: Path = Path("brain")
    workspace_dir: Path = Path("/workspace")

    # github-scan feature config (instruction/feature/github-repo-audit.md PRD)
    github_max_mb: int = 50
    github_max_files: int = 3000
    github_timeout: float = 60.0
    github_cache: bool = True

    # CI/Compliance Reporting (instruction/feature/ci-compliance-reporting.md)
    scan_mode_default: str = "standard"  # quick | standard | deep
    scope_mode_default: str = "auto"     # auto | full | diff
    sarif_enabled: bool = True
    coverage_enabled: bool = True

    # Live CVE search (augments the local CVE database via NVD/MITRE APIs).
    cve_online_enabled: bool = True
    cve_search_timeout: float = 12.0


settings = Settings()
