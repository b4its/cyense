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


settings = Settings()
