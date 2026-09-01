"""Structured logging per stage (PRD v2.0 §9 observability)."""

from __future__ import annotations

import logging
import os
import sys

# Default level for cyense.* loggers. Overridable via CYENSE_LOG_LEVEL env
# (e.g. "INFO", "DEBUG"). Previously the effective level of the parent
# "cyense" logger (default WARNING on the root logger) was used, which meant
# log.info() was silently dropped and Settings.log_level was never applied.
_DEFAULT_LEVEL = os.environ.get("CYENSE_LOG_LEVEL", "INFO").upper()
if _DEFAULT_LEVEL not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
    _DEFAULT_LEVEL = "INFO"


def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(f"cyense.{name}")
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
        )
        logger.addHandler(handler)
        logger.propagate = False
    logger.setLevel(getattr(logging, _DEFAULT_LEVEL, logging.INFO))
    return logger


_root = get_logger("root")
_root.setLevel(getattr(logging, _DEFAULT_LEVEL, logging.INFO))
