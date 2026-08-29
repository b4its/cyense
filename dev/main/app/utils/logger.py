"""Structured logging per stage (PRD v2.0 §9 observability)."""

from __future__ import annotations

import logging
import sys


def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(f"cyense.{name}")
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
        )
        logger.addHandler(handler)
        logger.propagate = False
    logger.setLevel(logging.getLogger("cyense").getEffectiveLevel() or logging.INFO)
    return logger


_root = get_logger("root")
_root.setLevel(logging.INFO)
