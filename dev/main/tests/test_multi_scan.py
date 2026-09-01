"""Tests for multi-target scan permission gate (fail closed)."""

from __future__ import annotations

import pytest


def test_build_request_requires_permission() -> None:
    from app.services.multi_scan import build_request

    with pytest.raises(ValueError):
        build_request({"type": "github", "url": "https://github.com/o/r"}, {})


def test_build_request_accepts_explicit_permission() -> None:
    from app.services.multi_scan import build_request

    r = build_request(
        {"type": "github", "url": "https://github.com/o/r"},
        {"i_have_permission": True},
    )
    assert r.i_have_permission is True
