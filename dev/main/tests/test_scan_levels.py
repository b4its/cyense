"""Unit tests for scan levels (app.engines.scan_levels).

Verifies the four analysis depth levels (low/medium/high/max) and their
rule gating: every level runs the base rules, ``high``-gated rules (CY011,
CY012, XS009, XS010) run at high+max, and ``max``-gated rules (CY013, XS011)
run only at max. A typo/unknown level must never make a scan silently
exhaustive or silently empty — it falls back to ``medium``.
"""

from __future__ import annotations

from app.engines.scan_levels import (
    LEVEL_ORDER,
    LEVEL_RULE_REQUIREMENTS,
    LEVELS,
    describe_levels,
    get_level,
    is_valid_level,
    rules_for_level,
)


def test_four_levels_present() -> None:
    assert list(LEVELS) == ["low", "medium", "high", "max"]
    assert LEVEL_ORDER == ("low", "medium", "high", "max")


def test_max_files_caps() -> None:
    assert LEVELS["low"].max_files == 100
    assert LEVELS["medium"].max_files == 1000
    assert LEVELS["high"].max_files == 5000
    # max level is unlimited
    assert LEVELS["max"].max_files == -1


def test_data_flow_and_cross_file_flags() -> None:
    assert LEVELS["low"].enable_data_flow is False
    assert LEVELS["medium"].enable_data_flow is False
    assert LEVELS["high"].enable_data_flow is True
    assert LEVELS["max"].enable_data_flow is True
    assert LEVELS["max"].enable_cross_file is True
    assert LEVELS["high"].enable_cross_file is False


def test_get_level_unknown_falls_back_to_medium() -> None:
    assert get_level("nope").name == "medium"
    assert get_level("").name == "medium"


def test_is_valid_level() -> None:
    assert is_valid_level("low")
    assert is_valid_level("high")
    assert is_valid_level("max")
    assert not is_valid_level("turbo")
    assert not is_valid_level("")


def test_base_rules_run_at_every_level() -> None:
    # CY001 is a base rule, not listed in LEVEL_RULE_REQUIREMENTS
    for name in LEVEL_ORDER:
        assert LEVELS[name].should_run_rule("CY001") is True
        assert LEVELS[name].should_run_rule("XS001") is True
        assert LEVELS[name].should_run_rule("SQLI001") is True


def test_high_rules_gated() -> None:
    for name in LEVEL_ORDER:
        expect = name in ("high", "max")
        assert LEVELS[name].should_run_rule("CY011") is expect
        assert LEVELS[name].should_run_rule("CY012") is expect
        assert LEVELS[name].should_run_rule("XS009") is expect
        assert LEVELS[name].should_run_rule("XS010") is expect


def test_max_rules_only_at_max() -> None:
    for name in LEVEL_ORDER:
        expect = name == "max"
        assert LEVELS[name].should_run_rule("CY013") is expect
        assert LEVELS[name].should_run_rule("XS011") is expect


def test_rules_for_level_preserves_list_order() -> None:
    rules = ["CY013", "CY001", "XS011", "CY011"]
    # At max every rule is active
    assert rules_for_level(rules, "max") == rules
    # At high, the max-only rules (CY013, XS011) are dropped, order preserved
    assert rules_for_level(rules, "high") == ["CY001", "CY011"]


def test_rules_for_level_sorted_when_set() -> None:
    rules = {"CY011", "CY001", "CY013"}
    assert rules_for_level(rules, "max") == ["CY001", "CY011", "CY013"]
    assert rules_for_level(rules, "high") == ["CY001", "CY011"]


def test_rules_for_level_unknown_uses_medium() -> None:
    rules = ["CY013", "CY001"]
    # unknown -> medium: CY013 (max-only) dropped
    assert rules_for_level(rules, "sideways") == ["CY001"]


def test_describe_levels_shape() -> None:
    desc = describe_levels()
    assert len(desc) == 4
    for item in desc:
        assert item["name"] in LEVELS
        assert "description" in item
        assert "exclusive_rules" in item
    low = next(i for i in desc if i["name"] == "low")
    assert low["exclusive_rules"] == []
    high = next(i for i in desc if i["name"] == "high")
    assert set(high["exclusive_rules"]) == LEVEL_RULE_REQUIREMENTS["high"]
    mx = next(i for i in desc if i["name"] == "max")
    assert set(mx["exclusive_rules"]) == LEVEL_RULE_REQUIREMENTS["max"]
