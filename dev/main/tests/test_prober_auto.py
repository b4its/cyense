"""Regression: auto probing (probe_ids=None) must generate numeric candidates."""

from __future__ import annotations

from app.agents.prober import ProberAgent


def test_numeric_neighbours_returns_ids() -> None:
    prober = ProberAgent("t", "/tmp")
    ids = prober._numeric_neighbours("1", 3)
    # ±1..±3 around 1, non-negative, deduped by callers
    assert "2" in ids and "4" in ids
    assert "0" in ids
    assert all(i.isdigit() for i in ids)


def test_numeric_neighbours_falls_back_to_wordlist(tmp_path) -> None:
    """Non-numeric seed falls back to the wordlist (not a tautology)."""
    # Create a real wordlist so the fallback has content to return.
    wordlist = tmp_path / "ids.txt"
    wordlist.write_text("alpha\nbeta\n42\n")
    prober = ProberAgent("t", tmp_path, wordlist_path=wordlist)
    ids = prober._numeric_neighbours("not-a-number", 3)
    # Must return wordlist entries, not []; a regression that returns an
    # empty list would now fail (previously only checked isinstance(list)).
    assert ids == ["alpha", "beta", "42"]


def test_baseline_hint_is_numeric_default() -> None:
    from app.agents.recon import TargetProfile

    prober = ProberAgent("t", "/tmp")
    assert prober._baseline_id_hint(TargetProfile(url_template="x", host="h")) == "1"


def test_candidates_auto_generates_when_no_request_ids(tmp_path) -> None:
    from pathlib import Path

    from app.agents.recon import TargetProfile

    prober = ProberAgent("t", tmp_path, wordlist_path=Path(tmp_path) / "none.txt")
    profile = TargetProfile(url_template="http://lab/invoice/{ID}", host="lab",
                            placeholders=["id"])
    candidates = prober._candidates(None, [], profile, probe_max=5)
    assert candidates, "auto mode must produce numeric candidates"
    assert "2" in candidates and "3" in candidates
