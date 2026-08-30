"""Unit tests for utils: similarity, pii, redaction, brain memory."""

from __future__ import annotations

from app.agents.brain import Brain
from app.utils.pii import extract_pii, pii_diff
from app.utils.redact import redact_cookies, redact_headers, redact_url_credentials
from app.utils.similarity import similarity


def test_similarity_identical_and_disjoint() -> None:
    assert similarity("abc", "abc") == 1.0
    assert similarity("", "") == 1.0
    assert similarity("abc", "xyz") < 0.5


def test_extract_pii_email_and_phone() -> None:
    pii = extract_pii("contact bob@example.com or +62 811-1000-102 thanks")
    assert "bob@example.com" in pii
    assert any("628111000102" in p for p in pii)


def test_pii_diff_other_account() -> None:
    base = extract_pii("alice@example.com")
    other = extract_pii("bob@example.com +628111000102")
    assert pii_diff(other, base)  # bob's pii flagged


def test_redact_headers_and_cookies() -> None:
    red = redact_headers({
        "Authorization": "Bearer supersecretvalue123",
        "Accept": "application/json",
    })
    assert red["Authorization"].endswith("[REDACTED]")
    assert "supersecret" not in red["Authorization"]
    assert red["Accept"] == "application/json"
    assert redact_cookies({"session": "xyz"}) == {"session": "[REDACTED]"}


def test_redact_url_credentials() -> None:
    assert "hunter2" not in redact_url_credentials("http://user:hunter2@lab/invoice/1")


def test_brain_strategy_and_memory(tmp_path) -> None:
    brain = Brain(tmp_path / "brain")
    strategy = brain.strategy_for({"framework": "flask", "server": "werkzeug"})
    assert strategy["framework"] == "flask"
    assert "increment" in strategy["strategy"]

    brain.remember_valid_ids("lab", ["2", "3"])
    brain.remember_valid_ids("lab", ["3", "4"])  # dedupe/merge
    memory = brain.recall_host("lab")
    assert memory["valid_ids"] == ["2", "3", "4"]

    # persistence round-trip
    brain2 = Brain(tmp_path / "brain")
    assert brain2.recall_host("lab")["valid_ids"] == ["2", "3", "4"]
