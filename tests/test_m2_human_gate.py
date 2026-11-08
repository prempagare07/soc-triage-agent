"""Milestone 2: human approval gate for the mocked isolate_host."""
import json
import m2_fixtures  # noqa: F401
from soc.human_gate import HumanGate

REC = {"alert_id": "T001", "host": "HOST-01", "verdict": "malicious", "tactic": "Credential Access",
       "action": "escalate_tier2", "analyst_note": "lsass read", "propose_isolate_host": True}


def test_eval_mode_denies_and_logs(tmp_path):
    log = tmp_path / "approvals.jsonl"
    decision = HumanGate(False, log).review(REC)
    assert decision["approved"] is False and json.loads(log.read_text())["mode"].startswith("non-interactive")


def test_interactive_mode_asks_a_person(tmp_path, monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _: "y")
    assert HumanGate(True, tmp_path / "a.jsonl").review(REC)["result"] == "mock: host isolated"


def test_nothing_to_review_without_a_proposal(tmp_path):
    assert HumanGate(False, tmp_path / "a.jsonl").review({**REC, "propose_isolate_host": False}) is None
