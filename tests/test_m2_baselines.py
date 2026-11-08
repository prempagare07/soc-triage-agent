"""Milestone 2: single-call and fixed-workflow baselines on the local model."""
from m2_fixtures import ALERT, CONTEXT, FakeLLM
from soc.baselines import single_call, fixed_workflow


def test_baselines_use_same_record_shape():
    reply = {"verdict": "malicious", "tactic": "Execution", "evidence": [0, 7], "analyst_note": "n"}
    rec = single_call(ALERT, FakeLLM([reply]))
    assert rec["evidence"] == [0] and rec["action"] == "investigate"
    rec = fixed_workflow(ALERT, FakeLLM([reply]), CONTEXT)
    assert rec["agent"]["tool_calls"] >= 4 and rec["evidence"] == [0]
    assert single_call(ALERT, FakeLLM(["x", "y"]))["parse_failure"]


def test_false_positives_are_counted_on_benign_alerts():
    from soc.eval_metrics import report
    alerts = [{"alert_id": "N1", "label_tactic": "Benign", "label_verdict": "benign"},
              {"alert_id": "N2", "label_tactic": "Benign", "label_verdict": "benign"}]
    recs = {"rules": [{"alert_id": "N1", "verdict": "malicious", "tactic": "Execution", "action": "investigate"},
                      {"alert_id": "N2", "verdict": "benign", "tactic": "Benign", "action": "close"}]}
    md, sums = report("benign", recs, alerts)
    assert sums["rules"]["false_pos"] == ["N1"] and "False positives (benign called malicious) | 1/2" in md


def test_cohen_kappa_for_the_evidence_check():
    from soc.eval_metrics import cohen_kappa
    assert cohen_kappa(["yes", "no", "yes"], ["yes", "no", "yes"]) == 1.0
    assert abs(cohen_kappa(["yes", "yes", "no", "no"], ["yes", "no", "yes", "no"])) < 1e-9
