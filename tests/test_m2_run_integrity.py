"""Evaluation provenance and failure semantics; no live model calls."""
from m2_fixtures import ALERT
import json
from pathlib import Path
import sys

import pytest

from soc.eval_metrics import score, summary, report, cohen_kappa
from soc.run_artifacts import output_lock, preserve_existing, save_system, load_compatible


def test_parse_failure_fallback_is_not_a_correct_prediction():
    # Even a fail-safe fallback that coincides with ground truth is a failure.
    rec = {"alert_id": ALERT["alert_id"], "verdict": "malicious", "tactic": "Execution",
           "action": "investigate", "parse_failure": True}
    stats = summary(score([ALERT], [rec]))
    assert stats["tactic"] == stats["top2"] == stats["verdict"] == stats["action"] == 0
    assert stats["failed"] == [ALERT["alert_id"]]
    assert stats["missed"] == stats["under"] == []
    md, _ = report("test", {"single_call": [rec]}, [ALERT])
    assert "Failed classifications (counted incorrect) | 1/1" in md
    assert "Zero-miss 95% upper bound (attack denominator) | n/a" in md


def test_missing_prediction_stays_in_accuracy_denominator():
    rows = score([ALERT], [])
    stats = summary(rows)
    assert stats["n"] == 1 and stats["tactic"] == stats["verdict"] == 0
    assert stats["failed"] == [ALERT["alert_id"]]


def test_agent_without_submission_retains_safe_action_but_is_not_a_correct_guess():
    from m2_fixtures import FakeLLM
    from soc.agent import TriageAgent
    record, _ = TriageAgent(FakeLLM(["invalid", "invalid"]), enrich=False).run(ALERT, [])
    assert record["status"] == "failed" and record["action"] == "escalate_tier2"
    stats = summary(score([ALERT], [record]))
    assert stats["failed"] == [ALERT["alert_id"]]
    assert stats["tactic"] == stats["verdict"] == 0


def test_duplicate_predictions_are_rejected():
    with pytest.raises(ValueError, match="Duplicate"):
        score([ALERT], [{"alert_id": ALERT["alert_id"]}] * 2)


def test_zero_miss_bound_requires_successful_attack_predictions():
    benign = {"alert_id": ALERT["alert_id"], "verdict": "benign", "tactic": "Benign", "action": "close"}
    md, _ = report("test", {"single_call": [benign]}, [ALERT])
    assert "Zero-miss 95% upper bound (attack denominator) | n/a" in md
    correct = {**benign, "verdict": "malicious", "tactic": "Execution", "action": "investigate"}
    md, _ = report("test", {"single_call": [correct]}, [ALERT])
    assert "Zero-miss 95% upper bound (attack denominator) | 95.0% (N=1)" in md


def test_kappa_rejects_unpaired_lengths():
    with pytest.raises(ValueError, match="same number"):
        cohen_kappa(["yes"], [])


@pytest.mark.parametrize("field", ["model", "provider", "input_sha256", "context_sha256", "options", "code_sha256"])
def test_saved_system_requires_matching_configuration(tmp_path, field):
    config = {"model": "model-a", "provider": "ollama", "input_sha256": "input",
              "context_sha256": "context", "options": {"seed": 0}, "code_sha256": {"code": "hash"}}
    records = [{"alert_id": "a"}]
    save_system(tmp_path, "single_call", records, config)
    assert load_compatible(tmp_path, "single_call", config, ["a"]) == records
    changed = {**config, field: "different"}
    assert load_compatible(tmp_path, "single_call", changed, ["a"]) is None


def test_saved_system_requires_hash_metadata_and_selected_ids(tmp_path):
    save_system(tmp_path, "agent", [{"alert_id": "a"}], {})
    assert load_compatible(tmp_path, "agent", {}, ["different"]) is None
    (tmp_path / "agent.jsonl").write_text('{"alert_id":"a","changed":true}\n')
    assert load_compatible(tmp_path, "agent", {}, ["a"]) is None
    (tmp_path / "agent.meta.json").write_text("invalid JSON")
    assert load_compatible(tmp_path, "agent", {}, ["a"]) is None
    assert load_compatible(tmp_path, "missing", {}, ["a"]) is None


def test_lock_prevents_parallel_writes_and_releases_on_failure(tmp_path):
    with pytest.raises(RuntimeError):
        with output_lock(tmp_path):
            with pytest.raises(ValueError, match="already locked"):
                with output_lock(tmp_path):
                    pytest.fail("A second writer entered the directory")
            assert (tmp_path / ".run.lock").exists()
            raise RuntimeError("stopped")
    assert not (tmp_path / ".run.lock").exists()


def test_archive_preserves_results_and_moves_old_traces(tmp_path):
    (tmp_path / "agent.jsonl").write_text("original predictions\n")
    (tmp_path / "traces").mkdir()
    (tmp_path / "traces/a.json").write_text("original trace\n")
    with output_lock(tmp_path):
        archive = preserve_existing(tmp_path)
        assert (archive / "agent.jsonl").read_text() == "original predictions\n"
        assert (archive / "traces/a.json").read_text() == "original trace\n"
        assert not (tmp_path / "traces").exists()
        assert not (archive / ".run.lock").exists()


def invoke(monkeypatch, out, systems, *extra):
    import run_eval
    monkeypatch.setattr(sys, "argv", ["run_eval.py", "--dataset", "dev", "--limit", "2",
                                      "--systems", systems, "--out", str(out), *extra])
    run_eval.main()


def test_rules_only_is_offline_and_reruns_preserve_outputs(monkeypatch, tmp_path):
    import run_eval
    def forbidden(*args, **kwargs):
        pytest.fail("Rules-only evaluation initialized a model")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setattr(run_eval, "OllamaLLM", forbidden)
    invoke(monkeypatch, tmp_path, "rules", "--provider", "openai")
    previous = (tmp_path / "dev/rules.jsonl").read_bytes()
    invoke(monkeypatch, tmp_path, "rules", "--provider", "openai")
    meta = json.loads((tmp_path / "dev/run_meta.json").read_text())
    archive = Path(meta["previous_artifacts_archive"])
    assert (archive / "rules.jsonl").read_bytes() == previous
    assert meta["model"] is None and meta["options"] == {} and meta["provider"] is None


def test_runner_excludes_unproven_results_and_does_not_invent_seed(monkeypatch, tmp_path):
    import run_eval
    out = tmp_path / "dev"
    out.mkdir()
    alerts = run_eval.load_jsonl(run_eval.DATASETS["dev"])[:2]
    (out / "agent.jsonl").write_text("".join(json.dumps(a) + "\n" for a in alerts))
    class Model:
        options = {"temperature": 0}
        def __init__(self, *args): pass
        def chat(self, messages):
            return json.dumps({"verdict": "benign", "tactic": "Benign", "evidence": [], "analyst_note": "mock"}), {}
    monkeypatch.setattr(run_eval, "OllamaLLM", Model)
    invoke(monkeypatch, tmp_path, "single_call")
    meta = json.loads((out / "run_meta.json").read_text())
    assert meta["systems"] == ["single_call"]
    assert meta["excluded_incompatible_systems"] == ["agent"]
    assert "seed" not in meta["options"] and "seed 0" not in (out / "results.md").read_text()


def test_interrupted_run_archives_old_report_and_does_not_leave_it_current(monkeypatch, tmp_path):
    import run_eval
    from soc.local_llm import StopRun
    out = tmp_path / "dev"
    out.mkdir()
    (out / "results.md").write_text("previous measured report")
    (out / "run_meta.json").write_text("previous metadata")
    class StoppedModel:
        options = {}
        def __init__(self, *args): pass
        def chat(self, *args): raise StopRun("mock quota exhausted")
    monkeypatch.setattr(run_eval, "OllamaLLM", StoppedModel)
    with pytest.raises(StopRun):
        invoke(monkeypatch, tmp_path, "single_call")
    assert not (out / "results.md").exists() and not (out / "run_meta.json").exists()
    assert not (out / ".run.lock").exists()
    archives = list((out / "history").iterdir())
    assert (archives[0] / "results.md").read_text() == "previous measured report"


@pytest.mark.parametrize("extra", [("--limit", "0"), ("--budget", "-1")])
def test_invalid_limits_fail_before_model_initialization(monkeypatch, tmp_path, extra):
    with pytest.raises(SystemExit) as exc:
        invoke(monkeypatch, tmp_path, "agent", *extra)
    assert exc.value.code == 2
    assert not (tmp_path / "dev").exists()
