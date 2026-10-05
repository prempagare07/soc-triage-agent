import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from soc.codex_cli import Classifier, CodexError
from soc.sanitize import strip_alert
from soc import rules
from soc.metrics import write_metrics

ROOT = Path(__file__).resolve().parents[1]


def mock_cli(monkeypatch, response=None, event=None):
    calls = []
    def run(command, **kwargs):
        if command[-1] == "--version":
            return SimpleNamespace(stdout="codex-cli test\n", returncode=0)
        calls.append((command, kwargs))
        assert kwargs["cwd"] != str(ROOT)
        assert "OPENAI_API_KEY" not in kwargs["env"]
        assert "CODEX_API_KEY" not in kwargs["env"]
        Path(command[command.index("--output-last-message") + 1]).write_text(
            response or json.dumps({"verdict": "benign", "tactic": "Benign", "evidence": [], "analyst_note": "Normal."}))
        events = [event] if event else []
        events.append({"type": "turn.completed", "usage": {"input_tokens": 20, "cached_input_tokens": 5, "output_tokens": 10}})
        return SimpleNamespace(returncode=0, stdout="\n".join(map(json.dumps, events)))
    monkeypatch.setattr(subprocess, "run", run)
    return calls


def test_sanitization_and_all_alerts_no_leakage(monkeypatch):
    calls = mock_cli(monkeypatch)
    classifier = Classifier("explicit-model")
    for line in (ROOT / "examples/alerts.jsonl").read_text().splitlines():
        alert = json.loads(line)
        assert set(strip_alert(alert)) == {"alert_id", "host", "events"}
        assert rules.classify(alert) == rules.classify(strip_alert(alert))
        classifier.classify(alert)
        command, kwargs = calls[-1]
        payload = kwargs["input"]
        assert "label_tactic" not in payload and "label_verdict" not in payload
        source = alert.get("source_file")
        if source:
            assert source not in payload and Path(source).stem not in payload
        assert "--ignore-user-config" in command and "--ephemeral" in command
        assert "shell_tool" in command and "unified_exec" in command


def test_success_and_cache(monkeypatch, tmp_path):
    calls = mock_cli(monkeypatch)
    classifier = Classifier("explicit-model", cache_dir=tmp_path)
    alert = {"alert_id": "one", "host": "h", "events": []}
    assert classifier.classify(alert)["action"] == "close"
    assert not classifier.last_metadata["cache_hit"]
    assert classifier.classify(alert)["verdict"] == "benign"
    assert classifier.last_metadata["cache_hit"]
    assert len(calls) == 1


@pytest.mark.parametrize("response", ["not JSON", '{"verdict":"benign"}',
    json.dumps({"verdict": "malicious", "tactic": "Execution", "evidence": [9], "analyst_note": "x"})])
def test_invalid_response(monkeypatch, response):
    mock_cli(monkeypatch, response=response)
    with pytest.raises(CodexError, match="Invalid classification"):
        Classifier("explicit-model").classify({"alert_id": "a", "host": "h", "events": []})


@pytest.mark.parametrize("tool_type", ["command_execution", "mcp_tool_call", "web_search", "file_change", "collab_tool_call"])
def test_tool_activity_rejected(monkeypatch, tool_type):
    mock_cli(monkeypatch, event={"type": "item.completed", "item": {"type": tool_type}})
    classifier = Classifier("explicit-model")
    with pytest.raises(CodexError, match=f"item types: {tool_type}"):
        classifier.classify({"alert_id": "a", "host": "h", "events": []})
    assert classifier.last_metadata["rejected_item_types"] == [tool_type]
    assert classifier.last_metadata["usage"]["input_tokens"] == 20


def test_boundary_code_change_invalidates_cache(monkeypatch, tmp_path):
    from soc import codex_cli
    calls = mock_cli(monkeypatch)
    classifier = Classifier("explicit-model", cache_dir=tmp_path)
    alert = {"alert_id": "a", "host": "h", "events": []}
    classifier.classify(alert)
    old_hash = classifier.last_metadata["request_sha256"]
    hashes = codex_cli.code_hashes()
    hashes["soc/sanitize.py"] = "different-boundary-code"
    monkeypatch.setattr(codex_cli, "code_hashes", lambda: hashes)
    classifier.classify(alert)
    assert classifier.last_metadata["request_sha256"] != old_hash
    assert not classifier.last_metadata["cache_hit"]
    assert len(calls) == 2


def test_unknown_item_is_rejected_without_recording_its_body(monkeypatch):
    mock_cli(monkeypatch, event={"type": "item.completed", "item": {
        "type": "unexpected_item", "arguments": "private diagnostic content"}})
    classifier = Classifier("explicit-model")
    with pytest.raises(CodexError, match="unexpected_item"):
        classifier.classify({"alert_id": "a", "host": "h", "events": []})
    assert "private diagnostic content" not in json.dumps(classifier.last_metadata)


def test_completed_turn_with_diagnostic_is_not_tool_use(monkeypatch):
    mock_cli(monkeypatch, event={"type": "item.completed", "item": {
        "type": "error", "message": "A recoverable CLI diagnostic"}})
    classifier = Classifier("explicit-model")
    result = classifier.classify({"alert_id": "a", "host": "h", "events": []})
    assert result["verdict"] == "benign"
    assert classifier.last_metadata["rejected_item_types"] == []
    assert classifier.last_metadata["diagnostics"][0]["message"] == "A recoverable CLI diagnostic"


def test_top_level_error_still_fails_even_with_completed_event(monkeypatch):
    mock_cli(monkeypatch, event={"type": "error", "message": "Fatal CLI error"})
    with pytest.raises(CodexError, match="failed turn"):
        Classifier("explicit-model").classify({"alert_id": "a", "host": "h", "events": []})


def test_diagnostic_does_not_override_invalid_json(monkeypatch):
    mock_cli(monkeypatch, response="invalid JSON", event={"type": "item.completed",
        "item": {"type": "error", "message": "diagnostic"}})
    with pytest.raises(CodexError, match="Invalid classification"):
        Classifier("explicit-model").classify({"alert_id": "a", "host": "h", "events": []})


def test_diagnostic_redacts_credentials(monkeypatch):
    from soc.codex_cli import redact_diagnostic
    monkeypatch.setenv("EXAMPLE_SECRET", "test-secret-value")
    result = redact_diagnostic("test-secret-value sk-example123 Bearer token123")
    assert "test-secret-value" not in result
    assert "sk-example123" not in result
    assert "token123" not in result


def test_timeout(monkeypatch):
    mock_cli(monkeypatch)
    classifier = Classifier("explicit-model")
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired("codex", 180)
    monkeypatch.setattr(subprocess, "run", timeout)
    with pytest.raises(CodexError, match="timed out"):
        classifier.classify({"alert_id": "a", "host": "h", "events": []})


def test_failure_counts_as_incorrect(tmp_path):
    alerts = [{"alert_id": "a", "label_tactic": "Credential Access", "label_verdict": "malicious"}]
    report = write_metrics(alerts, [{"alert_id": "a", "status": "failed"}], "codex", tmp_path / "metrics.md")
    assert "Tactic accuracy: 0/1" in report
    assert "Failed classifications: 1" in report
    assert "FAILED" in report


def test_codex_runner_writes_metadata_and_failure_denominators(monkeypatch, tmp_path):
    import sys
    import run_baseline
    mock_cli(monkeypatch)
    # Avoid mocking git through the CLI fake; its metadata is optional here.
    alerts = [json.loads((ROOT / "examples/alerts.jsonl").read_text().splitlines()[0])]
    source = tmp_path / "alerts.jsonl"
    source.write_text(json.dumps(alerts[0]) + "\n")
    output = tmp_path / "alerts_codex.jsonl"
    monkeypatch.setattr(sys, "argv", ["run_baseline.py", "--input", str(source),
        "--mode", "codex", "--model", "explicit-model", "--no-cache", "--output", str(output)])
    original = subprocess.run
    def dispatch(command, **kwargs):
        if command[0] == "git":
            return SimpleNamespace(returncode=1, stdout="")
        return original(command, **kwargs)
    monkeypatch.setattr(subprocess, "run", dispatch)
    assert run_baseline.main() == 0
    meta = json.loads((tmp_path / "run_meta_alerts_codex.json").read_text())
    assert meta["successful_alerts"] == 1
    assert meta["estimated_api_cost"] is None
    assert meta["tokens"]["input_tokens"] == 20
    assert (tmp_path / "m1_codex_metrics.md").exists()


def test_existing_outputs_preserved(tmp_path):
    from run_baseline import preserve_outputs
    output = tmp_path / "measured.jsonl"
    output.write_text('original measured bytes\n')
    archive = preserve_outputs([output, tmp_path / "missing.json"], tmp_path)
    assert (archive / output.name).read_bytes() == output.read_bytes()
    assert output.exists()


def test_comparison_rejects_mismatched_input_and_modified_outputs(tmp_path):
    import hashlib
    from soc.metrics import write_comparison
    alert = {"alert_id": "a", "label_tactic": "Benign"}
    for mode, input_hash in (("rules", "first"), ("codex", "second")):
        output = tmp_path / f"alerts_{mode}.jsonl"
        output.write_text(json.dumps({"alert_id": "a", "tactic": "Benign", "action": "close"}) + "\n")
        (tmp_path / f"run_meta_alerts_{mode}.json").write_text(json.dumps({
            "input_sha256": input_hash,
            "output_sha256": hashlib.sha256(output.read_bytes()).hexdigest()}))
    write_comparison([alert], tmp_path, "alerts")
    assert not (tmp_path / "m1_per_alert.csv").exists()
    meta = tmp_path / "run_meta_alerts_codex.json"
    data = json.loads(meta.read_text())
    data["input_sha256"] = "first"
    meta.write_text(json.dumps(data))
    write_comparison([alert], tmp_path, "alerts")
    assert (tmp_path / "m1_per_alert.csv").exists()
    (tmp_path / "m1_per_alert.csv").unlink()
    (tmp_path / "alerts_codex.jsonl").write_text('{}\n')
    write_comparison([alert], tmp_path, "alerts")
    assert not (tmp_path / "m1_per_alert.csv").exists()
