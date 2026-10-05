"""Constructed classifier boundaries, without live model calls."""
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

from soc import llm, rules
from soc.codex_cli import Classifier, CONFIG, DISABLED, OUTPUT_SCHEMA
from soc.sanitize import strip_alert

ROOT = Path(__file__).resolve().parents[1]
ALERTS = [json.loads(line) for line in (ROOT / "examples/alerts.jsonl").read_text().splitlines()]


def assert_no_metadata(text, alert):
    for token in ("source_file", "label_tactic", "label_verdict", "EVTX-ATTACK-SAMPLES",
                  alert["source_file"], Path(alert["source_file"]).stem):
        assert token.casefold() not in text.casefold()
    # Tactic names in the fixed instructions/schema are valid output choices,
    # rather than a ground-truth label supplied for this alert.


def test_independent_copy_and_exact_keys():
    original = deepcopy(ALERTS[0])
    original["extra"] = {"private": "discard me"}
    before = deepcopy(original)
    sanitized = strip_alert(original)
    assert set(sanitized) == {"alert_id", "host", "events"}
    assert sanitized["events"] == original["events"]
    sanitized["events"][0]["new"] = ["changed"]
    sanitized["events"].append({})
    assert original == before


@pytest.mark.parametrize("alert", ALERTS, ids=lambda a: a["alert_id"])
def test_dev_alert_direct_boundaries(monkeypatch, tmp_path, alert):
    before = deepcopy(alert)
    sanitized = strip_alert(alert)
    assert_no_metadata(json.dumps(sanitized), alert)
    assert rules.classify(alert) == rules.classify(sanitized)
    seen = []
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("CODEX_API_KEY", raising=False)
    cache = tmp_path / "offline-cache"
    cache.mkdir()
    (cache / "offline-evaluation.json").write_text(json.dumps(alert))

    def run(command, **kwargs):
        if command[-1] == "--version":
            return SimpleNamespace(stdout="codex-cli test", returncode=0)
        directory = Path(kwargs["cwd"])
        assert directory.resolve() != ROOT
        assert not directory.resolve().is_relative_to(ROOT)
        assert command[command.index("--cd") + 1] == str(directory)
        assert {p.name for p in directory.iterdir()} == {"instructions.txt", "schema.json"}
        instructions = (directory / "instructions.txt").read_text()
        schema = (directory / "schema.json").read_text()
        assert instructions == llm.SYSTEM
        assert json.loads(schema) == OUTPUT_SCHEMA
        for content in (kwargs["input"], instructions, schema, json.dumps(command)):
            assert_no_metadata(content, alert)
        payload = json.loads(kwargs["input"])
        assert payload == {"host": alert["host"], "events": [
            {**event, "index": i} for i, event in enumerate(alert["events"])]}
        for flag in ("--ignore-user-config", "--ignore-rules", "--ephemeral", "--skip-git-repo-check"):
            assert flag in command
        assert command[command.index("--sandbox") + 1] == "read-only"
        settings = [command[i + 1] for i, arg in enumerate(command) if arg == "-c"]
        assert set(CONFIG).issubset(settings)
        assert 'model_reasoning_effort="medium"' in settings
        assert {command[i + 1] for i, arg in enumerate(command) if arg == "--disable"} == set(DISABLED)
        assert {"shell_tool", "apps", "plugins", "multi_agent", "hooks", "memories",
                "skill_search", "code_mode_host"}.issubset(DISABLED)
        assert "OPENAI_API_KEY" not in kwargs["env"]
        assert "CODEX_API_KEY" not in kwargs["env"]
        seen.append(str(directory))
        Path(command[command.index("--output-last-message") + 1]).write_text(json.dumps({
            "verdict": "benign", "tactic": "Benign", "evidence": [], "analyst_note": "Normal."}))
        return SimpleNamespace(returncode=0, stdout=json.dumps({"type": "turn.completed"}))

    monkeypatch.setattr(subprocess, "run", run)
    # Place a labelled offline cache next to, never inside, the scratch directory.
    classifier = Classifier("explicit-model", cache_dir=cache)
    classifier.classify(alert)
    assert len(seen) == 1
    assert not Path(seen[0]).exists()
    assert alert == before


@pytest.mark.parametrize("alert", ALERTS, ids=lambda a: a["alert_id"])
def test_optional_api_direct_boundary(monkeypatch, alert):
    calls = []
    def create(**kwargs):
        calls.append(kwargs)
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=json.dumps({
            "verdict": "benign", "tactic": "Benign", "evidence": [], "analyst_note": "Normal."})))])
    def client(**kwargs):
        return SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create)))
    monkeypatch.setitem(sys.modules, "openai", SimpleNamespace(OpenAI=client))
    monkeypatch.setenv("OPENAI_API_KEY", "dummy-test-value")
    before = deepcopy(alert)
    llm.classify(alert)
    request = calls[0]
    assert request["messages"][0]["content"] == llm.SYSTEM
    assert_no_metadata(json.dumps(request), alert)
    assert json.loads(request["messages"][1]["content"]) == {"host": alert["host"], "events": [
        {"index": i, **event} for i, event in enumerate(alert["events"])]}
    assert alert == before


@pytest.mark.parametrize("embedded", [
    {"label_tactic": "Credential Access"}, {"nested": [{"label_verdict": "malicious"}]},
    {"note": "source_file: private.evtx"},
    {"note": "C:\\corpus\\EVTX-ATTACK-SAMPLES\\Execution\\private.evtx"},
    {"note": "/corpus/private.evtx"}, {"note": "PRIVATE"},
])
def test_nested_leakage_rejected_before_classification(monkeypatch, embedded):
    alert = {"alert_id": "a", "host": "h", "events": [embedded], "source_file": "private.evtx"}
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: SimpleNamespace(stdout="test", returncode=0))
    classifier = Classifier("explicit-model")
    # No API SDK installed or credentials supplied for these rejected inputs.
    monkeypatch.delitem(sys.modules, "openai", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    for classify in (strip_alert, rules.classify, llm.classify, classifier.classify):
        with pytest.raises(ValueError, match="Evaluation metadata embedded"):
            classify(alert)


def test_host_corpus_path_rejected():
    with pytest.raises(ValueError, match="Evaluation metadata embedded"):
        strip_alert({"alert_id": "a", "host": "/EVTX-ATTACK-SAMPLES/host", "events": []})


def test_rules_match_saved_measured_predictions():
    saved = ROOT / "outputs/alerts_rules.jsonl"
    predictions = {row["alert_id"]: row for row in map(json.loads, saved.read_text().splitlines())}
    for alert in ALERTS:
        result = rules.classify(alert)
        assert result == {key: predictions[alert["alert_id"]][key] for key in result}
