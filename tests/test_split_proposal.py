import hashlib
import json
from pathlib import Path

import pytest

from data.freeze_manifest import build_manifest, resolve_source
from data.split_numbers import allocations, exact_mcnemar, simulate_power, verify_audit, wilson, zero_miss_bound


def write_split(path, alerts, ending=b"\n"):
    path.write_bytes(ending.join(json.dumps(a).encode() for a in alerts) + ending)


def test_manifest_exact_bytes_and_zip_provenance(tmp_path):
    corpus = tmp_path / "corpus"
    folder = corpus / "Execution"
    folder.mkdir(parents=True)
    capture = folder / "capture.evtx"
    capture.write_bytes(b"original capture bytes")
    split = tmp_path / "split.jsonl"
    write_split(split, [{"alert_id": "a", "source_file": "Execution/capture.evtx"}], ending=b"\r\n")
    manifest = build_manifest(split, corpus, demo=True)
    assert manifest["split_sha256"] == hashlib.sha256(split.read_bytes()).hexdigest()
    assert manifest["alerts"][0]["line_sha256"] == manifest["split_sha256"]
    assert manifest["alerts"][0]["capture_sha256"] == hashlib.sha256(capture.read_bytes()).hexdigest()
    assert manifest["corpus"]["commit"] is None
    assert manifest["corpus"]["explanation"]
    assert manifest["purpose"] == "dev_demo"
    assert manifest["held_out_frozen"] is False
    original = manifest["split_sha256"]
    split.write_bytes(split.read_bytes().rstrip(b"\r\n"))
    changed = build_manifest(split, corpus)
    assert changed["split_sha256"] != original
    assert changed["alerts"][0]["line_sha256"] == changed["split_sha256"]
    capture.write_bytes(b"changed capture bytes")
    assert build_manifest(split, corpus)["alerts"][0]["capture_sha256"] != manifest["alerts"][0]["capture_sha256"]


def test_source_resolution_never_uses_label_to_break_ties(tmp_path):
    corpus = tmp_path / "corpus"
    paths = []
    for folder in ("Execution", "Persistence"):
        path = corpus / folder / "same.evtx"
        path.parent.mkdir(parents=True)
        path.write_bytes(folder.encode())
        paths.append(path)
    with pytest.raises(ValueError, match="ambiguous"):
        resolve_source("same.evtx", corpus)
    assert resolve_source("Execution/same.evtx", corpus) == paths[0]
    assert resolve_source("Persistence\\same.evtx", corpus) == paths[1]
    with pytest.raises(ValueError, match="Missing"):
        resolve_source("Discovery/same.evtx", corpus)
    with pytest.raises(ValueError, match="relative"):
        resolve_source("../same.evtx", corpus)
    split = tmp_path / "split.jsonl"
    write_split(split, [{"alert_id": "a", "source_file": "same.evtx", "label_tactic": "Execution"}])
    with pytest.raises(ValueError, match="ambiguous"):
        build_manifest(split, corpus)


@pytest.mark.parametrize("case", ["duplicate_id", "duplicate_capture", "missing", "blank", "empty"])
def test_manifest_rejects_invalid_split(tmp_path, case):
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "one.evtx").write_bytes(b"capture")
    split = tmp_path / "split.jsonl"
    alerts = [{"alert_id": "a", "source_file": "one.evtx"}]
    if case == "duplicate_id":
        alerts.append({"alert_id": "a", "source_file": "other.evtx"})
    elif case == "duplicate_capture":
        alerts.append({"alert_id": "b", "source_file": "one.evtx"})
    elif case == "missing":
        alerts[0]["source_file"] = "missing.evtx"
    write_split(split, alerts)
    if case == "blank":
        split.write_bytes(split.read_bytes() + b"\n")
    elif case == "empty":
        split.write_bytes(b"")
    with pytest.raises(ValueError):
        build_manifest(split, corpus)


def test_synthetic_provenance_is_explicit(tmp_path):
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    split = tmp_path / "split.jsonl"
    write_split(split, [{"alert_id": "b", "source_file": "synthetic_benign_demo.json", "label_verdict": "benign"}])
    result = build_manifest(split, corpus)
    assert result["synthetic_count"] == 1 and result["evtx_capture_count"] == 0
    assert result["alerts"][0]["capture_sha256"] is None
    assert result["alerts"][0]["provenance_note"]


def test_source_symlink_cannot_escape_corpus(tmp_path):
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    external = tmp_path / "outside.evtx"
    external.write_bytes(b"outside capture")
    (corpus / "linked.evtx").symlink_to(external)
    with pytest.raises(ValueError, match="outside corpus"):
        resolve_source("linked.evtx", corpus)


def test_manifest_rejects_non_object_json(tmp_path):
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    split = tmp_path / "split.jsonl"
    split.write_bytes(b"[]\n")
    with pytest.raises(ValueError, match="JSON object"):
        build_manifest(split, corpus)


def test_audit_input_hash_mismatch_stops_proposal(tmp_path):
    dev = tmp_path / "dev.jsonl"
    dev.write_bytes(b"changed dev input")
    report = tmp_path / "audit.md"
    report.write_text('```json\n{"input_sha256": "old-hash"}\n```\n')
    with pytest.raises(ValueError, match="input_sha256"):
        verify_audit(tmp_path / "unused.csv", report, dev, tmp_path)


def test_wilson_and_zero_population():
    lo, hi, half = wilson(50, 100)
    assert half == pytest.approx(0.0961684696)
    assert lo == pytest.approx(1-hi)
    assert wilson(0, 0) is None and zero_miss_bound(0) is None
    assert zero_miss_bound(1) == 1
    assert zero_miss_bound(60) == 0.05
    # Odd N uses floor(N/2); interval radius remains half the endpoint span.
    lo, hi, half = wilson(42, 85)
    assert half == pytest.approx((hi-lo)/2)
    assert (lo+hi)/2 < 0.5
    for successes, n in ((1, 0), (-1, 10), (11, 10)):
        with pytest.raises(ValueError):
            wilson(successes, n)


def test_exact_conditional_binomial_edges():
    assert exact_mcnemar(0, 0) == 1
    assert exact_mcnemar(5, 5) == 1
    assert exact_mcnemar(0, 5) == 0.0625
    assert exact_mcnemar(0, 6) == 0.03125
    assert exact_mcnemar(1, 9) == pytest.approx(22/1024)
    assert exact_mcnemar(9, 1) == exact_mcnemar(1, 9)
    with pytest.raises(ValueError):
        exact_mcnemar(-1, 2)


def test_simulation_reproducibility_and_no_discordance_rejection():
    results = simulate_power(ns=(5,), rates=(0.2,), trials=100, seed=0)
    assert results == simulate_power(ns=(5,), rates=(0.2,), trials=100, seed=0)
    assert results[0]["rejections"] == 0  # Even five entirely one-sided pairs cannot reject.
    assert results[0]["baseline_only_probability"] == pytest.approx(0.025)
    assert results[0]["agent_only_probability"] == pytest.approx(0.175)
    with pytest.raises(ValueError):
        simulate_power(rates=(0.1,), trials=10)


def test_allocation_caps_never_oversample():
    counts = {"Command and Control": 1, "Credential Access": 13, "Defense Evasion": 14,
              "Discovery": 2, "Execution": 16, "Lateral Movement": 22,
              "Persistence": 6, "Privilege Escalation": 51}
    policies = allocations(counts)
    assert [sum(p.values()) for p in policies.values()] == [125, 81, 69]
    assert all(n <= counts[t] for p in policies.values() for t, n in p.items())
