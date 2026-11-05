"""The built evaluation sets keep labels and source names away from the systems."""
import json
from collections import Counter
from pathlib import Path

EVAL = Path(__file__).resolve().parents[1] / "data/eval"


def load(name):
    return [json.loads(l) for l in (EVAL / name).read_text().splitlines() if l.strip()]


def test_sets_are_opaque_and_separate_from_dev():
    dev = {json.loads(l)["source_file"] for l in (EVAL.parents[1] / "examples/alerts.jsonl").read_text().splitlines() if l.strip()}
    for name, prefix in (("evtx_heldout", "H"), ("otrf_pilot", "O")):
        alerts = load(f"{name}.jsonl")
        manifest = json.loads((EVAL / f"{name}_manifest.json").read_text())
        assert all(set(a) == {"alert_id", "host", "events", "label_tactic", "label_verdict"} for a in alerts)
        assert all(a["alert_id"].startswith(prefix) for a in alerts)
        assert not {r["source"].rsplit("/", 1)[-1] for r in manifest["alerts"]} & dev
        stems = [r["source"].rsplit("/", 1)[-1].rsplit(".", 1)[0].lower() for r in manifest["alerts"]]
        blob = (EVAL / f"{name}.jsonl").read_text().lower() + (EVAL / f"{name}_context.jsonl").read_text().lower()
        assert not [s for s in stems if len(s) > 6 and s in blob]
        assert all(3 <= len(a["events"]) <= 20 for a in alerts)
        assert max(Counter(a["label_tactic"] for a in alerts).values()) <= 15


def test_heldout_matches_m1_split():
    alerts = load("evtx_heldout.jsonl")
    assert len(alerts) == 81
    assert json.loads((EVAL / "evtx_heldout_manifest.json").read_text())["usable_per_tactic"]["Privilege Escalation"] == 51


def test_validation_split_never_overlaps_heldout_and_benign_set_is_marked_synthetic():
    held = {r["source"] for r in json.loads((EVAL / "evtx_heldout_manifest.json").read_text())["alerts"]}
    val = {r["source"] for r in json.loads((EVAL / "evtx_val_manifest.json").read_text())["alerts"]}
    assert val and not val & held
    benign = load("benign.jsonl")
    manifest = json.loads((EVAL / "benign_manifest.json").read_text())
    assert manifest["synthetic"] and len(benign) == len(manifest["alerts"]) == 44
    assert {a["label_verdict"] for a in benign} == {"benign"}
    fresh = load("benign_fresh.jsonl")
    sources = lambda n: {r["source"] for r in json.loads((EVAL / f"{n}_manifest.json").read_text())["alerts"]}
    assert len(fresh) == 20 and not sources("benign") & sources("benign_fresh")
