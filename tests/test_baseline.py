import json, subprocess, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT))


def test_rules_mode_runs_end_to_end(tmp_path):
    out = tmp_path / "o.jsonl"
    r = subprocess.run([sys.executable, "run_baseline.py", "--input", "examples/alerts.jsonl",
                        "--mode", "rules", "--output", str(out)], cwd=ROOT, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    recs = [json.loads(l) for l in out.read_text().splitlines()]
    assert len(recs) == 28
    assert all(r["action"] in {"escalate_tier2", "investigate", "monitor", "close"} for r in recs)


def test_benign_synthetics_are_closed():
    from soc import rules
    for l in open(ROOT / "examples/alerts.jsonl"):
        a = json.loads(l)
        if a["alert_id"].startswith("B"):
            assert rules.classify(a)["verdict"] == "benign"


def test_lsass_access_is_critical():
    from soc import rules
    a = {"alert_id": "x", "host": "h", "events": [{"event_id": 10, "SourceImage": "C:\\tmp\\p.exe",
         "TargetImage": "C:\\Windows\\system32\\lsass.exe", "GrantedAccess": "0x1010"}]}
    r = rules.classify(a)
    assert r["tactic"] == "Credential Access" and r["action"] == "escalate_tier2" and r["evidence"] == [0]
