"""Evaluate saved records, counting failed classifications in denominators."""
import csv
import json
import hashlib
from collections import Counter
from .schema import ACTION, SEVERITY

RANK = {"close": 0, "monitor": 1, "investigate": 2, "escalate_tier2": 3}


def write_metrics(alerts, records, mode, output):
    labelled = [a for a in alerts if "label_tactic" in a and "label_verdict" in a]
    by_id = {r["alert_id"]: r for r in records}
    n = len(labelled)
    correct_t = correct_v = 0
    missed, under, critical_under, failed = [], [], [], []
    tactics, actions, per_tactic = Counter(), Counter(), {}
    for alert in labelled:
        rec = by_id[alert["alert_id"]]
        tactic, verdict = alert["label_tactic"], alert["label_verdict"]
        ok = rec.get("status") != "failed"
        predicted = rec.get("tactic", "FAILED")
        predicted_action = rec.get("action", "FAILED")
        tc = ok and predicted == tactic
        correct_t += tc
        correct_v += ok and rec.get("verdict") == verdict
        counts = per_tactic.setdefault(tactic, [0, 0])
        counts[0] += tc
        counts[1] += 1
        true_action = ACTION[SEVERITY[tactic]]
        tactics[tactic, predicted] += 1
        actions[true_action, predicted_action] += 1
        if not ok:
            failed.append(alert["alert_id"])
        elif verdict == "malicious" and rec["verdict"] == "benign":
            missed.append(alert["alert_id"])
        if ok and RANK[predicted_action] < RANK[true_action]:
            under.append(alert["alert_id"])
            if tactic in ("Credential Access", "Lateral Movement"):
                critical_under.append(alert["alert_id"])
    def accuracy(c):
        return f"{c}/{n} ({c/n:.1%})" if n else "N/A (0 labelled alerts)"
    lines = [f"# {mode} baseline metrics", "", f"Tactic accuracy: {accuracy(correct_t)}",
             f"Verdict accuracy: {accuracy(correct_v)}", f"Missed attacks: {len(missed)} {missed}",
             f"Under-escalations: {len(under)} {under}",
             f"Credential Access / Lateral Movement under-escalations: {len(critical_under)} {critical_under}",
             f"Failed classifications: {len(failed)} {failed}", "",
             "Accuracy denominators include all labelled alerts; failures count as incorrect.",
             "Misses and under-escalations describe successful predictions only; failures are reported separately.",
             "", "## Per-tactic accuracy", "", "| Tactic | Correct / total |", "|---|---|"]
    lines += [f"| {t} | {c}/{total} |" for t, (c, total) in sorted(per_tactic.items())]
    if failed:
        lines += ["", "## Failure causes", ""]
        lines += [f"- {alert_id}: {by_id[alert_id].get('error', 'unspecified failure')}" for alert_id in failed]
    for title, matrix in (("Tactic confusion (true × predicted)", tactics),
                          ("Action confusion (policy true × predicted)", actions)):
        columns = sorted({b for a, b in matrix})
        lines += ["", f"## {title}", "", "| True | " + " | ".join(columns) + " |",
                  "|---|" + "---|" * len(columns)]
        lines += ["| " + a + " | " + " | ".join(str(matrix[a, b]) for b in columns) + " |"
                  for a in sorted({a for a, b in matrix})]
    output.write_text("\n".join(lines) + "\n")
    return "\n".join(lines)


def write_comparison(alerts, directory, stem):
    paths = [directory / f"{stem}_{mode}.jsonl" for mode in ("rules", "codex")]
    if not all(p.exists() for p in paths):
        return
    metadata = [directory / f"run_meta_{stem}_{mode}.json" for mode in ("rules", "codex")]
    if not all(p.exists() for p in metadata):
        return
    run_metadata = [json.loads(p.read_text()) for p in metadata]
    hashes = [m.get("input_sha256") for m in run_metadata]
    if not hashes[0] or hashes[0] != hashes[1]:
        return
    if any(hashlib.sha256(p.read_bytes()).hexdigest() != m.get("output_sha256")
           for p, m in zip(paths, run_metadata)):
        return
    results = [{r["alert_id"]: r for r in map(json.loads, p.read_text().splitlines())} for p in paths]
    with (directory / "m1_per_alert.csv").open("w", newline="") as handle:
        fields = ["alert_id", "true_tactic"] + [f"{mode}_{key}" for mode in ("rules", "codex")
                    for key in ("tactic", "correct", "action", "under_escalation", "status")]
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for a in alerts:
            if "label_tactic" not in a:
                continue
            row = {"alert_id": a["alert_id"], "true_tactic": a["label_tactic"]}
            true_rank = RANK[ACTION[SEVERITY[a["label_tactic"]]]]
            for mode, records in zip(("rules", "codex"), results):
                r = records.get(a["alert_id"], {})
                row.update({f"{mode}_tactic": r.get("tactic", "FAILED"),
                            f"{mode}_correct": r.get("tactic") == a["label_tactic"],
                            f"{mode}_action": r.get("action", "FAILED"),
                            f"{mode}_under_escalation": RANK[r["action"]] < true_rank if "action" in r else "",
                            f"{mode}_status": r.get("status", "success" if r else "missing")})
            writer.writerow(row)
