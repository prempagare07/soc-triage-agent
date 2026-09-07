#!/usr/bin/env python3
"""SOC alert-triage baseline.

  python run_baseline.py --input examples/alerts.jsonl --mode rules
  python run_baseline.py --input examples/alerts.jsonl --mode llm
  python run_baseline.py --input examples/single_alert.json --mode rules
"""
import argparse, json, os, sys, time
from pathlib import Path
from soc import rules, schema


def load(path: Path):
    if path.suffix == ".jsonl":
        return [json.loads(l) for l in path.read_text().splitlines() if l.strip()]
    return [json.loads(path.read_text())]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--mode", choices=["rules", "llm"], default="rules")
    ap.add_argument("--model", default="gpt-4o-mini")
    ap.add_argument("--output")
    a = ap.parse_args()
    if a.mode == "llm" and not os.environ.get("OPENAI_API_KEY"):
        sys.exit("OPENAI_API_KEY not set. Export it or use --mode rules.")
    if a.mode == "llm":
        from soc import llm
        clf = lambda x: llm.classify(x, a.model)
    else:
        clf = rules.classify

    inp = Path(a.input)
    out = Path(a.output or f"outputs/{inp.stem}_{a.mode}.jsonl")
    out.parent.mkdir(exist_ok=True, parents=True)
    alerts = load(inp)
    res, t0 = [], time.time()
    n_t = c_t = n_v = c_v = 0
    missed_attacks = 0
    for al in alerts:
        r = clf(al); schema.validate(r)
        mark = ""
        if "label_tactic" in al:
            r["label_tactic"], r["label_verdict"] = al["label_tactic"], al["label_verdict"]
            r["tactic_correct"] = r["tactic"] == al["label_tactic"]
            r["verdict_correct"] = r["verdict"] == al["label_verdict"]
            n_t += 1; c_t += r["tactic_correct"]; n_v += 1; c_v += r["verdict_correct"]
            if al["label_verdict"] == "malicious" and r["verdict"] == "benign":
                missed_attacks += 1
            mark = (" ✓" if r["tactic_correct"] else f" ✗ (expected {al['label_tactic']})")
        res.append(r)
        print(f"[{r['alert_id']}] {r['verdict']:<9} {r['severity']:<8} {r['tactic']:<21} -> {r['action']:<14}{mark}")
    with out.open("w") as f:
        for r in res:
            f.write(json.dumps(r) + "\n")
    print(f"\nmode={a.mode}  alerts={len(alerts)}  time={time.time()-t0:.1f}s")
    if n_t:
        print(f"tactic accuracy  = {c_t}/{n_t} = {c_t/n_t:.1%}")
        print(f"verdict accuracy = {c_v}/{n_v} = {c_v/n_v:.1%}   missed attacks (false negatives) = {missed_attacks}")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
