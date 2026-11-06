#!/usr/bin/env python3
"""Compare rules, single call, fixed workflow and the agent on one dataset.

  python run_eval.py --dataset dev
"""
import argparse, hashlib, json, platform, subprocess, sys, time
from datetime import datetime, timezone
from pathlib import Path

from soc import rules
from soc.agent import TriageAgent
from soc.human_gate import HumanGate
from soc.baselines import single_call, fixed_workflow
from soc.eval_metrics import report
from soc.local_llm import OllamaLLM

ROOT = Path(__file__).resolve().parent
DATASETS = {"dev": ROOT / "examples/alerts.jsonl",
            "evtx_heldout": ROOT / "data/eval/evtx_heldout.jsonl",
            "otrf_pilot": ROOT / "data/eval/otrf_pilot.jsonl",
            "evtx_val": ROOT / "data/eval/evtx_val.jsonl",
            "benign": ROOT / "data/eval/benign.jsonl",
            "benign_fresh": ROOT / "data/eval/benign_fresh.jsonl"}


def load_jsonl(path):
    return [json.loads(l) for l in Path(path).read_text().splitlines() if l.strip()]


def forbidden_tokens(dataset):
    """Source file names per alert; tools refuse output that contains them."""
    manifest = ROOT / f"data/eval/{dataset}_manifest.json"
    if not manifest.exists():
        return {}
    out = {}
    for row in json.loads(manifest.read_text())["alerts"]:
        stem = row["source"].replace("\\", "/").rsplit("/", 1)[-1].rsplit(".", 1)[0]
        out[row["alert_id"]] = (stem,) if len(stem) > 6 else ()
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", choices=DATASETS, required=True)
    ap.add_argument("--systems", default="rules,single_call,fixed_workflow,agent")
    ap.add_argument("--provider", choices=["ollama", "gemini", "openai"], default="ollama")
    ap.add_argument("--model", help="default: qwen2.5:7b (ollama), gemini-3.5-flash (gemini), gpt-4o-mini (openai)")
    ap.add_argument("--budget", type=int, default=3, help="tool calls the agent may add after the standard enrichment")
    ap.add_argument("--limit", type=int, help="only the first N alerts (pilot)")
    ap.add_argument("--base-url", default="http://localhost:11434")
    ap.add_argument("--out", default="outputs/m2")
    ap.add_argument("--verbose", action="store_true", help="print each agent step as it happens")
    ap.add_argument("--interactive", action="store_true", help="ask a person to approve isolate_host (demo only)")
    a = ap.parse_args()

    alerts = load_jsonl(DATASETS[a.dataset])[: a.limit]
    context = {r["alert_id"]: r["events"] for r in load_jsonl(ROOT / f"data/eval/{a.dataset}_context.jsonl")}
    forbid = forbidden_tokens(a.dataset)
    if a.dataset == "dev":
        forbid = {x["alert_id"]: (x["source_file"].rsplit(".", 1)[0],) for x in alerts if x.get("source_file")}
    if a.provider in ("gemini", "openai"):
        from soc.cloud_llm import GeminiLLM, OpenAILLM
        cls = GeminiLLM if a.provider == "gemini" else OpenAILLM
        a.model = a.model or cls.__init__.__defaults__[0]
        llm = cls(a.model)
    else:
        a.model = a.model or "qwen2.5:7b"
        llm = OllamaLLM(a.model, a.base_url)
    out = Path(a.out) / a.dataset
    (out / "traces").mkdir(parents=True, exist_ok=True)
    suffix = f"_b{a.budget}" if a.budget != 3 else ""

    systems = [s.strip() for s in a.systems.split(",")]
    results = {}
    for name in systems:
        records, t0 = [], time.time()
        gate = HumanGate(a.interactive, out / "approvals.jsonl")
        agent = TriageAgent(llm, a.budget, lambda i: forbid.get(i, ()), gate, a.verbose)
        for n, alert in enumerate(alerts, 1):
            ctx = context.get(alert["alert_id"], [])
            if name == "rules":
                rec = rules.classify(alert)
            elif name == "single_call":
                rec = single_call(alert, llm)
            elif name == "fixed_workflow":
                rec = fixed_workflow(alert, llm, ctx, forbid.get(alert["alert_id"], ()))
            elif name == "agent":
                rec, trace = agent.run(alert, ctx)
                (out / "traces" / f"{alert['alert_id']}{suffix}.json").write_text(json.dumps(trace, indent=1))
            else:
                sys.exit(f"unknown system {name}")
            ok = rec["tactic"] == alert["label_tactic"]
            print(f"[{name} {n}/{len(alerts)}] {alert['alert_id']} {rec['verdict']:<9} {rec['tactic']:<21} "
                  f"-> {rec['action']:<14} {'ok' if ok else 'expected ' + alert['label_tactic']}", flush=True)
            records.append(rec)
        key = name + suffix if name == "agent" else name
        results[key] = records
        (out / f"{key}.jsonl").write_text("".join(json.dumps(r) + "\n" for r in records))
        print(f"{name}: {time.time() - t0:.0f}s\n")

    # include systems saved by earlier runs on the same alerts
    for f in sorted(out.glob("*.jsonl")):
        if f.stem not in results:
            recs = load_jsonl(f)
            if [r["alert_id"] for r in recs] == [x["alert_id"] for x in alerts]:
                results[f.stem] = recs
    order = ["rules", "single_call", "fixed_workflow"] + sorted(k for k in results if k.startswith("agent"))
    results = {k: results[k] for k in order if k in results}
    md, _ = report(a.dataset, results, alerts)
    git = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    meta = {"dataset": a.dataset, "alerts": len(alerts), "model": a.model, "options": llm.options,
            "budget": a.budget, "systems": list(results), "git_commit": git,
            "input_sha256": hashlib.sha256(DATASETS[a.dataset].read_bytes()).hexdigest(),
            "python": platform.python_version(), "finished_at": datetime.now(timezone.utc).isoformat(),
            "command": " ".join([sys.executable, *sys.argv])}
    (out / "run_meta.json").write_text(json.dumps(meta, indent=2) + "\n")
    (out / "results.md").write_text(md + f"\nModel: `{a.model}` ({a.provider}, temperature 0, seed 0). "
                                    f"Command: `{meta['command']}`\n")
    print(md)


if __name__ == "__main__":
    from soc.local_llm import StopRun
    try:
        main()
    except StopRun as exc:
        sys.exit(f"stopped: {exc}")
