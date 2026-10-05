#!/usr/bin/env python3
"""SOC alert-triage baseline.

  python run_baseline.py --input examples/alerts.jsonl --mode rules
  python run_baseline.py --input examples/alerts.jsonl --mode llm
  python run_baseline.py --input examples/single_alert.json --mode rules
"""
import argparse, json, os, sys, time
import hashlib, platform, subprocess, shutil
from datetime import datetime, timezone
from pathlib import Path
from soc import rules, schema
from soc.sanitize import strip_alert
from soc.metrics import write_metrics, write_comparison

ROOT = Path(__file__).resolve().parent


def git(*args):
    process = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True)
    return process.stdout.strip() if process.returncode == 0 else None


def preserve_outputs(paths, directory):
    """Archive existing artifacts before replacing them, including tracked samples."""
    existing = [path for path in paths if path.exists()]
    if not existing:
        return None
    archive = directory / "history" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    archive.mkdir(parents=True)
    for path in existing:
        shutil.copy2(path, archive / path.name)
    return archive


def load(path: Path):
    if path.suffix == ".jsonl":
        return [json.loads(l) for l in path.read_text().splitlines() if l.strip()]
    return [json.loads(path.read_text())]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--mode", choices=["rules", "llm", "codex"], default="rules")
    ap.add_argument("--model", help="Required for codex; defaults to gpt-4o-mini for llm")
    ap.add_argument("--reasoning-effort", choices=["low", "medium", "high", "xhigh", "max"], default="medium")
    ap.add_argument("--timeout", type=float, default=180)
    ap.add_argument("--cache-dir", default="outputs/codex_cache")
    ap.add_argument("--no-cache", action="store_true")
    ap.add_argument("--output")
    a = ap.parse_args()
    provenance = {"git_commit": git("rev-parse", "HEAD"),
                  "worktree_dirty": None}
    worktree_status = git("status", "--porcelain")
    provenance["worktree_dirty"] = bool(worktree_status) if worktree_status is not None else None
    if a.timeout <= 0:
        ap.error("--timeout must be positive")
    if a.mode == "codex" and not a.model:
        ap.error("--model is required for codex to keep the experiment explicit")
    if a.mode == "llm" and not a.model:
        a.model = "gpt-4o-mini"
    adapter = None
    if a.mode == "codex":
        from soc.codex_cli import Classifier, CodexError
        try:
            adapter = Classifier(a.model, a.reasoning_effort, a.timeout,
                                 None if a.no_cache else a.cache_dir)
        except (OSError, subprocess.SubprocessError) as exc:
            sys.exit(f"Cannot initialize Codex CLI: {exc}")
    if a.mode == "llm" and not os.environ.get("OPENAI_API_KEY"):
        sys.exit("OPENAI_API_KEY not set. Export it or use --mode rules.")
    if a.mode == "llm":
        from soc import llm
        clf = lambda x: llm.classify(x, a.model)
    elif adapter:
        clf = adapter.classify
    else:
        clf = rules.classify

    inp = Path(a.input)
    out = Path(a.output or f"outputs/{inp.stem}_{a.mode}.jsonl")
    out.parent.mkdir(exist_ok=True, parents=True)
    alerts = load(inp)
    if len({alert["alert_id"] for alert in alerts}) != len(alerts):
        sys.exit("Duplicate alert IDs; refusing ambiguous evaluation")
    metadata_path = out.parent / f"run_meta_{inp.stem}_{a.mode}.json"
    archive = preserve_outputs([out, metadata_path,
                                out.parent / f"m1_{a.mode}_metrics.md",
                                out.parent / "m1_metrics.md", out.parent / "m1_per_alert.csv"], out.parent)
    if archive:
        print(f"preserved previous artifacts in {archive}")
    res, t0 = [], time.time()
    started = datetime.now(timezone.utc).isoformat()
    per_alert_metadata = []
    n_t = c_t = n_v = c_v = 0
    missed_attacks = 0
    for al in alerts:
        try:
            r = clf(strip_alert(al)); schema.validate(r)
        except Exception as exc:
            if not adapter:
                raise
            # Adapter errors are safe summaries; never persist arbitrary CLI output.
            error = str(exc) if isinstance(exc, CodexError) else type(exc).__name__
            res.append({"alert_id": al["alert_id"], "status": "failed", "error": error})
            per_alert_metadata.append({"alert_id": al["alert_id"], **adapter.last_metadata, "status": "failed"})
            print(f"[{al['alert_id']}] FAILED: {error}")
            continue
        if adapter:
            per_alert_metadata.append({"alert_id": al["alert_id"], **adapter.last_metadata, "status": "success"})
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
    if n_t and not any(r.get("status") == "failed" for r in res):
        print(f"tactic accuracy  = {c_t}/{n_t} = {c_t/n_t:.1%}")
        print(f"verdict accuracy = {c_v}/{n_v} = {c_v/n_v:.1%}   missed attacks (false negatives) = {missed_attacks}")
    print(f"wrote {out}")
    if adapter or a.mode == "rules":
        failures = sum(r.get("status") == "failed" for r in res)
        usage_rows = [r.get("usage") for r in per_alert_metadata if not r.get("cache_hit")]
        totals = {key: sum(u.get(key, 0) for u in usage_rows if isinstance(u, dict))
                  if usage_rows and all(isinstance(u, dict) and key in u for u in usage_rows) else None
                  for key in ("input_tokens", "cached_input_tokens", "output_tokens")}
        meta = {**provenance,
                "started_at": started, "finished_at": datetime.now(timezone.utc).isoformat(),
                "python_version": platform.python_version(), "mode": a.mode,
                "input_path": str(inp), "input_sha256": hashlib.sha256(inp.read_bytes()).hexdigest(),
                "alert_count": len(alerts), "successful_alerts": len(alerts)-failures,
                "failed_alerts": failures, "retries": 0, "command": [sys.executable, *sys.argv],
                "requested_model": a.model if adapter else None, "actual_model": None,
                "estimated_api_cost": None if adapter else 0,
                "output_path": str(out), "output_sha256": hashlib.sha256(out.read_bytes()).hexdigest(),
                "code_sha256": {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                    for name in ("run_baseline.py", "soc/rules.py", "soc/schema.py", "soc/sanitize.py", "soc/metrics.py")},
                "authentication_type": "none (offline)" if not adapter else "ChatGPT subscription (enforced)",
                "requested_reasoning_effort": None, "effective_reasoning_effort": None,
                "cache_hits": 0, "tokens": None, "usage_source": None,
                "billing_basis": "offline; no model inference" if not adapter else "ChatGPT/Codex subscription allowance",
                "previous_artifacts_archive": str(archive) if archive else None,
                "per_alert": per_alert_metadata}
        if adapter:
            from soc.codex_cli import digest, SYSTEM, OUTPUT_SCHEMA, code_hashes
            meta["code_sha256"].update(code_hashes())
            meta.update({"codex_version": adapter.version, "authentication_type": "ChatGPT subscription (enforced)",
                         "requested_reasoning_effort": a.reasoning_effort, "effective_reasoning_effort": None,
                         "configuration": adapter.configuration, "timeout_seconds": a.timeout,
                         "prompt_sha256": digest(SYSTEM), "schema_sha256": digest(OUTPUT_SCHEMA),
                         "adapter_sha256": meta["code_sha256"]["soc/codex_cli.py"],
                         "cache_hits": sum(r.get("cache_hit", False) for r in per_alert_metadata),
                         "tokens": totals, "usage_source": "codex exec turn.completed usage",
                         "usage_includes_cache_hits": False, "billing_basis": "ChatGPT/Codex subscription allowance",
                         "usage_includes_failed_attempts": "Only when a failed attempt exposes usage; otherwise aggregate totals are null, not zero.",
                         "cli_arguments": next((r.get("cli_arguments") for r in per_alert_metadata if r.get("cli_arguments")), None),
                         "attempted_alerts": sum(r.get("attempted", False) for r in per_alert_metadata),
                         "temperature": None, "seed": None, "system_fingerprint": None,
                         "unavailable_fields": "CLI events do not reliably expose resolved model, effective effort, temperature, seed, fingerprint or dollar cost; missing token fields are null."})
        metadata_path.write_text(json.dumps(meta, indent=2) + "\n")
        saved_records = [json.loads(line) for line in out.read_text().splitlines() if line.strip()]
        report = write_metrics(alerts, saved_records, a.mode, out.parent / f"m1_{a.mode}_metrics.md")
        report += "\n\nCommand: `" + " ".join([sys.executable, *sys.argv]) + "`\n"
        (out.parent / f"m1_{a.mode}_metrics.md").write_text(report)
        # Include only reports whose metadata matches this input and saved output.
        reports = []
        for mode in ("rules", "codex"):
            other_meta = out.parent / f"run_meta_{inp.stem}_{mode}.json"
            other_report = out.parent / f"m1_{mode}_metrics.md"
            if other_meta.exists() and other_report.exists():
                other = json.loads(other_meta.read_text())
                other_output = Path(other["output_path"]) if "output_path" in other else None
                if (other.get("input_sha256") == meta["input_sha256"] and other_output and
                        other_output.exists() and hashlib.sha256(other_output.read_bytes()).hexdigest() == other.get("output_sha256")):
                    reports.append(other_report.read_text())
        (out.parent / "m1_metrics.md").write_text("\n\n".join(reports))
        write_comparison(alerts, out.parent, inp.stem)
        print(f"wrote {metadata_path}")
        if failures:
            print(f"{failures} failures; complete-run metrics in m1_{a.mode}_metrics.md")
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
