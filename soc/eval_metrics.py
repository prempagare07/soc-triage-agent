"""M2 metrics. A missed attack also counts as an under-escalation, as agreed with Prem."""
import math
from statistics import median
from .schema import ACTION, SEVERITY, TACTICS

RANK = {"close": 0, "monitor": 1, "investigate": 2, "escalate_tier2": 3}
HIGH_STAKES = ("Credential Access", "Lateral Movement")


def zero_miss_bound(n):
    return 1 - 0.05 ** (1 / n) if n else None


def mcnemar(a_only, b_only):
    m = a_only + b_only
    if m == 0:
        return 1.0
    tail = sum(math.comb(m, k) for k in range(min(a_only, b_only) + 1))
    return min(1.0, 2 * tail / 2 ** m)


def score(alerts, records):
    by_id = {r["alert_id"]: r for r in records}
    if len(by_id) != len(records) or len({a["alert_id"] for a in alerts}) != len(alerts):
        raise ValueError("Duplicate alert IDs make evaluation ambiguous")
    rows = []
    for a in alerts:
        r = by_id.get(a["alert_id"], {"status": "failed", "error": "Missing prediction"})
        failed = bool(r.get("parse_failure") or r.get("status") == "failed")
        predicted = "FAILED" if failed else r["tactic"]
        true_t, true_v = a["label_tactic"], a["label_verdict"]
        policy = ACTION[SEVERITY[true_t]]
        ranked = r.get("tactics") or [predicted]
        rows.append({"alert_id": a["alert_id"], "true_tactic": true_t, "pred_tactic": predicted,
                     "failed": failed,
                     "tactic_ok": not failed and predicted == true_t, "top2_ok": not failed and true_t in ranked[:2],
                     "verdict_ok": not failed and r["verdict"] == true_v,
                     "missed": not failed and true_v == "malicious" and r["verdict"] == "benign",
                     "false_pos": not failed and true_v == "benign" and r["verdict"] == "malicious",
                     "under": not failed and RANK[r["action"]] < RANK[policy], "action_ok": not failed and r["action"] == policy,
                     "uncertain": bool(r.get("uncertain")), "parse_failure": bool(r.get("parse_failure")),
                     "record": r})
    return rows


def macro_f1(rows, min_n=5):
    support = {t: sum(r["true_tactic"] == t for r in rows) for t in TACTICS}
    f1s = []
    for t, n in support.items():
        if n < min_n:
            continue
        tp = sum(r["true_tactic"] == t and r["pred_tactic"] == t for r in rows)
        fp = sum(r["true_tactic"] != t and r["pred_tactic"] == t for r in rows)
        p = tp / (tp + fp) if tp + fp else 0
        rc = tp / n
        f1s.append(2 * p * rc / (p + rc) if p + rc else 0)
    return sum(f1s) / len(f1s) if f1s else None, len(f1s)


def summary(rows):
    n = len(rows)
    attacks = [r for r in rows if r["record"] and r["true_tactic"] != "Benign"]
    usage = [r["record"].get("agent") or {} for r in rows]
    secs, tokens = [], []
    for r in rows:
        rec = r["record"]
        cost = rec.get("usage") or rec.get("agent") or {}
        tokens.append(cost)
        sec = (rec.get("agent") or {}).get("seconds", (rec.get("usage") or {}).get("seconds_total"))
        if sec is not None:
            secs.append(sec)
    f1, k = macro_f1(rows)
    claims_ok = sum(r["record"].get("claims_valid", 0) for r in rows)
    claims_n = sum(r["record"].get("claims_total", 0) for r in rows)
    return {
        "n": n,
        "tactic": sum(r["tactic_ok"] for r in rows), "top2": sum(r["top2_ok"] for r in rows),
        "verdict": sum(r["verdict_ok"] for r in rows),
        "missed": [r["alert_id"] for r in rows if r["missed"]],
        "failed": [r["alert_id"] for r in rows if r["failed"]],
        "failed_attacks": [r["alert_id"] for r in attacks if r["failed"]],
        "under": [r["alert_id"] for r in rows if r["under"]],
        "false_pos": [r["alert_id"] for r in rows if r["false_pos"]],
        "benign": sum(r["true_tactic"] == "Benign" for r in rows),
        "under_hs": [r["alert_id"] for r in rows if r["under"] and r["true_tactic"] in HIGH_STAKES],
        "action": sum(r["action_ok"] for r in rows),
        "macro_f1": f1, "macro_f1_tactics": k,
        "uncertain": sum(r["uncertain"] for r in rows), "parse_failures": sum(r["parse_failure"] for r in rows),
        "tool_calls": sum(u.get("tool_calls", 0) for u in usage), "tool_errors": sum(u.get("tool_errors", 0) for u in usage),
        "verifier_failures": sum(u.get("verifier_failures", 0) for u in usage),
        "revised": sum(bool(u.get("revised")) for u in usage),
        "budget_exhausted": sum(bool(u.get("budget_exhausted")) for u in usage),
        "claims_valid": claims_ok, "claims_total": claims_n,
        "p50_s": median(secs) if secs else None,
        "p95_s": sorted(secs)[max(0, math.ceil(0.95 * len(secs)) - 1)] if secs else None,
        "tokens": sum(t.get("prompt_tokens", 0) + t.get("completion_tokens", 0) for t in tokens),
        "attacks": len(attacks),
    }


def pct(x, n):
    return f"{x}/{n} ({100 * x / n:.1f}%)" if n else "n/a"


def report(dataset, results, alerts):
    if not results:
        raise ValueError("No systems to evaluate")
    scored = {name: score(alerts, recs) for name, recs in results.items()}
    sums = {name: summary(rows) for name, rows in scored.items()}
    names = list(results)
    lines = [f"# Results: {dataset}", "", f"Alerts: {len(alerts)}", "",
             "| Metric | " + " | ".join(names) + " |", "| --- |" + " --- |" * len(names)]

    def row(label, fn):
        lines.append(f"| {label} | " + " | ".join(fn(sums[n]) for n in names) + " |")

    row("Tactic accuracy (exact)", lambda s: pct(s["tactic"], s["n"]))
    row("Tactic top-2", lambda s: pct(s["top2"], s["n"]))
    row(f"Macro-F1 (tactics with n>=5)", lambda s: f"{s['macro_f1']:.2f} ({s['macro_f1_tactics']} tactics)" if s["macro_f1"] is not None else "n/a")
    row("Verdict accuracy", lambda s: pct(s["verdict"], s["n"]))
    row("Failed classifications (counted incorrect)", lambda s: pct(len(s["failed"]), s["n"]))
    row("Missed attacks", lambda s: f"{len(s['missed'])}" + (f" ({', '.join(s['missed'][:8])}{'...' if len(s['missed']) > 8 else ''})" if s["missed"] else ""))
    if sums[names[0]]["benign"]:
        row("False positives (benign called malicious)", lambda s: f"{len(s['false_pos'])}/{s['benign']}"
            + (f" ({', '.join(s['false_pos'][:8])}{'...' if len(s['false_pos']) > 8 else ''})" if s["false_pos"] else ""))
    row("Under-escalations (incl. misses)", lambda s: str(len(s["under"])))
    row("  of which Credential Access / Lateral Movement", lambda s: str(len(s["under_hs"])))
    row("Action-level accuracy", lambda s: pct(s["action"], s["n"]))
    row("Uncertain escalations", lambda s: str(s["uncertain"]))
    row("Parse failures", lambda s: str(s["parse_failures"]))
    row("Tool calls (total)", lambda s: str(s["tool_calls"]))
    row("Tool errors", lambda s: str(s["tool_errors"]))
    row("Verifier failures / revisions", lambda s: f"{s['verifier_failures']} / {s['revised']}")
    row("Budget exhausted", lambda s: str(s["budget_exhausted"]))
    row("Claim-level evidence validity", lambda s: pct(s["claims_valid"], s["claims_total"]) if s["claims_total"] else "n/a")
    row("Latency p50 / p95 (s per alert)", lambda s: f"{s['p50_s']:.1f} / {s['p95_s']:.1f}" if s["p50_s"] is not None else "n/a")
    row("Tokens (reported; may include cached calls)", lambda s: str(s["tokens"]))
    row("Zero-miss 95% upper bound (attack denominator)",
        lambda s: f"{zero_miss_bound(s['attacks']):.1%} (N={s['attacks']})"
        if s["attacks"] and not s["missed"] and not s["failed_attacks"] else "n/a")
    lines += ["", "Accuracy denominators include all labelled alerts; missing/failed/parse-failure predictions count as incorrect. "
              "Misses and under-escalations describe completed predictions; failures are listed separately. "
              "Zero-miss bounds apply only with zero misses and no failed attack classifications, assuming independent Bernoulli trials."]
    for name, s in sums.items():
        if s["failed"]:
            lines.append(f"Failed IDs ({name}): {', '.join(s['failed'])}.")
    per_alert = {n: s["tokens"] / s["n"] for n, s in sums.items() if s["n"]}
    if per_alert.get("single_call") and len(per_alert) > 1:
        lines += ["", "Reported tokens per alert relative to the single call (cache use not separated): "
                  + ", ".join(f"{n} {v / per_alert['single_call']:.1f}x" for n, v in per_alert.items() if v)]

    if "agent" in scored:
        lines += ["", "## Paired comparison with the agent (exact McNemar on tactic correctness)", "",
                  "| Baseline | agent right, baseline wrong | baseline right, agent wrong | p |", "| --- | --- | --- | --- |"]
        agent = {r["alert_id"]: r["tactic_ok"] for r in scored["agent"]}
        for name in names:
            if name == "agent":
                continue
            other = {r["alert_id"]: r["tactic_ok"] for r in scored[name]}
            a = sum(agent[i] and not other[i] for i in agent)
            b = sum(other[i] and not agent[i] for i in agent)
            lines.append(f"| {name} | {a} | {b} | {mcnemar(a, b):.3f} |")

    lines += ["", "## Tactic accuracy by true tactic", "", "| True tactic | n | " + " | ".join(names) + " |",
              "| --- | --- |" + " --- |" * len(names)]
    for t in TACTICS:
        n = sum(a["label_tactic"] == t for a in alerts)
        if n:
            cells = [str(sum(r["tactic_ok"] for r in scored[nm] if r["true_tactic"] == t)) for nm in names]
            lines.append(f"| {t} | {n} | " + " | ".join(cells) + " |")
    return "\n".join(lines) + "\n", sums


def cohen_kappa(a, b):
    """Agreement between two raters beyond chance, over the same items."""
    n = len(a)
    if n != len(b):
        raise ValueError("Raters must label the same number of items")
    if not n:
        return None
    seen = sum(x == y for x, y in zip(a, b)) / n
    labels = set(a) | set(b)
    chance = sum((a.count(l) / n) * (b.count(l) / n) for l in labels)
    return 1.0 if chance == 1 else (seen - chance) / (1 - chance)
