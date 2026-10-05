"""Verify the offline audit and generate split allocations and power estimates."""
import argparse
from collections import Counter
import csv
from functools import lru_cache
import json
import math
from pathlib import Path
import random
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from data import build_dataset as builder
from data.audit_corpus import WIDER
from data.freeze_manifest import build_manifest, corpus_provenance, evtx_inventory, sha256


def wilson(successes, n):
    if n < 0 or successes < 0 or successes > n:
        raise ValueError("Invalid binomial counts")
    if n == 0:
        return None
    z = 1.959963984540054
    p = successes / n
    denominator = 1 + z*z/n
    midpoint = (p + z*z/(2*n)) / denominator
    radius = z * math.sqrt(p*(1-p)/n + z*z/(4*n*n)) / denominator
    return midpoint - radius, midpoint + radius, radius


def zero_miss_bound(n):
    if n < 0:
        raise ValueError("Negative population")
    return min(1.0, 3/n) if n else None


@lru_cache(maxsize=None)
def exact_mcnemar(baseline_only, agent_only):
    if baseline_only < 0 or agent_only < 0:
        raise ValueError("Negative discordant count")
    m = baseline_only + agent_only
    if m == 0:
        return 1.0
    # Equal-probability null is symmetric: double the smaller inclusive tail.
    tail = sum(math.comb(m, k) for k in range(min(baseline_only, agent_only) + 1))
    return min(1.0, 2*tail/(2**m))


def simulate_power(ns=(60, 85, 100), rates=(0.20, 0.30, 0.40), trials=10000, seed=0):
    if trials <= 0 or any(n <= 0 for n in ns):
        raise ValueError("Positive trial and attack counts required")
    rng, results = random.Random(seed), []
    for n in ns:
        for d in rates:
            if not 0.15 <= d <= 1:
                raise ValueError("Discordance must accommodate a 0.15 gain")
            baseline_prob, agent_prob = (d-0.15)/2, (d+0.15)/2
            rejected = 0
            for _ in range(trials):
                baseline_only = agent_only = 0
                for _ in range(n):
                    u = rng.random()
                    if u < baseline_prob:
                        baseline_only += 1
                    elif u < baseline_prob + agent_prob:
                        agent_only += 1
                rejected += exact_mcnemar(baseline_only, agent_only) <= 0.05
            power = rejected/trials
            results.append({"n": n, "d": d, "baseline_only_probability": baseline_prob,
                            "agent_only_probability": agent_prob, "rejections": rejected,
                            "trials": trials, "power": power,
                            "mc_se": math.sqrt(power*(1-power)/trials)})
    return results


def flag(row, key):
    if row[key] not in ("True", "False"):
        raise ValueError(f"Invalid audit boolean: {key}")
    return row[key] == "True"


def verify_audit(csv_path, report_path, dev_path, corpus):
    report = report_path.read_text()
    match = re.search(r"```json\n(.*?)\n```", report, re.S)
    if not match:
        raise ValueError("Missing audit provenance")
    provenance = json.loads(match.group(1))
    for name, path in (("input_sha256", dev_path), ("builder_sha256", ROOT / "data/build_dataset.py"),
                       ("audit_script_sha256", ROOT / "data/audit_corpus.py")):
        if sha256(path.read_bytes()) != provenance[name]:
            raise ValueError(f"Audit provenance mismatch: {name}")
    actual = corpus_provenance(corpus)
    if actual["commit"] != provenance["corpus_commit"] or actual["dirty"]:
        raise ValueError("Corpus revision/cleanliness differs from audited state")
    if provenance["corpus_commit_after"] != actual["commit"]:
        raise ValueError("Audit changed corpus revision")
    rows = list(csv.DictReader(csv_path.open(newline="")))
    paths = {p.relative_to(corpus).as_posix(): p for p in evtx_inventory(corpus)}
    if len({r["file"] for r in rows}) != len(rows) or set(paths) != {r["file"] for r in rows}:
        raise ValueError("Audit inventory mismatch or duplicate rows")
    for row in rows:
        if sha256(paths[row["file"]].read_bytes()) != row["source_sha256"]:
            raise ValueError(f"Capture changed since audit: {row['file']}")
        parts = Path(row["file"]).parts
        expected_scope = len(parts) == 2 and parts[0] in builder.TACTICS
        if flag(row, "in_scope") != expected_scope:
            raise ValueError("Audit scope mismatch")
        if expected_scope:
            if row["folder"] != parts[0] or row["status"] != "ok" or row["error"]:
                raise ValueError("Audit contains an in-scope error or folder mismatch")
            for setting in ("current", "wide"):
                if flag(row, f"qualifies_{setting}") != (int(row[f"events_kept_{setting}"]) >= 3):
                    raise ValueError("Eligibility mismatch")
    demo = build_manifest(dev_path, corpus, demo=True)
    used = {r["capture_path"] for r in demo["alerts"] if r["source_kind"] == "evtx"}
    if len(used) != 24 or used != {r["file"] for r in rows if flag(r, "used_in_dev")}:
        raise ValueError("Dev capture exclusion mismatch")
    for setting, ids in (("Current", builder.KEEP_IDS), ("Wider", builder.KEEP_IDS | WIDER)):
        recorded = re.search(rf"^{setting}: ([0-9, ]+)\.", report, re.M)
        if not recorded or set(recorded.group(1).split(", ")) != ids:
            raise ValueError("Audit event-ID set mismatch")
    current = [r for r in rows if flag(r, "in_scope") and not flag(r, "used_in_dev") and flag(r, "qualifies_current")]
    wide = [r for r in rows if flag(r, "in_scope") and not flag(r, "used_in_dev") and flag(r, "qualifies_wide")]
    if builder.KEEP_IDS == builder.KEEP_IDS | WIDER:
        if {r["file"] for r in current} != {r["file"] for r in wide} or any(
                r["events_kept_current"] != r["events_kept_wide"] for r in rows):
            raise ValueError("Identical settings have differing audited results")
    dev_hashes = {r["capture_sha256"] for r in demo["alerts"] if r["capture_sha256"]}
    collisions = [r["file"] for r in current if r["source_sha256"] in dev_hashes]
    duplicates = [h for h, n in Counter(r["source_sha256"] for r in current).items() if n > 1]
    if collisions or duplicates:
        raise ValueError("Qualifying candidates contain byte duplicates; deduplicate before allocating")
    if corpus_provenance(corpus) != actual:
        raise ValueError("Corpus changed during verification")
    return provenance, actual, rows, current, wide


def allocations(counts):
    return {policy: {t: min(counts[t], cap) if cap else counts[t] for t in builder.TACTICS}
            for policy, cap in (("A: all available", None), ("B: cap 15", 15), ("C: cap 12", 12))}


def make_report(args):
    provenance, actual, rows, current, wide = verify_audit(args.audit_csv, args.audit_md, args.dev, args.corpus)
    counts = Counter(r["folder"] for r in current)
    wide_counts = Counter(r["folder"] for r in wide)
    policies = allocations(counts)
    power = simulate_power()
    command = "python data/split_numbers.py --corpus ../EVTX-ATTACK-SAMPLES"
    lines = ["# Held-out split proposal (not frozen)", "", f"Command: `{command}`", "",
             "## Verified provenance", "", f"Corpus commit: `{actual['commit']}`; checkout clean.",
             f"Dev SHA256: `{provenance['input_sha256']}`.",
             f"Builder SHA256: `{provenance['builder_sha256']}`.",
             f"Audit script SHA256: `{provenance['audit_script_sha256']}`.",
             f"Audit CSV SHA256: `{sha256(args.audit_csv.read_bytes())}`.",
             f"Audit Markdown SHA256: `{sha256(args.audit_md.read_bytes())}`.", "",
             f"Verified inventory and every capture SHA256: {len(rows)}/{len(rows)} files. "
             "All 24 dev EVTX sources resolve uniquely and match audit exclusions. "
             "No unused qualifying candidate is a byte duplicate of a dev capture or another candidate.", "",
             "Eligibility is one unused direct-child capture in a builder tactic folder with at least "
             "three retained events under default parse() truncation (last 20 events). "
             "Out-of-scope captures are not eligible automatically.", "",
             "## Availability and allocation", "",
             "Current and wider settings are identical; newly added IDs: none.",
             "Both sets: " + ", ".join(sorted(builder.KEEP_IDS, key=int)) + ".", "",
             "| Tactic | Current unused qualifying | Wider unused qualifying | A | B (cap 15) | C (cap 12) |",
             "|---|---:|---:|---:|---:|---:|---:|"]
    for tactic in builder.TACTICS:
        lines.append(f"| {tactic} | {counts[tactic]} | {wide_counts[tactic]} | " +
                     " | ".join(str(p[tactic]) for p in policies.values()) + " |")
    totals = [sum(p.values()) for p in policies.values()]
    lines += [f"| Total attacks | {len(current)} | {len(wide)} | " + " | ".join(map(str, totals)) + " |", "",
              "Counts exclude all dev captures. No duplicates are oversampled to fill caps.", "",
              "| Policy | N attacks | Eligible macro-F1 classes (n >= 5) | Case studies (n < 5) |",
              "|---|---:|---|---|"]
    for name, allocation in policies.items():
        eligible = [t for t, n in allocation.items() if n >= 5]
        thin = [f"{t} (n={n})" for t, n in allocation.items() if n < 5]
        lines.append(f"| {name} | {sum(allocation.values())} | {', '.join(eligible)} | {', '.join(thin)} |")
    lines += ["", "Define primary macro-F1 as the arithmetic mean of per-class F1 over exactly "
              "Credential Access, Defense Evasion, Execution, Lateral Movement, Persistence, and "
              "Privilege Escalation. Compute each class's TP/FP/FN across the entire same tested "
              "population (including thin tactics and benign cases); do not discard their false "
              "positives. Zero-denominator class F1 is 0. Report Command and Control and Discovery "
              "predictions as case studies with correct/total; they do not enter this macro mean. "
              "Failures count as incorrect/FN for their true class and are reported separately. "
              "Any approved label changes require recomputing counts and fixing the eligible set "
              "before results are seen. Benign performance is reported separately.", "",
              "## Precision and zero-miss limits", "",
              "Wilson uses z=1.959963984540054. Near 0.5, successes=floor(N/2), "
              "so odd N rounds down. Half-width is (upper-lower)/2, not distance from the sample "
              "proportion to either endpoint. Percentages below are rounded to two decimals.", "",
              "| Policy | N | Assumed correct | Wilson 95% interval | Half-width (points) | Zero-miss 3/N upper bound |",
              "|---|---:|---:|---|---:|---:|"]
    for name, allocation in policies.items():
        n = sum(allocation.values())
        lo, hi, radius = wilson(n//2, n)
        lines.append(f"| {name} | {n} | {n//2} | {lo:.2%}–{hi:.2%} | {radius*100:.2f} | {zero_miss_bound(n):.2%} |")
    lines += ["", "| Policy | Credential Access N | CA zero-miss bound | Lateral Movement N | LM zero-miss bound | Combined CA/LM N | Combined bound |",
              "|---|---:|---:|---:|---:|---:|---:|"]
    for name, allocation in policies.items():
        ca, lm = allocation["Credential Access"], allocation["Lateral Movement"]
        lines.append(f"| {name} | {ca} | {zero_miss_bound(ca):.2%} | {lm} | {zero_miss_bound(lm):.2%} | {ca+lm} | {zero_miss_bound(ca+lm):.2%} |")
    lines += ["", "The rule of three is an approximate one-sided 95% upper probability bound after "
              "zero observed misses in N independent Bernoulli attack trials with a common miss "
              "probability; it is not a guarantee of zero future misses. Display min(1,3/N); "
              "small subgroup approximations are rough. N=0 yields null/not estimable, never zero. "
              "Use each tested attack subgroup's own N for its verdict-miss and under-escalation "
              "bound; report these outcomes separately. Failures prevent a claim of zero misses "
              "unless explicitly resolved and reported. Benign alerts never enlarge the attack "
              "denominator. Correlated scenario captures can make these nominal limits optimistic. "
              "Wilson accuracy denominators change if reporting the mixed benign/attack population.", "",
              "## Exact paired McNemar power simulation", "",
              "10,000 trials per cell; random.Random seed 0, one continuous stream in ascending "
              "N then d order. Alpha=0.05, reject when exact two-sided p <= alpha. "
              "Each trial samples N independent paired correctness outcomes. Baseline-only "
              "probability=(d-0.15)/2; agent-only=(d+0.15)/2; remainder=1-d concordant. "
              "The split of concordant outcomes into both-right/both-wrong does not affect "
              "McNemar and is not assumed. Under the null, conditional on m discordant pairs, "
              "baseline-only is Binomial(m,0.5). p=min(1,2*smaller inclusive binomial tail); "
              "m=0 gives p=1. These are hypothetical 15-point gains with homogeneous discordance, "
              "not measured achievements or guarantees. Only standard-library random/math "
              "are used; no added statistical dependency.", "",
              "| N | d | Baseline-only probability | Agent-only probability | Rejections / trials | Estimated power | Monte Carlo SE (points) |",
              "|---:|---:|---:|---:|---:|---:|---:|"]
    for row in power:
        lines.append(f"| {row['n']} | {row['d']:.2f} | {row['baseline_only_probability']:.3f} | {row['agent_only_probability']:.3f} | {row['rejections']}/{row['trials']} | {row['power']:.2%} | {100*row['mc_se']:.2f} |")
    lines += ["", "Requested N=60,85,100 scenarios are sensitivity analyses. They do not prescribe "
              "the selected split size. Power also depends on paired discordance and independence; "
              "multiple tactics or safety endpoints need a predeclared multiplicity/reporting plan.", "",
              "## Proposed selection and review", "",
              f"Recommend policy B: {totals[1]} attack captures before label review. It limits "
              "Privilege Escalation dominance while retaining more Credential Access and Lateral "
              "Movement safety cases than cap 12. Policy A retains maximal evidence but is highly "
              "imbalanced; policy C sacrifices available safety cases. Keep all thin-tactic cases. "
              "These are availability counts, not an approved final split; review can reduce them.", "",
              "Before selecting, group related campaign/scenario variants (including paired "
              "source/destination-host captures) and near-identical event streams. Exclude dev "
              "scenario groups, not just identical filenames or bytes. Review without predictions; "
              "record exclusions and any count changes. From each eligible reviewed pool, sample "
              "without replacement using a declared seed (proposed 0) from sorted corpus-relative "
              "paths; publish the selection list and grouping decisions offline before evaluation.", "",
              "Folder labels are provisional. Two reviewers inspect original capture evidence and "
              "the exact truncated alert view, adjudicate disagreements, and record a defensible "
              "single primary tactic for this task or exclude unresolved multi-tactic ambiguity. "
              "Do not force DE-prefixed tunneling files into a tactic based on filename alone. "
              "Normalize ATT&CK tactic spelling to the existing schema, define evidence indices "
              "against the preserved event order, derive action/severity from existing policy, "
              "and document preprocessing/normalization without changing builder or policy. "
              "If the truncated view cannot support the label, flag it before model runs.", "",
              "Add a separately approved hard-negative pool from real benign Windows activity "
              "with known provenance (e.g. authorized remote administration, signed maintenance, "
              "scheduled tasks, and legitimate PowerShell). Establish genuine benign ground truth "
              "through independent context/review; do not relabel attack-corpus files as benign "
              "just because a model calls them benign. No verified real-benign count is available "
              "in this audit, so no fixed count or mixed total is claimed. The four dev synthetic "
              "benign examples are not real benign captures and remain development examples.", "",
              "## Stakeholder targets and comparisons", "",
              "Targets, not measured achievements: +15 percentage points tactic accuracy versus "
              "the Codex classification baseline on the SAME held-out alerts; report paired "
              "McNemar even for smaller gains; evidence validity >=95%; no uncited claim passing "
              "the verifier; zero verdict misses and zero policy under-escalations for Credential "
              "Access / Lateral Movement; two judges on about 25 alerts. Predeclare evidence-validity "
              "and claim-verification denominators (citations/claims, including failed verification) "
              "and judge sampling, blinding, rubric, and disagreement handling. Prefer stratified "
              "judge selection including thin tactics and safety subgroups; no tuning on their "
              "held-out judgments.", "",
              "Hold requested model gpt-6.1-sol and medium reasoning fixed across Codex "
              "classification, fixed-workflow, and agentic runs, recording actual exposure, CLI "
              "version, prompt/config/code hashes, failures, tool budgets, and any differences. "
              "Use identical held-out alert hashes, true labels, denominators and failure treatment. "
              "Report whole-population and eligible-class metrics plus subgroup safety and thin "
              "case studies. Dev baseline accuracy is not a paired comparator to held-out agent "
              "accuracy. Freeze evaluation scripts/endpoints before viewing results.", "",
              "## Freeze procedure and demo", "",
              "Approve capture selection, benign provenance, normalization, and reviewed labels; "
              "generate a separate held-out JSONL without overwriting examples/alerts.jsonl. "
              "Check unique IDs/captures, source and byte-hash overlap, event-stream/scenario overlap, "
              "and label leakage against development. Inspect allowed host/events recursively; "
              "keep all source names, paths, labels, audit reports, judge notes and manifest files "
              "offline. Classifiers receive only sanitized alert_id/host/events and isolated "
              "scratch files; classifier tools must never receive the repository/audit artifacts.", "",
              "Hash the approved split and captures with freeze_manifest.py; record approval "
              "separately referencing the manifest hash, and make split/manifest immutable for "
              "evaluation. The utility emits held_out_frozen=false because it cannot certify "
              "approval. Any edit requires a new manifest and documented revision; manifests "
              "are not overwritten by the utility. Runtime isolation still requires live checks.", "",
              "Line hashes include exact stored newline bytes (LF or CRLF); the last line is "
              "hashed without an added newline if unterminated. Complete-split SHA256 covers all "
              "bytes. Capture resolution uses exact corpus-relative paths, or a globally unique "
              "basename; ambiguity, missing files, escaping paths and duplicate IDs/captures "
              "are errors. A ZIP has a null Git commit with an explanation, plus byte hashes. "
              "Synthetic dev sources are explicitly marked and have null capture hashes.", "",
              "The following creates only a dev demo, not a frozen held-out set:", "", "```bash",
              "source .venv/bin/activate",
              "python data/split_numbers.py --corpus ../EVTX-ATTACK-SAMPLES",
              "python data/freeze_manifest.py --input examples/alerts.jsonl \\",
              "  --corpus ../EVTX-ATTACK-SAMPLES --output outputs/manifest_dev_demo.json --demo",
              "python -m pytest -q tests", "git diff --check", "git diff --stat", "```", "",
              "The demo command refuses an existing output; preserve it and use a new output name "
              "for a repeat. All allocation, interval, subgroup and simulation numbers above "
              f"come from `{command}` and state their denominators in the tables. No model calls "
              "were made. No actual held-out selection, approved labels or held-out manifest exists."]
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--audit-csv", type=Path, default=Path("outputs/corpus_audit.csv"))
    parser.add_argument("--audit-md", type=Path, default=Path("outputs/corpus_audit.md"))
    parser.add_argument("--dev", type=Path, default=Path("examples/alerts.jsonl"))
    parser.add_argument("--output", type=Path, default=Path("outputs/split_numbers.md"))
    args = parser.parse_args()
    args.corpus = args.corpus.resolve()
    report = make_report(args)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report)
    print(report)


if __name__ == "__main__":
    main()
