# Held-out split proposal (not frozen)

Command: `python data/split_numbers.py --corpus ../EVTX-ATTACK-SAMPLES`

## Verified provenance

Corpus commit: `4ceed2f4706daf601c212a8f91c113dd85349a2c`; checkout clean.
Dev SHA256: `f4fe76b73de02ad87be2b03023a4ca4c48d68f911d1edc192387d8672dd88672`.
Builder SHA256: `7fa7a9f6743c400ae92158de550c1f3d55e4337f92ed5ef2a3c0dbb87a229bf8`.
Audit script SHA256: `3e0124f3f30fa1ab109819285667238939c3a066fdd5aec79680cb49cb18cec4`.
Audit CSV SHA256: `8588d098c99090a5bf0d0df4f331e9ab064a621d1a22113c0ebdf10498e2ecfc`.
Audit Markdown SHA256: `f7f94cb6c856844b433f2dca475207d2732d40bee6fd93b68f79abbb7ce45268`.

Verified inventory and every capture SHA256: 278/278 files. All 24 dev EVTX sources resolve uniquely and match audit exclusions. No unused qualifying candidate is a byte duplicate of a dev capture or another candidate.

Eligibility is one unused direct-child capture in a builder tactic folder with at least three retained events under default parse() truncation (last 20 events). Out-of-scope captures are not eligible automatically.

## Availability and allocation

Current and wider settings are identical; newly added IDs: none.
Both sets: 1, 3, 7, 8, 10, 11, 13, 4103, 4104, 4624, 4625, 4648, 4672, 4688, 4698, 4720, 4728, 4732, 5140, 5145, 7045.

| Tactic | Current unused qualifying | Wider unused qualifying | A | B (cap 15) | C (cap 12) |
|---|---:|---:|---:|---:|---:|---:|
| Command and Control | 1 | 1 | 1 | 1 | 1 |
| Credential Access | 13 | 13 | 13 | 13 | 12 |
| Defense Evasion | 14 | 14 | 14 | 14 | 12 |
| Discovery | 2 | 2 | 2 | 2 | 2 |
| Execution | 16 | 16 | 16 | 15 | 12 |
| Lateral Movement | 22 | 22 | 22 | 15 | 12 |
| Persistence | 6 | 6 | 6 | 6 | 6 |
| Privilege Escalation | 51 | 51 | 51 | 15 | 12 |
| Total attacks | 125 | 125 | 125 | 81 | 69 |

Counts exclude all dev captures. No duplicates are oversampled to fill caps.

| Policy | N attacks | Eligible macro-F1 classes (n >= 5) | Case studies (n < 5) |
|---|---:|---|---|
| A: all available | 125 | Credential Access, Defense Evasion, Execution, Lateral Movement, Persistence, Privilege Escalation | Command and Control (n=1), Discovery (n=2) |
| B: cap 15 | 81 | Credential Access, Defense Evasion, Execution, Lateral Movement, Persistence, Privilege Escalation | Command and Control (n=1), Discovery (n=2) |
| C: cap 12 | 69 | Credential Access, Defense Evasion, Execution, Lateral Movement, Persistence, Privilege Escalation | Command and Control (n=1), Discovery (n=2) |

Define primary macro-F1 as the arithmetic mean of per-class F1 over exactly Credential Access, Defense Evasion, Execution, Lateral Movement, Persistence, and Privilege Escalation. Compute each class's TP/FP/FN across the entire same tested population (including thin tactics and benign cases); do not discard their false positives. Zero-denominator class F1 is 0. Report Command and Control and Discovery predictions as case studies with correct/total; they do not enter this macro mean. Failures count as incorrect/FN for their true class and are reported separately. Any approved label changes require recomputing counts and fixing the eligible set before results are seen. Benign performance is reported separately.

## Precision and zero-miss limits

Wilson uses z=1.959963984540054. Near 0.5, successes=floor(N/2), so odd N rounds down. Half-width is (upper-lower)/2, not distance from the sample proportion to either endpoint. Percentages below are rounded to two decimals.

| Policy | N | Assumed correct | Wilson 95% interval | Half-width (points) | Zero-miss 3/N upper bound |
|---|---:|---:|---|---:|---:|
| A: all available | 125 | 62 | 40.98%–58.25% | 8.63 | 2.40% |
| B: cap 15 | 81 | 40 | 38.77%–60.05% | 10.64 | 3.70% |
| C: cap 12 | 69 | 34 | 37.83%–60.79% | 11.48 | 4.35% |

| Policy | Credential Access N | CA zero-miss bound | Lateral Movement N | LM zero-miss bound | Combined CA/LM N | Combined bound |
|---|---:|---:|---:|---:|---:|---:|
| A: all available | 13 | 23.08% | 22 | 13.64% | 35 | 8.57% |
| B: cap 15 | 13 | 23.08% | 15 | 20.00% | 28 | 10.71% |
| C: cap 12 | 12 | 25.00% | 12 | 25.00% | 24 | 12.50% |

The rule of three is an approximate one-sided 95% upper probability bound after zero observed misses in N independent Bernoulli attack trials with a common miss probability; it is not a guarantee of zero future misses. Display min(1,3/N); small subgroup approximations are rough. N=0 yields null/not estimable, never zero. Use each tested attack subgroup's own N for its verdict-miss and under-escalation bound; report these outcomes separately. Failures prevent a claim of zero misses unless explicitly resolved and reported. Benign alerts never enlarge the attack denominator. Correlated scenario captures can make these nominal limits optimistic. Wilson accuracy denominators change if reporting the mixed benign/attack population.

## Exact paired McNemar power simulation

10,000 trials per cell; random.Random seed 0, one continuous stream in ascending N then d order. Alpha=0.05, reject when exact two-sided p <= alpha. Each trial samples N independent paired correctness outcomes. Baseline-only probability=(d-0.15)/2; agent-only=(d+0.15)/2; remainder=1-d concordant. The split of concordant outcomes into both-right/both-wrong does not affect McNemar and is not assumed. Under the null, conditional on m discordant pairs, baseline-only is Binomial(m,0.5). p=min(1,2*smaller inclusive binomial tail); m=0 gives p=1. These are hypothetical 15-point gains with homogeneous discordance, not measured achievements or guarantees. Only standard-library random/math are used; no added statistical dependency.

| N | d | Baseline-only probability | Agent-only probability | Rejections / trials | Estimated power | Monte Carlo SE (points) |
|---:|---:|---:|---:|---:|---:|---:|
| 60 | 0.20 | 0.025 | 0.175 | 7053/10000 | 70.53% | 0.46 |
| 60 | 0.30 | 0.075 | 0.225 | 4889/10000 | 48.89% | 0.50 |
| 60 | 0.40 | 0.125 | 0.275 | 3752/10000 | 37.52% | 0.48 |
| 85 | 0.20 | 0.025 | 0.175 | 8815/10000 | 88.15% | 0.32 |
| 85 | 0.30 | 0.075 | 0.225 | 6682/10000 | 66.82% | 0.47 |
| 85 | 0.40 | 0.125 | 0.275 | 5402/10000 | 54.02% | 0.50 |
| 100 | 0.20 | 0.025 | 0.175 | 9312/10000 | 93.12% | 0.25 |
| 100 | 0.30 | 0.075 | 0.225 | 7436/10000 | 74.36% | 0.44 |
| 100 | 0.40 | 0.125 | 0.275 | 6168/10000 | 61.68% | 0.49 |

Requested N=60,85,100 scenarios are sensitivity analyses. They do not prescribe the selected split size. Power also depends on paired discordance and independence; multiple tactics or safety endpoints need a predeclared multiplicity/reporting plan.

## Proposed selection and review

Recommend policy B: 81 attack captures before label review. It limits Privilege Escalation dominance while retaining more Credential Access and Lateral Movement safety cases than cap 12. Policy A retains maximal evidence but is highly imbalanced; policy C sacrifices available safety cases. Keep all thin-tactic cases. These are availability counts, not an approved final split; review can reduce them.

Before selecting, group related campaign/scenario variants (including paired source/destination-host captures) and near-identical event streams. Exclude dev scenario groups, not just identical filenames or bytes. Review without predictions; record exclusions and any count changes. From each eligible reviewed pool, sample without replacement using a declared seed (proposed 0) from sorted corpus-relative paths; publish the selection list and grouping decisions offline before evaluation.

Folder labels are provisional. Two reviewers inspect original capture evidence and the exact truncated alert view, adjudicate disagreements, and record a defensible single primary tactic for this task or exclude unresolved multi-tactic ambiguity. Do not force DE-prefixed tunneling files into a tactic based on filename alone. Normalize ATT&CK tactic spelling to the existing schema, define evidence indices against the preserved event order, derive action/severity from existing policy, and document preprocessing/normalization without changing builder or policy. If the truncated view cannot support the label, flag it before model runs.

Add a separately approved hard-negative pool from real benign Windows activity with known provenance (e.g. authorized remote administration, signed maintenance, scheduled tasks, and legitimate PowerShell). Establish genuine benign ground truth through independent context/review; do not relabel attack-corpus files as benign just because a model calls them benign. No verified real-benign count is available in this audit, so no fixed count or mixed total is claimed. The four dev synthetic benign examples are not real benign captures and remain development examples.

## Stakeholder targets and comparisons

Targets, not measured achievements: +15 percentage points tactic accuracy versus the Codex classification baseline on the SAME held-out alerts; report paired McNemar even for smaller gains; evidence validity >=95%; no uncited claim passing the verifier; zero verdict misses and zero policy under-escalations for Credential Access / Lateral Movement; two judges on about 25 alerts. Predeclare evidence-validity and claim-verification denominators (citations/claims, including failed verification) and judge sampling, blinding, rubric, and disagreement handling. Prefer stratified judge selection including thin tactics and safety subgroups; no tuning on their held-out judgments.

Hold requested model gpt-6.1-sol and medium reasoning fixed across Codex classification, fixed-workflow, and agentic runs, recording actual exposure, CLI version, prompt/config/code hashes, failures, tool budgets, and any differences. Use identical held-out alert hashes, true labels, denominators and failure treatment. Report whole-population and eligible-class metrics plus subgroup safety and thin case studies. Dev baseline accuracy is not a paired comparator to held-out agent accuracy. Freeze evaluation scripts/endpoints before viewing results.

## Freeze procedure and demo

Approve capture selection, benign provenance, normalization, and reviewed labels; generate a separate held-out JSONL without overwriting examples/alerts.jsonl. Check unique IDs/captures, source and byte-hash overlap, event-stream/scenario overlap, and label leakage against development. Inspect allowed host/events recursively; keep all source names, paths, labels, audit reports, judge notes and manifest files offline. Classifiers receive only sanitized alert_id/host/events and isolated scratch files; classifier tools must never receive the repository/audit artifacts.

Hash the approved split and captures with freeze_manifest.py; record approval separately referencing the manifest hash, and make split/manifest immutable for evaluation. The utility emits held_out_frozen=false because it cannot certify approval. Any edit requires a new manifest and documented revision; manifests are not overwritten by the utility. Runtime isolation still requires live checks.

Line hashes include exact stored newline bytes (LF or CRLF); the last line is hashed without an added newline if unterminated. Complete-split SHA256 covers all bytes. Capture resolution uses exact corpus-relative paths, or a globally unique basename; ambiguity, missing files, escaping paths and duplicate IDs/captures are errors. A ZIP has a null Git commit with an explanation, plus byte hashes. Synthetic dev sources are explicitly marked and have null capture hashes.

The following creates only a dev demo, not a frozen held-out set:

```bash
source .venv/bin/activate
python data/split_numbers.py --corpus ../EVTX-ATTACK-SAMPLES
python data/freeze_manifest.py --input examples/alerts.jsonl \
  --corpus ../EVTX-ATTACK-SAMPLES --output outputs/manifest_dev_demo.json --demo
python -m pytest -q tests
git diff --check
git diff --stat
```

The demo command refuses an existing output; preserve it and use a new output name for a repeat. All allocation, interval, subgroup and simulation numbers above come from `python data/split_numbers.py --corpus ../EVTX-ATTACK-SAMPLES` and state their denominators in the tables. No model calls were made. No actual held-out selection, approved labels or held-out manifest exists.
