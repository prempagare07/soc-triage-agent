# Baseline accuracy record — completed xhigh run

User-selected **best observed Codex accuracy** reference, as specified in
`AGENTS.md` and [best_accuracy_reference.json](best_accuracy_reference.json).
Unqualified stakeholder baseline-accuracy questions instead use the original
historical GPT-4o-mini figures in [baseline_reference.json](baseline_reference.json).
This best-run selection was made
after viewing repeated development-run results; it does not establish an
unbiased aggregate or held-out performance. Explicit fresh-run or
other-configuration requests remain separate measurements.

Historical run: subsequent fresh reruns are documented in
[record 3](baseline_accuracy_record_3.md). The predictions and metrics for
this record were preserved under `outputs/history/20261104T223457060411Z/`;
the shared default output files now describe a later run.

Recorded: 2026-11-04. This supersedes the pending-Codex status in
`baseline_accuracy_record_1.md`.

| Baseline | Verdict accuracy | Tactic accuracy | Execution failures |
|---|---:|---:|---:|
| Deterministic rules | 82.1% (23/28) | 57.1% (16/28) | 0/28 |
| Codex CLI, requested gpt-6.1-sol / xhigh | **85.7% (24/28)** | **60.7% (17/28)** | 0/28 |

Both evaluate the same 28 development alerts: 24 attacks and four synthetic
benign examples. These are not held-out results. Codex improves both
accuracies over rules by one correct alert out of 28 (3.6 percentage points,
rounded). This is not a comparison to a freshly rerun GPT-4o-mini API model.

| Attack-specific metric | Rules | Codex xhigh |
|---|---:|---:|
| Verdict misses | 5/24 | 4/24 |
| Policy under-escalations | 7/24 | 5/24 |
| Credential Access / Lateral Movement under-escalations | 2/6 | 2/6 |

Codex missed attacks: **A001, A003, A005, A007**.
Codex under-escalations: **A001, A003, A005, A007, A018**.
Its safety-subgroup under-escalations are A005 (Credential Access) and A018
(Lateral Movement); the zero-miss/zero-under-escalation targets are not met.

A014 is still detected as malicious. Codex predicts Defense Evasion rather
than the dataset's Execution label, so this is a tactic error, not a verdict
miss. Its action remains investigate under the existing policy.

## Exact commands

From the current repository root:

```bash
cd "/Users/praveen/Desktop/1st Sem/CSE 598 Agentic AI/Capstone/Milestone 1/soc-triage-agent"

# Fresh rules measurement, executed earlier on the same day:
.venv/bin/python run_baseline.py --input examples/alerts.jsonl --mode rules

# Successful fresh xhigh smoke, followed by the full run:
.venv/bin/python run_baseline.py --input examples/single_alert.json --mode codex \
  --model gpt-6.1-sol --reasoning-effort xhigh --timeout 180 --no-cache \
  --output outputs/smoke/single_alert_codex.jsonl &&
.venv/bin/python run_baseline.py --input examples/alerts.jsonl --mode codex \
  --model gpt-6.1-sol --reasoning-effort xhigh --timeout 180 --no-cache
```

The initial app-sandbox attempts failed before inference. The exact sequence
above subsequently succeeded using the supported, approved execution
permission request outside that app sandbox. Classifier read-only sandbox,
sanitized input, isolated directory, disabled-capability settings, original
instructions and tool-event rejection remained in place.

## Provenance and verification

- CLI version: `codex-cli 0.166.0`; ChatGPT subscription authentication.
- Requested model: `gpt-6.1-sol`; requested reasoning effort: `xhigh`.
- Actual resolved model and effective effort: null, not exposed by the CLI.
- Full run: 28 successful classifications, zero failures, zero retries,
  zero local response-cache hits. All 28 alerts were freshly attempted.
- There were no rejected tool item types. Observed item types were
  agent_message and error. The retained diagnostics describe the unstable
  skill-discovery exclusion flag and Code Mode's disabled host; no capability
  was enabled to suppress those diagnostics. This does not prove perfect
  runtime isolation.
- Input, predictions, metrics and recorded code hashes were verified for
  both runs. The per-alert CSV contains all 28 alerts.
- Input SHA256 for both modes:
  `f4fe76b73de02ad87be2b03023a4ca4c48d68f911d1edc192387d8672dd88672`.
- No API cost or exact subscription-credit charge is inferred.

The measurement commands above generate all counts and accuracies in this
record from the saved prediction files. Verification commands:

```bash
.venv/bin/python -m pytest -q tests
git diff --check
git diff --stat
```

## Saved evidence

- [Combined metrics](../outputs/history/20261104T223457060411Z/m1_metrics.md)
- [Rules metrics](../outputs/m1_rules_metrics.md)
- [Codex metrics](../outputs/history/20261104T223457060411Z/m1_codex_metrics.md)
- [Per-alert comparison](../outputs/history/20261104T223457060411Z/m1_per_alert.csv)
- [Rules predictions](../outputs/alerts_rules.jsonl)
- [Codex predictions](../outputs/history/20261104T223457060411Z/alerts_codex.jsonl)
- [Rules metadata](../outputs/run_meta_alerts_rules.json)
- [Codex metadata](../outputs/history/20261104T223457060411Z/run_meta_alerts_codex.json)

Existing outputs were archived before replacement. No commit or push was made.
