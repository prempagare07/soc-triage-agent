# Fresh xhigh rerun — concurrent output replacement

Recorded: 2026-11-04. This records the next requested full Codex baseline
after `baseline_accuracy_record_2.md`.

## Results and attribution

| Run | Verdict accuracy | Tactic accuracy | Evidence |
|---|---:|---:|---|
| Earlier completed xhigh run | 85.7% (24/28) | 60.7% (17/28) | Preserved predictions and metadata in `outputs/history/20261104T223457060411Z/`. |
| Agent-launched fresh rerun | 82.1% (23/28) | 42.9% (12/28) | Completed process stdout; its saved files were subsequently replaced by an overlapping run. Treat as console-only evidence, not the primary saved baseline. |
| Later overlapping run, latest verified saved result | **78.6% (22/28)** | **50.0% (14/28)** | Predictions, metadata and metrics independently hash-checked and preserved in `outputs/history/20261104T224402771820Z/`. |

All use the same development input of 28 alerts (24 attacks and four
synthetic benign examples). These are not held-out results. The rules
baseline remains 82.1% verdict (23/28) and 57.1% tactic (16/28).

Do not attribute the later run's saved files to the agent-launched process,
or silently select the best of these repeated runs as the baseline.

## Execution evidence

The agent executed:

```bash
cd "/Users/praveen/Desktop/1st Sem/CSE 598 Agentic AI/Capstone/Milestone 1/soc-triage-agent"
.venv/bin/python -u run_baseline.py --input examples/alerts.jsonl \
  --mode codex --model gpt-6.1-sol --reasoning-effort xhigh \
  --timeout 180 --no-cache
```

The runner archived existing artifacts at `20261104T223457060411Z` and
completed with exit status 0. Its final stdout reported 12/28 tactic
accuracy, 23/28 verdict accuracy and five verdict misses. All 28 progress
lines completed without execution failures. The `-u` interpreter flag
only enables unbuffered progress output.

During subsequent verification, `outputs/run_meta_alerts_codex.json`
identified a different run starting at `2026-11-04T22:36:03.224762+00:00`
and finishing at `2026-11-04T22:42:59.492203+00:00`. Its recorded command
is the same baseline command above without the interpreter's `-u` flag.
It archived artifacts at `20261104T223603217639Z`, confirming that it
started after the agent's run and overlapped it. The runner archives at
startup, so that second startup archive also contains the earlier completed
run, not the subsequently replaced agent-run predictions.

The agent did not launch this second overlapping process. Its origin has
not been established. Its saved files were copied without changing the
shared outputs into `outputs/history/20261104T224402771820Z/`. The copy's
prediction and canonical metrics SHA256 values match its metadata.
Original paths inside that copied metadata are retained unchanged;
verify the archived files by basename against the recorded hashes.

## Latest verified saved result

- Requested model: `gpt-6.1-sol`; requested reasoning effort: `xhigh`.
- CLI: `codex-cli 0.166.0`; ChatGPT subscription authentication.
- Resolved model and effective reasoning effort remain null/unexposed.
- Successful classifications: 28/28; execution failures: 0/28.
- Verdict misses: 6/24 attacks — A001, A003, A005, A007, A010, A011.
- Policy under-escalations: 7/24 attacks — those six plus A018.
- Credential Access / Lateral Movement under-escalations: 2/6 — A005, A018.
- Retries: zero; local response-cache hits: zero. Provider cached-input
  usage is distinct from local response-cache reuse.
- All 28 per-alert request hashes match the earlier completed run. Input,
  code, configuration, instruction, schema, CLI version, requested model,
  requested effort and timeout match. This demonstrates different fresh
  responses under the same recorded configuration; it does not expose or
  prove the actual resolved backend model or sampling parameters.
- Input/output/metrics/code hashes checked successfully. No rejected tool
  item types were observed. The comparison CSV contains all 28 alerts.

All run percentages and counts come from the baseline commands above and
the saved JSONL records. Accuracy denominators are all 28 labelled alerts;
attack-only and safety-subgroup denominators are stated separately.
No new rules run was made in this turn; its original command was:

```bash
.venv/bin/python run_baseline.py --input examples/alerts.jsonl --mode rules
```

## Stable saved evidence

- [Latest verified predictions](../outputs/history/20261104T224402771820Z/alerts_codex.jsonl)
- [Latest verified metadata](../outputs/history/20261104T224402771820Z/run_meta_alerts_codex.json)
- [Latest verified Codex metrics](../outputs/history/20261104T224402771820Z/metrics_alerts_codex.md)
- [Latest verified combined report](../outputs/history/20261104T224402771820Z/m1_metrics.md)
- [Latest verified per-alert CSV](../outputs/history/20261104T224402771820Z/m1_per_alert.csv)

Future simultaneous runs must use separate output directories to prevent
this race; do not run multiple processes against the shared default output
names. No classification instructions, policy, runner code or dev input
were edited in this turn. No commit or push was made.
