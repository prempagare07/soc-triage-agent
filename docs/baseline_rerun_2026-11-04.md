# Baseline rerun — 2026-11-04

## Latest outcome: completed

The user-requested `gpt-6.1-sol` / xhigh smoke and full run subsequently
completed using the supported approved execution permission request outside
the app sandbox. The fresh full Codex run achieved verdict accuracy 24/28
(85.7%) and tactic accuracy 17/28 (60.7%), with zero execution failures out
of 28 alerts. Rules remain 23/28 verdict (82.1%) and 16/28 tactic (57.1%).
See [the completed record](baseline_accuracy_record_2.md) for exact commands,
denominators, attack-specific metrics and provenance. Earlier blocked
attempts below are retained as historical execution evidence.

## Earlier app-sandbox attempts

The fresh rules baseline completed. The Codex preflight failed before
inference, so a full Codex baseline could not be run inside this app.

User-directed configuration update: the new Codex baseline must request
`gpt-6.1-sol` with **xhigh** reasoning, replacing medium for future runs.
A fresh xhigh preflight was attempted with timeout 180 and no cache. It
also failed before inference with the same sandbox initialization error.
The metadata confirms requested effort xhigh; effective effort is null
because no model inference occurred. The full command was gated on smoke
success and therefore did not execute. No additional medium run was made.

The xhigh attempt is saved separately under
`outputs/preflight_xhigh_20261104/`. Its exact attempted command was:

```bash
.venv/bin/python run_baseline.py --input examples/single_alert.json --mode codex \
  --model gpt-6.1-sol --reasoning-effort xhigh --timeout 180 --no-cache \
  --output outputs/preflight_xhigh_20261104/single_alert_codex.jsonl
```

It produced zero successful classifications and one startup failure for
one preflight alert. This is not a model accuracy measurement. The medium
command in the historical commands section below describes the earlier
attempt only; the terminal handoff now explicitly uses xhigh.

| Mode | Verdict accuracy | Tactic accuracy | Status |
|---|---:|---:|---|
| Rules | 23/28 (82.1%) | 16/28 (57.1%) | Fresh dev-set measurement; zero failures out of 28 alerts. |
| Codex, requested gpt-6.1-sol / xhigh | Unavailable | Unavailable | Preflight startup failed; no full run or model predictions generated. |

Rules missed attacks: A003, A010, A011, A012, A016 (5/24 attacks).
Rules under-escalations: those five plus A018 and A021 (7/24 attacks).
These remain development-set results, not held-out performance.

## Commands and saved evidence

Executed from `soc-triage-agent/`:

```bash
codex --version
codex login status
codex exec --help
codex features list
.venv/bin/python -m pytest -q tests
.venv/bin/python run_baseline.py --input examples/single_alert.json --mode codex \
  --model gpt-6.1-sol --reasoning-effort medium --timeout 30 --no-cache \
  --output outputs/preflight_20261104/single_alert_codex.jsonl
.venv/bin/python run_baseline.py --input examples/alerts.jsonl --mode rules
git diff --check
git diff --stat
```

CLI reports 0.166.0 and ChatGPT login. The smoke returned:
`Sandbox blocked initialization of the in-process app-server (Operation not permitted)`.
Its denominator is one attempted alert with zero successful classifications;
this is a runtime failure, not measured model accuracy. No attempt to run
the remaining alerts was made after the failed preflight. Current model
availability and effective runtime isolation could not be verified.

Preflight artifacts (older code hashes, preceding the reporting fixes):

- `outputs/preflight_20261104/single_alert_codex.jsonl`
- `outputs/preflight_20261104/run_meta_single_alert_codex.json`

Fresh rules artifacts:

- `outputs/alerts_rules.jsonl`
- `outputs/run_meta_alerts_rules.json`
- `outputs/metrics_alerts_rules.md` (canonical input-specific report)
- `outputs/m1_rules_metrics.md` (convenience copy)
- `outputs/m1_metrics.md` (currently rules only)

The prior rules artifacts were archived under
`outputs/history/20261104T213333948877Z/`. Rules input/output/code/metrics
hashes were checked against their metadata. No historical GPT-4o-mini API
run was performed; the approved workflow uses subscription-authenticated Codex.

## Reporting repairs before measurement

The earlier review's reporting defects were reproduced in mocked regression
tests and repaired:

- Canonical metrics are now input-specific, with their path and SHA256
  stored in run metadata. Combined reports require matching input, saved
  prediction and metrics hashes; a convenience report from another input
  cannot be included accidentally.
- The generated comparison CSV is invalidated before comparison validation,
  so missing or mismatched artifacts cannot leave an old CSV looking current.
  The runner preserves existing artifacts before calling the comparison.
- Per-alert Codex metadata is reset before runner sanitization and direct
  adapter sanitization, so a rejected alert cannot inherit another alert's
  response, request hash, usage, cache status or attempted flag.

After these repairs, `python -m pytest -q tests` passed 116 tests. Mocked
model responses are testing evidence only, not measured baseline results.
Classification instructions, policy, rule logic and dev input were unchanged.
Adapter code hashes changed; the next measured Codex run must use the new
hashes, with fresh inference requested below. No commit or push was made.

## Complete Codex in an ordinary terminal

Run the following exact commands. The full run starts only if the smoke
command succeeds. Earlier smoke output is preserved by the runner before
replacement. Explicit interpreter paths avoid relying on the virtualenv's
old activation path after the project moved under `Milestone 1/`.

```bash
cd "/Users/praveen/Desktop/1st Sem/CSE 598 Agentic AI/Capstone/Milestone 1/soc-triage-agent"
.venv/bin/python run_baseline.py --input examples/single_alert.json --mode codex \
  --model gpt-6.1-sol --reasoning-effort xhigh --timeout 180 --no-cache \
  --output outputs/smoke/single_alert_codex.jsonl &&
.venv/bin/python run_baseline.py --input examples/alerts.jsonl --mode codex \
  --model gpt-6.1-sol --reasoning-effort xhigh --timeout 180 --no-cache
```

The full command will save predictions, run metadata, Codex metrics and the
rules/Codex comparison. Failed classifications remain in the all-alert
accuracy denominator. Do not change model silently if access is unavailable;
record a new explicit selection only with stakeholder/user direction.

The isolation flags were checked against installed CLI help and feature
names. [Official non-interactive documentation](https://learn.chatgpt.com/docs/non-interactive-mode)
also documents JSON events, output schemas and ephemeral runs. Neither those
settings nor read-only sandboxing alone prove runtime isolation. The new
terminal smoke still requires inspection of metadata and tool activity.
