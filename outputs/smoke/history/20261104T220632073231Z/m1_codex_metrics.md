# codex baseline metrics

Tactic accuracy: 1/1 (100.0%)
Verdict accuracy: 1/1 (100.0%)
Missed attacks: 0 []
Under-escalations: 0 []
Credential Access / Lateral Movement under-escalations: 0 []
Failed classifications: 0 []

Accuracy denominators include all labelled alerts; failures count as incorrect.
Misses and under-escalations describe successful predictions only; failures are reported separately.

## Per-tactic accuracy

| Tactic | Correct / total |
|---|---|
| Credential Access | 1/1 |

## Tactic confusion (true × predicted)

| True | Credential Access |
|---|---|
| Credential Access | 1 |

## Action confusion (policy true × predicted)

| True | escalate_tier2 |
|---|---|
| escalate_tier2 | 1 |

Command: `/Users/praveen/Desktop/1st Sem/CSE 598 Agentic AI/Capstone/soc-triage-agent/.venv/bin/python3 run_baseline.py --input examples/single_alert.json --mode codex --model gpt-6.1-sol --reasoning-effort medium --timeout 180 --no-cache --output outputs/smoke/single_alert_codex.jsonl`
