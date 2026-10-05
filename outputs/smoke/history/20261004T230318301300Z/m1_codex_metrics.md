# codex baseline metrics

Tactic accuracy: 0/1 (0.0%)
Verdict accuracy: 0/1 (0.0%)
Missed attacks: 0 []
Under-escalations: 0 []
Credential Access / Lateral Movement under-escalations: 0 []
Failed classifications: 1 ['A006']

Accuracy denominators include all labelled alerts; failures count as incorrect.
Misses and under-escalations describe successful predictions only; failures are reported separately.

## Per-tactic accuracy

| Tactic | Correct / total |
|---|---|
| Credential Access | 0/1 |

## Failure causes

- A006: Sandbox blocked initialization of the in-process app-server (Operation not permitted)

## Tactic confusion (true × predicted)

| True | FAILED |
|---|---|
| Credential Access | 1 |

## Action confusion (policy true × predicted)

| True | FAILED |
|---|---|
| escalate_tier2 | 1 |

Command: `/Users/praveen/Desktop/1st Sem/CSE 598 Agentic AI/Capstone/soc-triage-agent/.venv/bin/python run_baseline.py --input examples/single_alert.json --mode codex --model gpt-6.1-sol --reasoning-effort medium --timeout 30 --no-cache --output outputs/smoke/single_alert_codex.jsonl`
