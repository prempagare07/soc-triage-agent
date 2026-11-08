# codex baseline metrics

Tactic accuracy: 15/28 (53.6%)
Verdict accuracy: 23/28 (82.1%)
Missed attacks: 5 ['A001', 'A003', 'A005', 'A007', 'A011']
Under-escalations: 7 ['A001', 'A003', 'A005', 'A006', 'A007', 'A011', 'A018']
Credential Access / Lateral Movement under-escalations: 3 ['A005', 'A006', 'A018']
Failed classifications: 0 []

Accuracy denominators include all labelled alerts; failures count as incorrect.
Misses and under-escalations describe successful predictions only; failures are reported separately.

## Per-tactic accuracy

| Tactic | Correct / total |
|---|---|
| Benign | 4/4 |
| Command and Control | 1/3 |
| Credential Access | 1/3 |
| Defense Evasion | 0/3 |
| Discovery | 2/3 |
| Execution | 0/3 |
| Lateral Movement | 2/3 |
| Persistence | 2/3 |
| Privilege Escalation | 3/3 |

## Tactic confusion (true × predicted)

| True | Benign | Command and Control | Credential Access | Defense Evasion | Discovery | Lateral Movement | Persistence | Privilege Escalation |
|---|---|---|---|---|---|---|---|---|
| Benign | 4 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| Command and Control | 2 | 1 | 0 | 0 | 0 | 0 | 0 | 0 |
| Credential Access | 1 | 0 | 1 | 1 | 0 | 0 | 0 | 0 |
| Defense Evasion | 1 | 0 | 0 | 0 | 0 | 0 | 1 | 1 |
| Discovery | 1 | 0 | 0 | 0 | 2 | 0 | 0 | 0 |
| Execution | 0 | 0 | 0 | 3 | 0 | 0 | 0 | 0 |
| Lateral Movement | 0 | 0 | 0 | 0 | 1 | 2 | 0 | 0 |
| Persistence | 0 | 0 | 0 | 0 | 0 | 0 | 2 | 1 |
| Privilege Escalation | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 3 |

## Action confusion (policy true × predicted)

| True | close | escalate_tier2 | investigate | monitor |
|---|---|---|---|---|
| close | 4 | 0 | 0 | 0 |
| escalate_tier2 | 3 | 10 | 1 | 1 |
| investigate | 1 | 2 | 3 | 0 |
| monitor | 1 | 0 | 0 | 2 |

Command: `/Users/praveen/Desktop/1st Sem/CSE 598 Agentic AI/Capstone/Milestone 1/soc-triage-agent/.venv/bin/python run_baseline.py --input examples/alerts.jsonl --mode codex --model gpt-6.1-sol --reasoning-effort xhigh --timeout 180 --no-cache`
