# rules baseline metrics

Tactic accuracy: 16/28 (57.1%)
Verdict accuracy: 23/28 (82.1%)
Missed attacks: 5 ['A003', 'A010', 'A011', 'A012', 'A016']
Under-escalations: 7 ['A003', 'A010', 'A011', 'A012', 'A016', 'A018', 'A021']
Credential Access / Lateral Movement under-escalations: 2 ['A016', 'A018']
Failed classifications: 0 []

Accuracy denominators include all labelled alerts; failures count as incorrect.
Misses and under-escalations describe successful predictions only; failures are reported separately.

## Per-tactic accuracy

| Tactic | Correct / total |
|---|---|
| Benign | 4/4 |
| Command and Control | 1/3 |
| Credential Access | 2/3 |
| Defense Evasion | 0/3 |
| Discovery | 0/3 |
| Execution | 3/3 |
| Lateral Movement | 1/3 |
| Persistence | 2/3 |
| Privilege Escalation | 3/3 |

## Tactic confusion (true × predicted)

| True | Benign | Command and Control | Credential Access | Discovery | Execution | Lateral Movement | Persistence | Privilege Escalation |
|---|---|---|---|---|---|---|---|---|
| Benign | 4 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| Command and Control | 1 | 1 | 0 | 0 | 0 | 1 | 0 | 0 |
| Credential Access | 0 | 0 | 2 | 0 | 0 | 1 | 0 | 0 |
| Defense Evasion | 0 | 1 | 0 | 0 | 0 | 1 | 1 | 0 |
| Discovery | 3 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| Execution | 0 | 0 | 0 | 0 | 3 | 0 | 0 | 0 |
| Lateral Movement | 1 | 0 | 0 | 1 | 0 | 1 | 0 | 0 |
| Persistence | 0 | 0 | 0 | 0 | 1 | 0 | 2 | 0 |
| Privilege Escalation | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 3 |

## Action confusion (policy true × predicted)

| True | close | escalate_tier2 | investigate | monitor |
|---|---|---|---|---|
| close | 4 | 0 | 0 | 0 |
| escalate_tier2 | 2 | 11 | 1 | 1 |
| investigate | 0 | 3 | 3 | 0 |
| monitor | 3 | 0 | 0 | 0 |

Command: `/Users/praveen/Desktop/1st Sem/CSE 598 Agentic AI/Capstone/soc-triage-agent/.venv/bin/python run_baseline.py --input examples/alerts.jsonl --mode rules`
