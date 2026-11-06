# Results: dev

Alerts: 28

| Metric | rules |
| --- | --- |
| Tactic accuracy (exact) | 16/28 (57.1%) |
| Tactic top-2 | 16/28 (57.1%) |
| Macro-F1 (tactics with n>=5) | n/a |
| Verdict accuracy | 23/28 (82.1%) |
| Failed classifications (counted incorrect) | 0/28 (0.0%) |
| Missed attacks | 5 (A003, A010, A011, A012, A016) |
| False positives (benign called malicious) | 0/4 |
| Under-escalations (incl. misses) | 7 |
|   of which Credential Access / Lateral Movement | 2 |
| Action-level accuracy | 18/28 (64.3%) |
| Uncertain escalations | 0 |
| Parse failures | 0 |
| Tool calls (total) | 0 |
| Tool errors | 0 |
| Verifier failures / revisions | 0 / 0 |
| Budget exhausted | 0 |
| Claim-level evidence validity | n/a |
| Latency p50 / p95 (s per alert) | n/a |
| Tokens (reported; may include cached calls) | 0 |
| Zero-miss 95% upper bound (attack denominator) | n/a |

Accuracy denominators include all labelled alerts; missing/failed/parse-failure predictions count as incorrect. Misses and under-escalations describe completed predictions; failures are listed separately. Zero-miss bounds apply only with zero misses and no failed attack classifications, assuming independent Bernoulli trials.

## Tactic accuracy by true tactic

| True tactic | n | rules |
| --- | --- | --- |
| Command and Control | 3 | 1 |
| Credential Access | 3 | 2 |
| Defense Evasion | 3 | 0 |
| Discovery | 3 | 0 |
| Execution | 3 | 3 |
| Lateral Movement | 3 | 1 |
| Persistence | 3 | 2 |
| Privilege Escalation | 3 | 3 |
| Benign | 4 | 4 |

Model: `None`; provider: `None`; options: `{}`. Command: `/Users/praveen/Desktop/1st Sem/CSE 598 Agentic AI/Capstone/Milestone 1/soc-triage-agent/.venv/bin/python run_eval.py --dataset dev --systems rules --out outputs/m2_dev_accuracy_20261106T041957Z`
