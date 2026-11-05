# Results: dev

Alerts: 28

| Metric | rules | single_call | fixed_workflow | agent |
| --- | --- | --- | --- | --- |
| Tactic accuracy (exact) | 16/28 (57.1%) | 7/28 (25.0%) | 12/28 (42.9%) | 11/28 (39.3%) |
| Tactic top-2 | 16/28 (57.1%) | 7/28 (25.0%) | 12/28 (42.9%) | 11/28 (39.3%) |
| Macro-F1 (tactics with n>=5) | n/a | n/a | n/a | n/a |
| Verdict accuracy | 23/28 (82.1%) | 18/28 (64.3%) | 19/28 (67.9%) | 20/28 (71.4%) |
| Missed attacks | 5 (A003, A010, A011, A012, A016) | 9 (A001, A002, A005, A007, A010, A017, A018, A019...) | 8 (A001, A002, A005, A007, A010, A011, A017, A018) | 7 (A004, A005, A007, A008, A012, A014, A016) |
| Under-escalations (incl. misses) | 7 | 15 | 9 | 4 |
|   of which Credential Access / Lateral Movement | 2 | 5 | 4 | 2 |
| Action-level accuracy | 18/28 (64.3%) | 8/28 (28.6%) | 15/28 (53.6%) | 17/28 (60.7%) |
| Uncertain escalations | 0 | 0 | 0 | 6 |
| Parse failures | 0 | 0 | 0 | 0 |
| Tool calls (total) | 0 | 0 | 178 | 137 |
| Tool errors | 0 | 0 | 0 | 0 |
| Verifier failures / revisions | 0 / 0 | 0 / 0 | 0 / 0 | 5 / 3 |
| Budget exhausted | 0 | 0 | 0 | 0 |
| Claim-level evidence validity | n/a | n/a | n/a | 35/37 (94.6%) |
| Latency p50 / p95 (s per alert) | n/a | 3.2 / 16.8 | 14.4 / 27.8 | 54.5 / 82.4 |
| Tokens (total, uncached runs) | 0 | 26586 | 45588 | 301314 |

Zero-miss 95% upper bound at 24 attacks: 11.7%

## Paired comparison with the agent (exact McNemar on tactic correctness)

| Baseline | agent right, baseline wrong | baseline right, agent wrong | p |
| --- | --- | --- | --- |
| rules | 3 | 8 | 0.227 |
| single_call | 7 | 3 | 0.344 |
| fixed_workflow | 2 | 3 | 1.000 |

## Tactic accuracy by true tactic

| True tactic | n | rules | single_call | fixed_workflow | agent |
| --- | --- | --- | --- | --- | --- |
| Command and Control | 3 | 1 | 1 | 1 | 3 |
| Credential Access | 3 | 2 | 0 | 1 | 0 |
| Defense Evasion | 3 | 0 | 0 | 0 | 0 |
| Discovery | 3 | 0 | 0 | 0 | 0 |
| Execution | 3 | 3 | 3 | 2 | 0 |
| Lateral Movement | 3 | 1 | 0 | 0 | 0 |
| Persistence | 3 | 2 | 0 | 2 | 2 |
| Privilege Escalation | 3 | 3 | 0 | 3 | 3 |
| Benign | 4 | 4 | 3 | 3 | 3 |

Model: `qwen2.5:7b` (Ollama, temperature 0, seed 0). Command: `/Users/amatyakatyayan/Downloads/soc-m2/.venv/bin/python run_eval.py --dataset dev --systems fixed_workflow,agent`
