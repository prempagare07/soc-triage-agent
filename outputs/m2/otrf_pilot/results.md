# Results: otrf_pilot

Alerts: 55

| Metric | rules | single_call | fixed_workflow | agent |
| --- | --- | --- | --- | --- |
| Tactic accuracy (exact) | 11/55 (20.0%) | 5/55 (9.1%) | 8/55 (14.5%) | 7/55 (12.7%) |
| Tactic top-2 | 11/55 (20.0%) | 5/55 (9.1%) | 8/55 (14.5%) | 15/55 (27.3%) |
| Macro-F1 (tactics with n>=5) | 0.16 (4 tactics) | 0.03 (4 tactics) | 0.14 (4 tactics) | 0.13 (4 tactics) |
| Verdict accuracy | 43/55 (78.2%) | 47/55 (85.5%) | 51/55 (92.7%) | 44/55 (80.0%) |
| Missed attacks | 12 (O005, O009, O010, O013, O016, O021, O024, O032...) | 8 (O005, O006, O017, O024, O032, O036, O038, O052) | 4 (O017, O024, O032, O038) | 11 (O002, O005, O006, O010, O015, O016, O017, O029...) |
| Under-escalations (incl. misses) | 14 | 27 | 23 | 13 |
|   of which Credential Access / Lateral Movement | 6 | 20 | 16 | 10 |
| Action-level accuracy | 25/55 (45.5%) | 19/55 (34.5%) | 26/55 (47.3%) | 25/55 (45.5%) |
| Uncertain escalations | 0 | 0 | 0 | 15 |
| Parse failures | 0 | 0 | 0 | 0 |
| Tool calls (total) | 0 | 0 | 426 | 282 |
| Tool errors | 0 | 0 | 0 | 0 |
| Verifier failures / revisions | 0 / 0 | 0 / 0 | 0 / 0 | 29 / 16 |
| Budget exhausted | 0 | 0 | 0 | 0 |
| Claim-level evidence validity | n/a | n/a | n/a | 77/91 (84.6%) |
| Latency p50 / p95 (s per alert) | n/a | 0.0 / 0.0 | 0.0 / 0.0 | 87.9 / 161.0 |
| Tokens (total, uncached runs) | 0 | 205728 | 296568 | 1682164 |

Zero-miss 95% upper bound at 55 attacks: 5.3%

## Paired comparison with the agent (exact McNemar on tactic correctness)

| Baseline | agent right, baseline wrong | baseline right, agent wrong | p |
| --- | --- | --- | --- |
| rules | 4 | 8 | 0.388 |
| single_call | 4 | 2 | 0.688 |
| fixed_workflow | 3 | 4 | 1.000 |

## Tactic accuracy by true tactic

| True tactic | n | rules | single_call | fixed_workflow | agent |
| --- | --- | --- | --- | --- | --- |
| Credential Access | 11 | 4 | 0 | 2 | 1 |
| Defense Evasion | 15 | 0 | 0 | 0 | 0 |
| Discovery | 7 | 0 | 0 | 1 | 1 |
| Execution | 4 | 1 | 3 | 4 | 3 |
| Lateral Movement | 13 | 4 | 1 | 0 | 1 |
| Persistence | 4 | 1 | 1 | 1 | 1 |
| Privilege Escalation | 1 | 1 | 0 | 0 | 0 |

Model: `qwen2.5:7b` (Ollama, temperature 0, seed 0). Command: `/Users/amatyakatyayan/Downloads/soc-m2/.venv/bin/python run_eval.py --dataset otrf_pilot`
