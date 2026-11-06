# Results: otrf_pilot

Alerts: 55

| Metric | rules | single_call | fixed_workflow | agent |
| --- | --- | --- | --- | --- |
| Tactic accuracy (exact) | 11/55 (20.0%) | 5/55 (9.1%) | 8/55 (14.5%) | 6/55 (10.9%) |
| Tactic top-2 | 11/55 (20.0%) | 5/55 (9.1%) | 8/55 (14.5%) | 13/55 (23.6%) |
| Macro-F1 (tactics with n>=5) | 0.16 (4 tactics) | 0.03 (4 tactics) | 0.12 (4 tactics) | 0.06 (4 tactics) |
| Verdict accuracy | 43/55 (78.2%) | 47/55 (85.5%) | 51/55 (92.7%) | 49/55 (89.1%) |
| Missed attacks | 12 (O005, O009, O010, O013, O016, O021, O024, O032...) | 8 (O005, O006, O017, O024, O032, O036, O038, O052) | 4 (O024, O032, O036, O038) | 6 (O015, O016, O032, O036, O038, O040) |
| Under-escalations (incl. misses) | 14 | 27 | 18 | 12 |
|   of which Credential Access / Lateral Movement | 6 | 20 | 12 | 6 |
| Action-level accuracy | 25/55 (45.5%) | 19/55 (34.5%) | 29/55 (52.7%) | 26/55 (47.3%) |
| Uncertain escalations | 0 | 0 | 0 | 28 |
| Parse failures | 0 | 0 | 0 | 0 |
| Tool calls (total) | 0 | 0 | 426 | 566 |
| Tool errors | 0 | 0 | 0 | 1 |
| Verifier failures / revisions | 0 / 0 | 0 / 0 | 0 / 0 | 76 / 54 |
| Budget exhausted | 0 | 0 | 0 | 0 |
| Claim-level evidence validity | n/a | n/a | n/a | 54/63 (85.7%) |
| Latency p50 / p95 (s per alert) | n/a | 0.0 / 0.0 | 52.0 / 62.4 | 104.6 / 135.6 |
| Tokens (total, uncached runs) | 0 | 205728 | 295461 | 1575410 |

Zero-miss 95% upper bound at 55 attacks: 5.3%

Tokens per alert relative to the single call: single_call 1.0x, fixed_workflow 1.4x, agent 7.7x

## Paired comparison with the agent (exact McNemar on tactic correctness)

| Baseline | agent right, baseline wrong | baseline right, agent wrong | p |
| --- | --- | --- | --- |
| rules | 2 | 7 | 0.180 |
| single_call | 3 | 2 | 1.000 |
| fixed_workflow | 0 | 2 | 0.500 |

## Tactic accuracy by true tactic

| True tactic | n | rules | single_call | fixed_workflow | agent |
| --- | --- | --- | --- | --- | --- |
| Credential Access | 11 | 4 | 0 | 2 | 2 |
| Defense Evasion | 15 | 0 | 0 | 0 | 0 |
| Discovery | 7 | 0 | 0 | 0 | 0 |
| Execution | 4 | 1 | 3 | 3 | 3 |
| Lateral Movement | 13 | 4 | 1 | 2 | 0 |
| Persistence | 4 | 1 | 1 | 0 | 0 |
| Privilege Escalation | 1 | 1 | 0 | 1 | 1 |

Model: `qwen2.5:7b` (ollama, temperature 0, seed 0). Command: `/Users/amatyakatyayan/Downloads/soc-m2/.venv/bin/python run_eval.py --dataset otrf_pilot --out outputs/m2_v22`
