# Results: otrf_pilot

Alerts: 55

| Metric | rules | single_call | fixed_workflow | agent |
| --- | --- | --- | --- | --- |
| Tactic accuracy (exact) | 11/55 (20.0%) | 12/55 (21.8%) | 13/55 (23.6%) | 13/55 (23.6%) |
| Tactic top-2 | 11/55 (20.0%) | 12/55 (21.8%) | 13/55 (23.6%) | 21/55 (38.2%) |
| Macro-F1 (tactics with n>=5) | 0.16 (4 tactics) | 0.12 (4 tactics) | 0.16 (4 tactics) | 0.16 (4 tactics) |
| Verdict accuracy | 43/55 (78.2%) | 50/55 (90.9%) | 52/55 (94.5%) | 52/55 (94.5%) |
| Missed attacks | 12 (O005, O009, O010, O013, O016, O021, O024, O032...) | 5 (O005, O006, O016, O017, O041) | 3 (O005, O016, O038) | 3 (O005, O016, O038) |
| Under-escalations (incl. misses) | 14 | 14 | 6 | 6 |
|   of which Credential Access / Lateral Movement | 6 | 11 | 5 | 5 |
| Action-level accuracy | 25/55 (45.5%) | 27/55 (49.1%) | 31/55 (56.4%) | 31/55 (56.4%) |
| Uncertain escalations | 0 | 0 | 0 | 0 |
| Parse failures | 0 | 0 | 0 | 0 |
| Tool calls (total) | 0 | 0 | 426 | 426 |
| Tool errors | 0 | 0 | 0 | 0 |
| Verifier failures / revisions | 0 / 0 | 0 / 0 | 0 / 0 | 8 / 8 |
| Budget exhausted | 0 | 0 | 0 | 0 |
| Claim-level evidence validity | n/a | n/a | n/a | 72/72 (100.0%) |
| Latency p50 / p95 (s per alert) | n/a | 0.0 / 0.0 | 0.0 / 0.0 | 4.1 / 8.2 |
| Tokens (total, uncached runs) | 0 | 164695 | 242512 | 573033 |

Zero-miss 95% upper bound at 55 attacks: 5.3%

Tokens per alert relative to the single call: single_call 1.0x, fixed_workflow 1.5x, agent 3.5x

## Paired comparison with the agent (exact McNemar on tactic correctness)

| Baseline | agent right, baseline wrong | baseline right, agent wrong | p |
| --- | --- | --- | --- |
| rules | 3 | 1 | 0.625 |
| single_call | 4 | 3 | 1.000 |
| fixed_workflow | 0 | 0 | 1.000 |

## Tactic accuracy by true tactic

| True tactic | n | rules | single_call | fixed_workflow | agent |
| --- | --- | --- | --- | --- | --- |
| Credential Access | 11 | 4 | 6 | 6 | 6 |
| Defense Evasion | 15 | 0 | 0 | 0 | 0 |
| Discovery | 7 | 0 | 0 | 0 | 0 |
| Execution | 4 | 1 | 3 | 2 | 2 |
| Lateral Movement | 13 | 4 | 1 | 3 | 3 |
| Persistence | 4 | 1 | 2 | 1 | 1 |
| Privilege Escalation | 1 | 1 | 0 | 1 | 1 |

Model: `gpt-4o-mini` (openai, temperature 0, seed 0). Command: `/Users/amatyakatyayan/Downloads/soc-m2/.venv/bin/python run_eval.py --provider openai --dataset otrf_pilot --systems agent --out outputs/m2_openai`
