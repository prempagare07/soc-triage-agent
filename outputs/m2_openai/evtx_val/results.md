# Results: evtx_val

Alerts: 23

| Metric | rules | single_call | fixed_workflow | agent |
| --- | --- | --- | --- | --- |
| Tactic accuracy (exact) | 8/23 (34.8%) | 4/23 (17.4%) | 9/23 (39.1%) | 9/23 (39.1%) |
| Tactic top-2 | 8/23 (34.8%) | 4/23 (17.4%) | 9/23 (39.1%) | 13/23 (56.5%) |
| Macro-F1 (tactics with n>=5) | 0.42 (2 tactics) | 0.17 (2 tactics) | 0.45 (2 tactics) | 0.45 (2 tactics) |
| Verdict accuracy | 16/23 (69.6%) | 22/23 (95.7%) | 23/23 (100.0%) | 23/23 (100.0%) |
| Missed attacks | 7 (V002, V005, V015, V016, V017, V018, V022) | 1 (V020) | 0 | 0 |
| Under-escalations (incl. misses) | 8 | 8 | 5 | 5 |
|   of which Credential Access / Lateral Movement | 2 | 2 | 2 | 2 |
| Action-level accuracy | 15/23 (65.2%) | 15/23 (65.2%) | 18/23 (78.3%) | 18/23 (78.3%) |
| Uncertain escalations | 0 | 0 | 0 | 0 |
| Parse failures | 0 | 0 | 0 | 0 |
| Tool calls (total) | 0 | 0 | 168 | 168 |
| Tool errors | 0 | 0 | 2 | 0 |
| Verifier failures / revisions | 0 / 0 | 0 / 0 | 0 / 0 | 3 / 3 |
| Budget exhausted | 0 | 0 | 0 | 0 |
| Claim-level evidence validity | n/a | n/a | n/a | 38/38 (100.0%) |
| Latency p50 / p95 (s per alert) | n/a | 0.0 / 0.0 | 0.0 / 0.0 | 4.6 / 7.4 |
| Tokens (total, uncached runs) | 0 | 39818 | 57558 | 145607 |

Zero-miss 95% upper bound at 23 attacks: 12.2%

Tokens per alert relative to the single call: single_call 1.0x, fixed_workflow 1.4x, agent 3.7x

## Paired comparison with the agent (exact McNemar on tactic correctness)

| Baseline | agent right, baseline wrong | baseline right, agent wrong | p |
| --- | --- | --- | --- |
| rules | 1 | 0 | 1.000 |
| single_call | 6 | 1 | 0.125 |
| fixed_workflow | 0 | 0 | 1.000 |

## Tactic accuracy by true tactic

| True tactic | n | rules | single_call | fixed_workflow | agent |
| --- | --- | --- | --- | --- | --- |
| Execution | 1 | 1 | 1 | 1 | 1 |
| Lateral Movement | 7 | 2 | 0 | 2 | 2 |
| Privilege Escalation | 15 | 5 | 3 | 6 | 6 |

Model: `gpt-4o-mini` (openai, temperature 0, seed 0). Command: `/Users/amatyakatyayan/Downloads/soc-m2/.venv/bin/python run_eval.py --provider openai --dataset evtx_val --systems agent --out outputs/m2_openai`
