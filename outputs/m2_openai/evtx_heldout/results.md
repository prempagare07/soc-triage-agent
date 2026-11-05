# Results: evtx_heldout

Alerts: 81

| Metric | rules | single_call | fixed_workflow | agent |
| --- | --- | --- | --- | --- |
| Tactic accuracy (exact) | 25/81 (30.9%) | 37/81 (45.7%) | 38/81 (46.9%) | 38/81 (46.9%) |
| Tactic top-2 | 25/81 (30.9%) | 37/81 (45.7%) | 38/81 (46.9%) | 50/81 (61.7%) |
| Macro-F1 (tactics with n>=5) | 0.41 (6 tactics) | 0.47 (6 tactics) | 0.47 (6 tactics) | 0.47 (6 tactics) |
| Verdict accuracy | 49/81 (60.5%) | 76/81 (93.8%) | 76/81 (93.8%) | 76/81 (93.8%) |
| Missed attacks | 32 (H002, H003, H012, H016, H017, H018, H020, H022...) | 5 (H002, H017, H055, H059, H072) | 5 (H002, H017, H055, H058, H080) | 5 (H002, H017, H055, H058, H080) |
| Under-escalations (incl. misses) | 44 | 17 | 14 | 14 |
|   of which Credential Access / Lateral Movement | 11 | 9 | 6 | 6 |
| Action-level accuracy | 33/81 (40.7%) | 52/81 (64.2%) | 58/81 (71.6%) | 58/81 (71.6%) |
| Uncertain escalations | 0 | 0 | 0 | 2 |
| Parse failures | 0 | 0 | 0 | 0 |
| Tool calls (total) | 0 | 0 | 534 | 534 |
| Tool errors | 0 | 0 | 0 | 0 |
| Verifier failures / revisions | 0 / 0 | 0 / 0 | 0 / 0 | 12 / 10 |
| Budget exhausted | 0 | 0 | 0 | 0 |
| Claim-level evidence validity | n/a | n/a | n/a | 118/120 (98.3%) |
| Latency p50 / p95 (s per alert) | n/a | 0.0 / 0.0 | 0.0 / 0.0 | 4.5 / 7.7 |
| Tokens (total, uncached runs) | 0 | 142854 | 198245 | 512312 |

Zero-miss 95% upper bound at 81 attacks: 3.6%

Tokens per alert relative to the single call: single_call 1.0x, fixed_workflow 1.4x, agent 3.6x

## Paired comparison with the agent (exact McNemar on tactic correctness)

| Baseline | agent right, baseline wrong | baseline right, agent wrong | p |
| --- | --- | --- | --- |
| rules | 14 | 1 | 0.001 |
| single_call | 9 | 8 | 1.000 |
| fixed_workflow | 0 | 0 | 1.000 |

## Tactic accuracy by true tactic

| True tactic | n | rules | single_call | fixed_workflow | agent |
| --- | --- | --- | --- | --- | --- |
| Command and Control | 1 | 0 | 0 | 0 | 0 |
| Credential Access | 13 | 6 | 11 | 9 | 9 |
| Defense Evasion | 14 | 0 | 2 | 1 | 1 |
| Discovery | 2 | 0 | 0 | 0 | 0 |
| Execution | 15 | 7 | 11 | 12 | 12 |
| Lateral Movement | 15 | 6 | 3 | 6 | 6 |
| Persistence | 6 | 3 | 3 | 3 | 3 |
| Privilege Escalation | 15 | 3 | 7 | 7 | 7 |

Model: `gpt-4o-mini` (openai, temperature 0, seed 0). Command: `/Users/amatyakatyayan/Downloads/soc-m2/.venv/bin/python run_eval.py --provider openai --dataset evtx_heldout --systems agent --out outputs/m2_openai`
