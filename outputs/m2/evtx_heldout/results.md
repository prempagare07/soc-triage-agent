# Results: evtx_heldout

Alerts: 81

| Metric | rules | single_call | fixed_workflow | agent | agent_b4 |
| --- | --- | --- | --- | --- | --- |
| Tactic accuracy (exact) | 25/81 (30.9%) | 12/81 (14.8%) | 21/81 (25.9%) | 19/81 (23.5%) | 15/81 (18.5%) |
| Tactic top-2 | 25/81 (30.9%) | 12/81 (14.8%) | 21/81 (25.9%) | 25/81 (30.9%) | 19/81 (23.5%) |
| Macro-F1 (tactics with n>=5) | 0.41 (6 tactics) | 0.15 (6 tactics) | 0.26 (6 tactics) | 0.28 (6 tactics) | 0.23 (6 tactics) |
| Verdict accuracy | 49/81 (60.5%) | 68/81 (84.0%) | 69/81 (85.2%) | 66/81 (81.5%) | 63/81 (77.8%) |
| Missed attacks | 32 (H002, H003, H012, H016, H017, H018, H020, H022...) | 13 (H001, H002, H022, H023, H031, H040, H049, H055...) | 12 (H001, H002, H021, H031, H040, H048, H049, H055...) | 15 (H002, H013, H016, H023, H028, H031, H032, H034...) | 18 (H002, H008, H009, H013, H017, H022, H023, H027...) |
| Under-escalations (incl. misses) | 44 | 42 | 31 | 22 | 18 |
|   of which Credential Access / Lateral Movement | 11 | 19 | 15 | 10 | 7 |
| Action-level accuracy | 33/81 (40.7%) | 26/81 (32.1%) | 39/81 (48.1%) | 39/81 (48.1%) | 45/81 (55.6%) |
| Uncertain escalations | 0 | 0 | 0 | 15 | 15 |
| Parse failures | 0 | 0 | 0 | 0 | 0 |
| Tool calls (total) | 0 | 0 | 534 | 399 | 272 |
| Tool errors | 0 | 0 | 0 | 0 | 0 |
| Verifier failures / revisions | 0 / 0 | 0 / 0 | 0 / 0 | 35 / 21 | 15 / 10 |
| Budget exhausted | 0 | 0 | 0 | 1 | 0 |
| Claim-level evidence validity | n/a | n/a | n/a | 97/113 (85.8%) | 101/106 (95.3%) |
| Latency p50 / p95 (s per alert) | n/a | 16.1 / 50.5 | 13.6 / 25.0 | 66.6 / 135.5 | 51.6 / 109.0 |
| Tokens (total, uncached runs) | 0 | 172845 | 236864 | 1557844 | 1065403 |

Zero-miss 95% upper bound at 81 attacks: 3.6%

## Paired comparison with the agent (exact McNemar on tactic correctness)

| Baseline | agent right, baseline wrong | baseline right, agent wrong | p |
| --- | --- | --- | --- |
| rules | 13 | 19 | 0.377 |
| single_call | 16 | 9 | 0.230 |
| fixed_workflow | 11 | 13 | 0.839 |
| agent_b4 | 10 | 6 | 0.454 |

## Tactic accuracy by true tactic

| True tactic | n | rules | single_call | fixed_workflow | agent | agent_b4 |
| --- | --- | --- | --- | --- | --- | --- |
| Command and Control | 1 | 0 | 0 | 0 | 0 | 0 |
| Credential Access | 13 | 6 | 1 | 3 | 4 | 2 |
| Defense Evasion | 14 | 0 | 0 | 1 | 3 | 2 |
| Discovery | 2 | 0 | 0 | 0 | 0 | 0 |
| Execution | 15 | 7 | 7 | 11 | 3 | 4 |
| Lateral Movement | 15 | 6 | 2 | 1 | 1 | 2 |
| Persistence | 6 | 3 | 1 | 2 | 2 | 2 |
| Privilege Escalation | 15 | 3 | 1 | 3 | 6 | 3 |

Model: `qwen2.5:7b` (Ollama, temperature 0, seed 0). Command: `/Users/amatyakatyayan/Downloads/soc-m2/.venv/bin/python run_eval.py --dataset evtx_heldout --systems agent --budget 4`
