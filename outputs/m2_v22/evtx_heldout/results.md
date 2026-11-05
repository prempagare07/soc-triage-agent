# Results: evtx_heldout

Alerts: 81

| Metric | rules | single_call | fixed_workflow | agent |
| --- | --- | --- | --- | --- |
| Tactic accuracy (exact) | 25/81 (30.9%) | 12/81 (14.8%) | 27/81 (33.3%) | 28/81 (34.6%) |
| Tactic top-2 | 25/81 (30.9%) | 12/81 (14.8%) | 27/81 (33.3%) | 34/81 (42.0%) |
| Macro-F1 (tactics with n>=5) | 0.41 (6 tactics) | 0.15 (6 tactics) | 0.34 (6 tactics) | 0.33 (6 tactics) |
| Verdict accuracy | 49/81 (60.5%) | 68/81 (84.0%) | 69/81 (85.2%) | 72/81 (88.9%) |
| Missed attacks | 32 (H002, H003, H012, H016, H017, H018, H020, H022...) | 13 (H001, H002, H022, H023, H031, H040, H049, H055...) | 12 (H002, H021, H022, H032, H040, H042, H049, H055...) | 9 (H002, H022, H032, H040, H049, H055, H057, H058...) |
| Under-escalations (incl. misses) | 44 | 42 | 26 | 6 |
|   of which Credential Access / Lateral Movement | 11 | 19 | 10 | 1 |
| Action-level accuracy | 33/81 (40.7%) | 26/81 (32.1%) | 44/81 (54.3%) | 50/81 (61.7%) |
| Uncertain escalations | 0 | 0 | 0 | 56 |
| Parse failures | 0 | 0 | 0 | 0 |
| Tool calls (total) | 0 | 0 | 534 | 727 |
| Tool errors | 0 | 0 | 0 | 5 |
| Verifier failures / revisions | 0 / 0 | 0 / 0 | 0 / 0 | 113 / 69 |
| Budget exhausted | 0 | 0 | 0 | 0 |
| Claim-level evidence validity | n/a | n/a | n/a | 80/88 (90.9%) |
| Latency p50 / p95 (s per alert) | n/a | 0.0 / 0.0 | 0.0 / 0.0 | 63.2 / 147.8 |
| Tokens (total, uncached runs) | 0 | 172845 | 235284 | 1338451 |

Zero-miss 95% upper bound at 81 attacks: 3.6%

Tokens per alert relative to the single call: single_call 1.0x, fixed_workflow 1.4x, agent 7.7x

## Paired comparison with the agent (exact McNemar on tactic correctness)

| Baseline | agent right, baseline wrong | baseline right, agent wrong | p |
| --- | --- | --- | --- |
| rules | 11 | 8 | 0.648 |
| single_call | 18 | 2 | 0.000 |
| fixed_workflow | 2 | 1 | 1.000 |

## Tactic accuracy by true tactic

| True tactic | n | rules | single_call | fixed_workflow | agent |
| --- | --- | --- | --- | --- | --- |
| Command and Control | 1 | 0 | 0 | 0 | 0 |
| Credential Access | 13 | 6 | 1 | 5 | 5 |
| Defense Evasion | 14 | 0 | 0 | 0 | 0 |
| Discovery | 2 | 0 | 0 | 0 | 0 |
| Execution | 15 | 7 | 7 | 10 | 12 |
| Lateral Movement | 15 | 6 | 2 | 5 | 5 |
| Persistence | 6 | 3 | 1 | 2 | 1 |
| Privilege Escalation | 15 | 3 | 1 | 5 | 5 |

Model: `qwen2.5:7b` (ollama, temperature 0, seed 0). Command: `/Users/amatyakatyayan/Downloads/soc-m2/.venv/bin/python run_eval.py --dataset evtx_heldout --out outputs/m2_v22`
