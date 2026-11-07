# Results: benign

Alerts: 44

| Metric | rules | single_call | fixed_workflow | agent |
| --- | --- | --- | --- | --- |
| Tactic accuracy (exact) | 26/44 (59.1%) | 31/44 (70.5%) | 27/44 (61.4%) | 23/44 (52.3%) |
| Tactic top-2 | 26/44 (59.1%) | 31/44 (70.5%) | 27/44 (61.4%) | 23/44 (52.3%) |
| Macro-F1 (tactics with n>=5) | 0.74 (1 tactics) | 0.83 (1 tactics) | 0.76 (1 tactics) | 0.69 (1 tactics) |
| Verdict accuracy | 26/44 (59.1%) | 31/44 (70.5%) | 27/44 (61.4%) | 23/44 (52.3%) |
| Missed attacks | 0 | 0 | 0 | 0 |
| False positives (benign called malicious) | 18/44 (N017, N018, N021, N022, N023, N024, N027, N028...) | 13/44 (N006, N007, N008, N009, N010, N013, N014, N016...) | 17/44 (N007, N008, N012, N023, N024, N025, N026, N027...) | 21/44 (N001, N002, N007, N008, N011, N012, N017, N023...) |
| Under-escalations (incl. misses) | 0 | 0 | 0 | 0 |
|   of which Credential Access / Lateral Movement | 0 | 0 | 0 | 0 |
| Action-level accuracy | 26/44 (59.1%) | 31/44 (70.5%) | 27/44 (61.4%) | 3/44 (6.8%) |
| Uncertain escalations | 0 | 0 | 0 | 37 |
| Parse failures | 0 | 0 | 0 | 0 |
| Tool calls (total) | 0 | 0 | 264 | 375 |
| Tool errors | 0 | 0 | 3 | 1 |
| Verifier failures / revisions | 0 / 0 | 0 / 0 | 0 / 0 | 69 / 38 |
| Budget exhausted | 0 | 0 | 0 | 0 |
| Claim-level evidence validity | n/a | n/a | n/a | 42/50 (84.0%) |
| Latency p50 / p95 (s per alert) | n/a | 0.0 / 0.0 | 0.0 / 0.0 | 58.4 / 80.1 |
| Tokens (total, uncached runs) | 0 | 27135 | 71880 | 528399 |



Tokens per alert relative to the single call: single_call 1.0x, fixed_workflow 2.6x, agent 19.5x

## Paired comparison with the agent (exact McNemar on tactic correctness)

| Baseline | agent right, baseline wrong | baseline right, agent wrong | p |
| --- | --- | --- | --- |
| rules | 8 | 11 | 0.648 |
| single_call | 7 | 15 | 0.134 |
| fixed_workflow | 2 | 6 | 0.289 |

## Tactic accuracy by true tactic

| True tactic | n | rules | single_call | fixed_workflow | agent |
| --- | --- | --- | --- | --- | --- |
| Benign | 44 | 26 | 31 | 27 | 23 |

Model: `qwen2.5:7b` (ollama, temperature 0, seed 0). Command: `/Users/amatyakatyayan/Downloads/soc-m2/.venv/bin/python run_eval.py --dataset benign --out outputs/m2_v22`
