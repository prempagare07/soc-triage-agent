# Results: benign_fresh

Alerts: 20

| Metric | rules | single_call | fixed_workflow | agent |
| --- | --- | --- | --- | --- |
| Tactic accuracy (exact) | 18/20 (90.0%) | 14/20 (70.0%) | 12/20 (60.0%) | 12/20 (60.0%) |
| Tactic top-2 | 18/20 (90.0%) | 14/20 (70.0%) | 12/20 (60.0%) | 12/20 (60.0%) |
| Macro-F1 (tactics with n>=5) | 0.95 (1 tactics) | 0.82 (1 tactics) | 0.75 (1 tactics) | 0.75 (1 tactics) |
| Verdict accuracy | 18/20 (90.0%) | 14/20 (70.0%) | 12/20 (60.0%) | 12/20 (60.0%) |
| Missed attacks | 0 | 0 | 0 | 0 |
| False positives (benign called malicious) | 2/20 (F015, F016) | 6/20 (F001, F002, F011, F012, F013, F014) | 8/20 (F002, F011, F012, F013, F015, F016, F017, F018) | 8/20 (F001, F002, F003, F011, F012, F013, F015, F016) |
| Under-escalations (incl. misses) | 0 | 0 | 0 | 0 |
|   of which Credential Access / Lateral Movement | 0 | 0 | 0 | 0 |
| Action-level accuracy | 18/20 (90.0%) | 14/20 (70.0%) | 12/20 (60.0%) | 2/20 (10.0%) |
| Uncertain escalations | 0 | 0 | 0 | 16 |
| Parse failures | 0 | 0 | 0 | 0 |
| Tool calls (total) | 0 | 0 | 104 | 154 |
| Tool errors | 0 | 0 | 0 | 1 |
| Verifier failures / revisions | 0 / 0 | 0 / 0 | 0 / 0 | 31 / 16 |
| Budget exhausted | 0 | 0 | 0 | 0 |
| Claim-level evidence validity | n/a | n/a | n/a | 17/20 (85.0%) |
| Latency p50 / p95 (s per alert) | n/a | 7.0 / 7.8 | 15.2 / 17.2 | 54.3 / 71.8 |
| Tokens (total, uncached runs) | 0 | 10110 | 28765 | 222399 |



Tokens per alert relative to the single call: single_call 1.0x, fixed_workflow 2.8x, agent 22.0x

## Paired comparison with the agent (exact McNemar on tactic correctness)

| Baseline | agent right, baseline wrong | baseline right, agent wrong | p |
| --- | --- | --- | --- |
| rules | 0 | 6 | 0.031 |
| single_call | 1 | 3 | 0.625 |
| fixed_workflow | 2 | 2 | 1.000 |

## Tactic accuracy by true tactic

| True tactic | n | rules | single_call | fixed_workflow | agent |
| --- | --- | --- | --- | --- | --- |
| Benign | 20 | 18 | 14 | 12 | 12 |

Model: `qwen2.5:7b` (ollama, temperature 0, seed 0). Command: `/Users/amatyakatyayan/Downloads/soc-m2/.venv/bin/python run_eval.py --dataset benign_fresh --out outputs/m2_v22`
