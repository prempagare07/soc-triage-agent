# Results: benign_fresh

Alerts: 20

| Metric | rules | single_call | fixed_workflow | agent |
| --- | --- | --- | --- | --- |
| Tactic accuracy (exact) | 18/20 (90.0%) | 13/20 (65.0%) | 8/20 (40.0%) | 8/20 (40.0%) |
| Tactic top-2 | 18/20 (90.0%) | 13/20 (65.0%) | 8/20 (40.0%) | 8/20 (40.0%) |
| Macro-F1 (tactics with n>=5) | 0.95 (1 tactics) | 0.79 (1 tactics) | 0.57 (1 tactics) | 0.57 (1 tactics) |
| Verdict accuracy | 18/20 (90.0%) | 13/20 (65.0%) | 8/20 (40.0%) | 8/20 (40.0%) |
| Missed attacks | 0 | 0 | 0 | 0 |
| False positives (benign called malicious) | 2/20 (F015, F016) | 7/20 (F006, F009, F010, F011, F012, F019, F020) | 12/20 (F005, F006, F009, F010, F011, F012, F015, F016...) | 12/20 (F005, F006, F009, F010, F011, F012, F015, F016...) |
| Under-escalations (incl. misses) | 0 | 0 | 0 | 0 |
|   of which Credential Access / Lateral Movement | 0 | 0 | 0 | 0 |
| Action-level accuracy | 18/20 (90.0%) | 13/20 (65.0%) | 8/20 (40.0%) | 8/20 (40.0%) |
| Uncertain escalations | 0 | 0 | 0 | 0 |
| Parse failures | 0 | 0 | 0 | 0 |
| Tool calls (total) | 0 | 0 | 104 | 110 |
| Tool errors | 0 | 0 | 0 | 0 |
| Verifier failures / revisions | 0 / 0 | 0 / 0 | 0 / 0 | 2 / 2 |
| Budget exhausted | 0 | 0 | 0 | 0 |
| Claim-level evidence validity | n/a | n/a | n/a | 23/23 (100.0%) |
| Latency p50 / p95 (s per alert) | n/a | 2.1 / 2.6 | 2.1 / 2.8 | 4.0 / 6.7 |
| Tokens (total, uncached runs) | 0 | 10396 | 28161 | 84372 |



Tokens per alert relative to the single call: single_call 1.0x, fixed_workflow 2.7x, agent 8.1x

## Paired comparison with the agent (exact McNemar on tactic correctness)

| Baseline | agent right, baseline wrong | baseline right, agent wrong | p |
| --- | --- | --- | --- |
| rules | 0 | 10 | 0.002 |
| single_call | 0 | 5 | 0.062 |
| fixed_workflow | 0 | 0 | 1.000 |

## Tactic accuracy by true tactic

| True tactic | n | rules | single_call | fixed_workflow | agent |
| --- | --- | --- | --- | --- | --- |
| Benign | 20 | 18 | 13 | 8 | 8 |

Model: `gpt-4o-mini` (openai, temperature 0, seed 0). Command: `/Users/amatyakatyayan/Downloads/soc-m2/.venv/bin/python run_eval.py --provider openai --dataset benign_fresh --systems agent --out outputs/m2_openai`
