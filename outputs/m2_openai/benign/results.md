# Results: benign

Alerts: 44

| Metric | rules | single_call | fixed_workflow | agent |
| --- | --- | --- | --- | --- |
| Tactic accuracy (exact) | 26/44 (59.1%) | 32/44 (72.7%) | 20/44 (45.5%) | 21/44 (47.7%) |
| Tactic top-2 | 26/44 (59.1%) | 32/44 (72.7%) | 20/44 (45.5%) | 21/44 (47.7%) |
| Macro-F1 (tactics with n>=5) | 0.74 (1 tactics) | 0.84 (1 tactics) | 0.62 (1 tactics) | 0.65 (1 tactics) |
| Verdict accuracy | 26/44 (59.1%) | 32/44 (72.7%) | 20/44 (45.5%) | 21/44 (47.7%) |
| Missed attacks | 0 | 0 | 0 | 0 |
| False positives (benign called malicious) | 18/44 (N017, N018, N021, N022, N023, N024, N027, N028...) | 12/44 (N002, N013, N014, N015, N016, N023, N024, N025...) | 24/44 (N002, N013, N014, N016, N017, N018, N021, N022...) | 23/44 (N002, N013, N014, N016, N017, N018, N021, N023...) |
| Under-escalations (incl. misses) | 0 | 0 | 0 | 0 |
|   of which Credential Access / Lateral Movement | 0 | 0 | 0 | 0 |
| Action-level accuracy | 26/44 (59.1%) | 32/44 (72.7%) | 20/44 (45.5%) | 19/44 (43.2%) |
| Uncertain escalations | 0 | 0 | 0 | 3 |
| Parse failures | 0 | 0 | 0 | 0 |
| Tool calls (total) | 0 | 0 | 264 | 276 |
| Tool errors | 0 | 0 | 3 | 2 |
| Verifier failures / revisions | 0 / 0 | 0 / 0 | 0 / 0 | 6 / 4 |
| Budget exhausted | 0 | 0 | 0 | 0 |
| Claim-level evidence validity | n/a | n/a | n/a | 50/52 (96.2%) |
| Latency p50 / p95 (s per alert) | n/a | 0.0 / 0.0 | 0.0 / 0.0 | 4.0 / 7.8 |
| Tokens (total, uncached runs) | 0 | 27291 | 70217 | 205187 |



Tokens per alert relative to the single call: single_call 1.0x, fixed_workflow 2.6x, agent 7.5x

## Paired comparison with the agent (exact McNemar on tactic correctness)

| Baseline | agent right, baseline wrong | baseline right, agent wrong | p |
| --- | --- | --- | --- |
| rules | 1 | 6 | 0.125 |
| single_call | 1 | 12 | 0.003 |
| fixed_workflow | 1 | 0 | 1.000 |

## Tactic accuracy by true tactic

| True tactic | n | rules | single_call | fixed_workflow | agent |
| --- | --- | --- | --- | --- | --- |
| Benign | 44 | 26 | 32 | 20 | 21 |

Model: `gpt-4o-mini` (openai, temperature 0, seed 0). Command: `/Users/amatyakatyayan/Downloads/soc-m2/.venv/bin/python run_eval.py --provider openai --dataset benign --systems agent --out outputs/m2_openai`
