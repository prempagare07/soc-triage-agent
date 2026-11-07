# Results: evtx_val

Alerts: 23

| Metric | rules | single_call | fixed_workflow | agent |
| --- | --- | --- | --- | --- |
| Tactic accuracy (exact) | 8/23 (34.8%) | 2/23 (8.7%) | 9/23 (39.1%) | 9/23 (39.1%) |
| Tactic top-2 | 8/23 (34.8%) | 2/23 (8.7%) | 9/23 (39.1%) | 13/23 (56.5%) |
| Macro-F1 (tactics with n>=5) | 0.42 (2 tactics) | 0.11 (2 tactics) | 0.48 (2 tactics) | 0.48 (2 tactics) |
| Verdict accuracy | 16/23 (69.6%) | 19/23 (82.6%) | 21/23 (91.3%) | 22/23 (95.7%) |
| Missed attacks | 7 (V002, V005, V015, V016, V017, V018, V022) | 4 (V002, V020, V021, V022) | 2 (V002, V016) | 1 (V002) |
| Under-escalations (incl. misses) | 8 | 18 | 7 | 1 |
|   of which Credential Access / Lateral Movement | 2 | 5 | 2 | 0 |
| Action-level accuracy | 15/23 (65.2%) | 5/23 (21.7%) | 16/23 (69.6%) | 21/23 (91.3%) |
| Uncertain escalations | 0 | 0 | 0 | 14 |
| Parse failures | 0 | 0 | 0 | 0 |
| Tool calls (total) | 0 | 0 | 168 | 216 |
| Tool errors | 0 | 0 | 2 | 0 |
| Verifier failures / revisions | 0 / 0 | 0 / 0 | 0 / 0 | 30 / 19 |
| Budget exhausted | 0 | 0 | 0 | 0 |
| Claim-level evidence validity | n/a | n/a | n/a | 23/26 (88.5%) |
| Latency p50 / p95 (s per alert) | n/a | 0.0 / 0.0 | 0.0 / 0.0 | 65.1 / 129.5 |
| Tokens (total, uncached runs) | 0 | 47960 | 68007 | 393631 |

Zero-miss 95% upper bound at 23 attacks: 12.2%

Tokens per alert relative to the single call: single_call 1.0x, fixed_workflow 1.4x, agent 8.2x

## Paired comparison with the agent (exact McNemar on tactic correctness)

| Baseline | agent right, baseline wrong | baseline right, agent wrong | p |
| --- | --- | --- | --- |
| rules | 1 | 0 | 1.000 |
| single_call | 8 | 1 | 0.039 |
| fixed_workflow | 0 | 0 | 1.000 |

## Tactic accuracy by true tactic

| True tactic | n | rules | single_call | fixed_workflow | agent |
| --- | --- | --- | --- | --- | --- |
| Execution | 1 | 1 | 1 | 1 | 1 |
| Lateral Movement | 7 | 2 | 1 | 3 | 3 |
| Privilege Escalation | 15 | 5 | 0 | 5 | 5 |

Model: `qwen2.5:7b` (ollama, temperature 0, seed 0). Command: `/Users/amatyakatyayan/Downloads/soc-m2/.venv/bin/python run_eval.py --dataset evtx_val --out outputs/m2_v22`
