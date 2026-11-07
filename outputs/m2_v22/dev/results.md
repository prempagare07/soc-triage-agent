# Results: dev

Alerts: 28

| Metric | rules | single_call | fixed_workflow | agent |
| --- | --- | --- | --- | --- |
| Tactic accuracy (exact) | 16/28 (57.1%) | 7/28 (25.0%) | 15/28 (53.6%) | 15/28 (53.6%) |
| Tactic top-2 | 16/28 (57.1%) | 7/28 (25.0%) | 15/28 (53.6%) | 17/28 (60.7%) |
| Macro-F1 (tactics with n>=5) | n/a | n/a | n/a | n/a |
| Verdict accuracy | 23/28 (82.1%) | 18/28 (64.3%) | 24/28 (85.7%) | 25/28 (89.3%) |
| Missed attacks | 5 (A003, A010, A011, A012, A016) | 9 (A001, A002, A005, A007, A010, A017, A018, A019...) | 4 (A010, A011, A016, A018) | 3 (A010, A016, A018) |
| False positives (benign called malicious) | 0/4 | 1/4 (B002) | 0/4 | 0/4 |
| Under-escalations (incl. misses) | 7 | 15 | 5 | 0 |
|   of which Credential Access / Lateral Movement | 2 | 5 | 2 | 0 |
| Action-level accuracy | 18/28 (64.3%) | 8/28 (28.6%) | 19/28 (67.9%) | 18/28 (64.3%) |
| Uncertain escalations | 0 | 0 | 0 | 20 |
| Parse failures | 0 | 0 | 0 | 0 |
| Tool calls (total) | 0 | 0 | 178 | 245 |
| Tool errors | 0 | 0 | 0 | 0 |
| Verifier failures / revisions | 0 / 0 | 0 / 0 | 0 / 0 | 42 / 25 |
| Budget exhausted | 0 | 0 | 0 | 0 |
| Claim-level evidence validity | n/a | n/a | n/a | 32/32 (100.0%) |
| Latency p50 / p95 (s per alert) | n/a | 0.0 / 0.0 | 0.0 / 0.0 | 67.0 / 98.3 |
| Tokens (total, uncached runs) | 0 | 26586 | 44847 | 311122 |

Zero-miss 95% upper bound at 24 attacks: 11.7%

Tokens per alert relative to the single call: single_call 1.0x, fixed_workflow 1.7x, agent 11.7x

## Paired comparison with the agent (exact McNemar on tactic correctness)

| Baseline | agent right, baseline wrong | baseline right, agent wrong | p |
| --- | --- | --- | --- |
| rules | 1 | 2 | 1.000 |
| single_call | 8 | 0 | 0.008 |
| fixed_workflow | 0 | 0 | 1.000 |

## Tactic accuracy by true tactic

| True tactic | n | rules | single_call | fixed_workflow | agent |
| --- | --- | --- | --- | --- | --- |
| Command and Control | 3 | 1 | 1 | 2 | 2 |
| Credential Access | 3 | 2 | 0 | 1 | 1 |
| Defense Evasion | 3 | 0 | 0 | 0 | 0 |
| Discovery | 3 | 0 | 0 | 0 | 0 |
| Execution | 3 | 3 | 3 | 3 | 3 |
| Lateral Movement | 3 | 1 | 0 | 1 | 1 |
| Persistence | 3 | 2 | 0 | 1 | 1 |
| Privilege Escalation | 3 | 3 | 0 | 3 | 3 |
| Benign | 4 | 4 | 3 | 4 | 4 |

Model: `qwen2.5:7b` (ollama, temperature 0, seed 0). Command: `/Users/amatyakatyayan/Downloads/soc-m2/.venv/bin/python run_eval.py --dataset dev --out outputs/m2_v22`
