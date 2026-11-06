# Results: dev

Alerts: 28

| Metric | rules | single_call | fixed_workflow | agent |
| --- | --- | --- | --- | --- |
| Tactic accuracy (exact) | 16/28 (57.1%) | 12/28 (42.9%) | 17/28 (60.7%) | 17/28 (60.7%) |
| Tactic top-2 | 16/28 (57.1%) | 12/28 (42.9%) | 17/28 (60.7%) | 22/28 (78.6%) |
| Macro-F1 (tactics with n>=5) | n/a | n/a | n/a | n/a |
| Verdict accuracy | 23/28 (82.1%) | 26/28 (92.9%) | 26/28 (92.9%) | 26/28 (92.9%) |
| Missed attacks | 5 (A003, A010, A011, A012, A016) | 2 (A014, A019) | 2 (A010, A018) | 2 (A010, A018) |
| False positives (benign called malicious) | 0/4 | 0/4 | 0/4 | 0/4 |
| Under-escalations (incl. misses) | 7 | 4 | 3 | 3 |
|   of which Credential Access / Lateral Movement | 2 | 1 | 2 | 2 |
| Action-level accuracy | 18/28 (64.3%) | 17/28 (60.7%) | 20/28 (71.4%) | 20/28 (71.4%) |
| Uncertain escalations | 0 | 0 | 0 | 1 |
| Parse failures | 0 | 0 | 0 | 0 |
| Tool calls (total) | 0 | 0 | 178 | 181 |
| Tool errors | 0 | 0 | 0 | 0 |
| Verifier failures / revisions | 0 / 0 | 0 / 0 | 0 / 0 | 7 / 6 |
| Budget exhausted | 0 | 0 | 0 | 0 |
| Claim-level evidence validity | n/a | n/a | n/a | 38/39 (97.4%) |
| Latency p50 / p95 (s per alert) | n/a | 0.0 / 0.0 | 0.0 / 0.0 | 4.3 / 9.5 |
| Tokens (total, uncached runs) | 0 | 25499 | 42389 | 134989 |

Zero-miss 95% upper bound at 24 attacks: 11.7%

Tokens per alert relative to the single call: single_call 1.0x, fixed_workflow 1.7x, agent 5.3x

## Paired comparison with the agent (exact McNemar on tactic correctness)

| Baseline | agent right, baseline wrong | baseline right, agent wrong | p |
| --- | --- | --- | --- |
| rules | 2 | 1 | 1.000 |
| single_call | 5 | 0 | 0.062 |
| fixed_workflow | 0 | 0 | 1.000 |

## Tactic accuracy by true tactic

| True tactic | n | rules | single_call | fixed_workflow | agent |
| --- | --- | --- | --- | --- | --- |
| Command and Control | 3 | 1 | 2 | 2 | 2 |
| Credential Access | 3 | 2 | 3 | 3 | 3 |
| Defense Evasion | 3 | 0 | 0 | 0 | 0 |
| Discovery | 3 | 0 | 0 | 0 | 0 |
| Execution | 3 | 3 | 1 | 3 | 3 |
| Lateral Movement | 3 | 1 | 0 | 1 | 1 |
| Persistence | 3 | 2 | 0 | 1 | 1 |
| Privilege Escalation | 3 | 3 | 2 | 3 | 3 |
| Benign | 4 | 4 | 4 | 4 | 4 |

Model: `gpt-4o-mini` (openai, temperature 0, seed 0). Command: `/Users/amatyakatyayan/Downloads/soc-m2/.venv/bin/python run_eval.py --provider openai --dataset dev --systems agent --out outputs/m2_openai`
