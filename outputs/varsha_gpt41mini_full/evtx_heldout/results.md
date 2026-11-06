# Results: evtx_heldout

Alerts: 81

| Metric | single_call | agent_b4 |
| --- | --- | --- |
| Tactic accuracy (exact) | 31/81 (38.3%) | 31/81 (38.3%) |
| Tactic top-2 | 31/81 (38.3%) | 37/81 (45.7%) |
| Macro-F1 (tactics with n>=5) | 0.47 (6 tactics) | 0.47 (6 tactics) |
| Verdict accuracy | 53/81 (65.4%) | 55/81 (67.9%) |
| Missed attacks | 28 (H001, H002, H005, H007, H008, H017, H022, H023...) | 26 (H001, H002, H017, H022, H023, H026, H027, H028...) |
| Under-escalations (incl. misses) | 32 | 29 |
|   of which Credential Access / Lateral Movement | 14 | 9 |
| Action-level accuracy | 37/81 (45.7%) | 41/81 (50.6%) |
| Uncertain escalations | 0 | 4 |
| Parse failures | 0 | 0 |
| Tool calls (total) | 0 | 582 |
| Tool errors | 0 | 0 |
| Verifier failures / revisions | 0 / 0 | 6 / 4 |
| Budget exhausted | 0 | 0 |
| Claim-level evidence validity | n/a | 130/132 (98.5%) |
| Latency p50 / p95 (s per alert) | 1.5 / 1.9 | 4.5 / 6.8 |
| Tokens (total, uncached runs) | 143529 | 630103 |

Zero-miss 95% upper bound at 81 attacks: 3.6%

Tokens per alert relative to the single call: single_call 1.0x, agent_b4 4.4x

## Tactic accuracy by true tactic

| True tactic | n | single_call | agent_b4 |
| --- | --- | --- | --- |
| Command and Control | 1 | 0 | 0 |
| Credential Access | 13 | 9 | 9 |
| Defense Evasion | 14 | 3 | 2 |
| Discovery | 2 | 0 | 0 |
| Execution | 15 | 4 | 5 |
| Lateral Movement | 15 | 3 | 4 |
| Persistence | 6 | 3 | 3 |
| Privilege Escalation | 15 | 9 | 8 |

Model: `gpt-4.1-mini` (openai, temperature 0, seed not specified). Command: `python run_eval.py --dataset evtx_heldout --provider openai --model gpt-4.1-mini --systems single_call,agent --budget 4 --openai-cap-usd 1.50 --openai-spend-file outputs/varsha_gpt41mini_spend.json --openai-cache-dir outputs/varsha_gpt41mini_llm_cache --out outputs/varsha_gpt41mini_full`
