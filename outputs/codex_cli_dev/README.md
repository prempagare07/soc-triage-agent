# Codex CLI runs on the 28 dev alerts

Prem's M1 prompt, one alert per call through Codex CLI (gpt-6.1-sol, extra-high reasoning,
subscription run, no temperature setting). Four runs on the same 28 dev alerts, Nov 4 2026:

| Run | Tactic | Verdict | Missed attacks |
| --- | --- | --- | --- |
| run1 | 17/28 | 24/28 | 4 |
| run2 | 14/28 | 22/28 | 6 |
| run3 | 15/28 | 23/28 | 5 |
| run4 | 15/28 | 23/28 | 5 |

`codex_cli_reference.py` is the wrapper that made these runs. It is a reference copy and is
not imported by the project (it needs the M1 branch's `soc/metrics.py` and `run_baseline.py`).
