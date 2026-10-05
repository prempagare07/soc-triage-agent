# SOC Alert-Triage Agent — Capstone Baseline

**CSE 598 Agentic AI (Fall 2026) · Prem · Individual proposal baseline**

Given a Windows endpoint alert (a bundle of Sysmon / Security log events), the system produces a
tier-1 SOC triage record: `verdict` (malicious/benign), MITRE ATT&CK `tactic`, `severity`,
recommended `action`, the `evidence` event indices, and a short `analyst_note`.

The alerts are **real attack telemetry** from the public
[EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) corpus (24 captures,
3 per tactic across 8 ATT&CK tactics, labeled by the corpus author), plus 4 clearly-marked
synthetic benign alerts (`B001`–`B004`) so that the verdict is testable.

| Mode    | What it is                                              | Needs API key |
|---------|---------------------------------------------------------|---------------|
| `rules` | indicator/keyword matcher over the events (floor)       | No            |
| `codex` | isolated classification using Codex CLI and ChatGPT login | No          |
| `llm`   | single-call `gpt-4o-mini`, JSON output, evidence cited  | Yes           |

## 1. Setup

```bash
git clone https://github.com/prempagare07/soc-triage-agent && cd soc-triage-agent
python3 -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```
Python 3.10+. `python-evtx` is only needed to rebuild the dataset; the built dataset is committed.

## 2. Keys / environment
Only `--mode llm` needs `OPENAI_API_KEY` (`export OPENAI_API_KEY=sk-...` or copy `.env.example`).
Install its optional dependency with `python -m pip install -r requirements-openai.txt`.
For Codex, install the Codex CLI and run `codex login` with your ChatGPT account.
The adapter forces ChatGPT authentication and consumes your subscription allowance.

## 3. Run
```bash
python run_baseline.py --input examples/alerts.jsonl --mode rules    # no key, <1 s
python run_baseline.py --input examples/alerts.jsonl --mode codex --model gpt-6.1-sol --reasoning-effort medium
python run_baseline.py --input examples/alerts.jsonl --mode llm      # ~28 API calls, ~$0.03
python run_baseline.py --input examples/single_alert.json --mode rules
python -m pytest -q tests
```

Choose a model available to your Codex account. Codex mode requires an explicit
`--model`; the example is not an entitlement check. Use `--timeout 180` to set the
per-alert timeout, or `--no-cache` for fresh calls. Successful responses are cached
in `outputs/codex_cache/` by request, configuration, CLI version, and adapter hash.
Each alert starts a fresh isolated session with shell, web search, apps, plugins,
and agent delegation disabled. User config and project instructions are excluded;
tool activity in CLI events causes rejection. This is a controlled CLI baseline,
not the original GPT-4o-mini API experiment. Codex still supplies its own runtime
context, so the two execution environments are not identical.

Rules and Codex runs write `run_meta_<input>_<mode>.json`, per-mode metrics,
and `m1_metrics.md` alongside the output. When both default-named output files
exist in the same directory, they also write `m1_per_alert.csv`. Run both against
the same input and keep the saved runs together. Failures count as incorrect in
accuracy denominators, are recorded explicitly, and produce exit status 1.
Metadata includes versions, hashes, configuration, per-alert usage and cache hits.
Token totals exclude cache hits and remain null when events lack usage fields.
API dollar cost, resolved model and unsupported sampling fields are null for Codex.
Inspect records before citing results; subscription allowance is not API billing.
Existing output files and reports are copied into `outputs/history/<UTC timestamp>/`
before replacement. Raw successful Codex JSON is retained in per-alert metadata
even with `--no-cache`. Input and output hashes gate combined reports and CSVs.
See `docs/m1_baseline_status.md` for the live-run status and terminal commands.

## 4. Input / output
- **Input:** `examples/alerts.jsonl` — one alert per line: `alert_id`, `source_file`, `host`,
  `events[]` (each with `event_id` and the key Sysmon/Security fields), `label_tactic`, `label_verdict`.
  `examples/single_alert.json` is one alert (a Meterpreter hashdump capture).
- **Output:** `outputs/<input>_<mode>.jsonl`, one triage record per alert, plus a console line per
  alert and summary metrics: tactic accuracy, verdict accuracy, and **missed attacks** (attacks the
  system called benign — the safety-critical number).
- Committed sample run: `outputs/alerts_rules.jsonl`, `outputs/run_log_rules.txt`.

## 5. Output schema
```json
{"alert_id": "A006", "verdict": "malicious", "tactic": "Credential Access", "severity": "critical",
 "action": "escalate_tier2", "evidence": [3, 5], "analyst_note": "...",
 "label_tactic": "Credential Access", "label_verdict": "malicious", "tactic_correct": true, "verdict_correct": true}
```
Severity and action are derived from tactic by a fixed policy in `soc/schema.py`.

## 6. Rebuilding the dataset (optional)
```bash
git clone https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES
python data/build_dataset.py --repo EVTX-ATTACK-SAMPLES --per-tactic 3
```

## 7. Layout
```
run_baseline.py        CLI
soc/schema.py          tactics, severity/action policy, validation
soc/rules.py           indicator baseline (offline)
soc/llm.py             single-call OpenAI baseline
data/build_dataset.py  EVTX -> JSONL converter
examples/              inputs   ·  outputs/  results  ·  tests/  pytest
```

## 8. Known limitations
Rule baseline: 57% tactic accuracy and 5 missed attacks on the 28-alert set, Discovery tooling
(BloodHound, PsLoggedOn) and PowerShell-based lateral movement produce no keyword hits.
Both baselines see only the events in the alert; no host context, no threat-intel lookup, no
ability to pull more logs, and the note is not verified against the cited evidence.
