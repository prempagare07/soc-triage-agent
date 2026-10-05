# Prompt 1 baseline status

Boundary update: see `label_leakage_guard.md`. Direct rules/API entry points
now sanitize inputs, and the shared sanitizer rejects recognizable embedded
evaluation metadata. The rules baseline was refreshed with unchanged
predictions. Previous Codex smoke evidence has older code hashes; a fresh
terminal smoke and full Codex run are required before final baseline claims.
The completed-evidence narrative below describes the earlier Prompt 1 work.

Prepared change: **Reproduce rules and Codex baselines with metadata**.
Working branch: `feature/praveen/baseline_1`. No commit or push performed.

## Completed evidence

Dependencies were already installed by:

```bash
python -m pip install -r requirements.txt
```

The rules dev-set run was produced with:

```bash
python run_baseline.py --input examples/alerts.jsonl --mode rules
```

Saved evidence is in `outputs/alerts_rules.jsonl`,
`outputs/run_meta_alerts_rules.json`, `outputs/m1_rules_metrics.md`, and
`outputs/m1_metrics.md`. The combined report currently contains only rules.
Prior rules output was preserved under `outputs/history/` before replacement.
The policy, rules classification logic, original classification instructions,
and dev dataset were not changed.

The run has 28 labelled alerts: 24 attacks and four benign cases. Rules tactic
accuracy is 16/28 (57.1%), verdict accuracy is 23/28 (82.1%), and five attacks
are called benign. Seven successful predictions are under-escalated, including
two Lateral Movement alerts (A016 and A018); Credential Access has none.
There are no classifier execution failures in this rules run. Full per-tactic
results and both confusion matrices are in the generated report.

Verification command:

```bash
python -m pytest -q tests
```

The suite checks rules behavior, all-dev-alert input sanitization, mocked Codex
parsing/cache/error handling, output preservation, and comparison hash checks.
These mocked tests do not constitute measured Codex classifications.

## Successful terminal smoke test and app execution blocker

`codex --version` reports CLI 0.153.4, and `codex login status` confirms
ChatGPT authentication. The requested experiment model is `gpt-6.1-sol`, with
medium reasoning effort. The user's terminal smoke test now succeeded with
that explicit requested model and effort: one successful classification and
zero failures. Its input, output, and every recorded code hash were verified
against the current files. The actual resolved model is still unavailable
in the CLI events and is not inferred from the requested model identifier.

The smoke record classifies A006 as malicious / Credential Access / critical /
escalate_tier2, with evidence indices 2, 7 and 8. This is one smoke alert,
not a full-dataset accuracy result. Metadata retains two diagnostic items:
an under-development feature warning for skip_host_skill_discovery, and
Code Mode being unavailable because its host was disabled. Neither is a
tool execution; event types include agent_message and error, with no
rejected tool item types. The adapter fix preserves such diagnostics while
still rejecting actual tool events, fatal turns, and invalid classifications.

The original live command attempted inside the app sandbox was:

```bash
python run_baseline.py --input examples/single_alert.json --mode codex \
  --model gpt-6.1-sol --reasoning-effort medium --timeout 30 --no-cache \
  --output outputs/smoke/single_alert_codex.jsonl
```

It returned exit status 1 before inference because the sandbox blocked
initialization of the in-process app-server with `Operation not permitted`.
Earlier failures are archived under `outputs/smoke/history/`; the successful
terminal result is now in `outputs/smoke/`. A new app-side check also failed
before inference and is recorded separately in `outputs/sandbox-check/`,
preserving the successful terminal smoke evidence. The full 28-alert Codex
run still needs to execute from an ordinary terminal because the current
app sandbox cannot initialize the CLI. A startup failure is neither a
measured wrong verdict nor a completed full-dataset run.

Missing full-run artifacts: `outputs/alerts_codex.jsonl`,
`outputs/run_meta_alerts_codex.json`, `outputs/m1_codex_metrics.md`, and
`outputs/m1_per_alert.csv`. They must come from a real run; no placeholders
or fabricated model outputs have been created.

## Continue in an ordinary terminal

```bash
cd "/Users/praveen/Desktop/1st Sem/CSE 598 Agentic AI/Capstone/soc-triage-agent"
source .venv/bin/activate
codex login status
python run_baseline.py --input examples/single_alert.json --mode codex \
  --model gpt-6.1-sol --reasoning-effort medium --timeout 180 --no-cache \
  --output outputs/smoke/single_alert_codex.jsonl
```

The terminal smoke command has already succeeded and does not need repeating.
Run the full baseline next:

```bash
python run_baseline.py --input examples/alerts.jsonl --mode codex \
  --model gpt-6.1-sol --reasoning-effort medium --timeout 180
python -m pytest -q tests
```

The full command will generate Codex records and metadata, add the Codex report
to `m1_metrics.md`, and produce the comparison CSV if the saved rules input and
output hashes match. Every failed alert remains in the accuracy denominator.
Do not interpret zero successful verdict misses as safety success when there
are failed classifications. Choose a different model only if access fails and
the new explicit selection is recorded and held fixed for the experiment.

## Isolation and reproducibility limits

The adapter supplies host and indexed events in stdin and uses the original
classification instructions in a temporary directory without labelled files.
It requests disabled shell, web, apps, MCP, plugins, skills discovery,
delegation, hooks, memories and project instructions, and ignores user config
and execution-policy rules. It rejects unexpected tool events. Supported CLI
flags were checked using `codex exec --help`; the successful terminal smoke
showed no tool activity. This observation does not prove that every possible
capability or runtime instruction has been excluded. Codex may still
supply runtime instructions and context; do not claim equivalence to a bare
API call or prove perfect isolation using a read-only sandbox alone.

Run metadata records code/input/output hashes, exact CLI arguments with
temporary paths normalized, requested model/effort, failures, cache hits,
raw successful responses, and exposed usage. Missing usage is null; aggregate
token counts do not conceal missing failed-attempt usage. Cache hits do not
count as fresh inference. No API dollar cost or exact subscription-credit
charge is inferred. Actual model, effective effort and unsupported sampling
fields remain null unless the CLI exposes them reliably.
