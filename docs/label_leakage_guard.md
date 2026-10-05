# Codex label-leakage guard

Prepared logical change: `Add Codex label-leakage guard and tests`.
Branch: `feature/praveen/baseline_1`. No commit or push performed.

`strip_alert()` makes a deep copy containing exactly `alert_id`, `host`, and
`events`. The runner and direct Codex, rules, and optional API entry points
use it. Nested event content, host, and alert ID are checked for evaluation
metadata keys, the corpus directory marker, and the supplied source path,
filename, and filename stem, case-insensitively. Recognizable embedded
metadata causes a rejection before classification; event fields and order
are not rewritten. Errors do not echo the offending content.

This is a guard against recognizable metadata, not a universal detector of
semantic ground truth. An arbitrary renamed label or an unknown corpus
filename without source metadata may escape detection. Offline dataset
review remains necessary. Ordinary endpoint executable/document paths are
valid evidence and remain intact. All committed dev alerts pass the guard.

## Verification

```bash
source .venv/bin/activate
python -m pytest -q tests
```

Result: 95 tests passed. Tests capture the Codex stdin, command, fixed
instructions, schema, and every initial scratch file for every dev alert.
They verify separate temporary working directories, context-discovery
exclusions, disabled capability arguments, original event indices, and
independence from labelled offline cache files. Existing adapter tests reject
shell, MCP, web, file-change, delegation, and unknown tool item activity.
The optional OpenAI SDK/request is mocked with a dummy environment value;
no real API key, installed SDK, or API call is needed by the test suite.
Labels remain available to offline scoring and are not classifier inputs.

Tests confirm identical direct rules outputs with and without labels, and
match the saved measured rules predictions. The fresh rules run used:

```bash
python run_baseline.py --input examples/alerts.jsonl --mode rules
```

Observed tactic accuracy: 16/28; verdict accuracy: 23/28; failures: 0/28.
Its outputs and metadata were refreshed; earlier results were preserved in
`outputs/history/20261004T234408513537Z/`.

`codex --version`, `codex exec --help`, and `codex features list` were also
inspected. The installed CLI reports `codex-cli 0.153.4`; help exposes the
context-exclusion flags and repeated configuration/disable arguments.
The feature listing alone does not demonstrate effective per-run settings.

## Cache invalidation and live verification

The fixed classification instructions, schema, and dev event payloads remain
unchanged. Sanitizer and optional LLM wrapper code changed. Both are included
in the Codex complete-request code hashes, so old cache keys cannot match
the new requests. A regression test confirms a changed sanitizer hash
causes a fresh request. Previous cached responses and measured artifacts
are preserved as historical evidence rather than deleted.

The previous successful terminal smoke used older code hashes. It cannot
verify the new boundary live. The app-side startup restriction documented
in `m1_baseline_status.md` remains unresolved; no additional nested model
run was attempted here. Run this fresh smoke in an ordinary terminal:

```bash
cd "/Users/praveen/Desktop/1st Sem/CSE 598 Agentic AI/Capstone/soc-triage-agent"
source .venv/bin/activate
python run_baseline.py --input examples/single_alert.json --mode codex \
  --model gpt-6.1-sol --reasoning-effort medium --timeout 180 --no-cache \
  --output outputs/smoke/single_alert_codex.jsonl
```

After successful smoke, rerun Prompt 1's full Codex baseline:

```bash
python run_baseline.py --input examples/alerts.jsonl --mode codex \
  --model gpt-6.1-sol --reasoning-effort medium --timeout 180 --no-cache
```

Mocked tests verify the constructed boundary. Live CLI isolation still needs
inspection of the new smoke's metadata and observed tool events. User or
repository context discovery, runtime-injected context, external settings,
and all capability exclusions cannot be proved solely by the mocked tests.
Read-only sandboxing alone does not prevent read access or prove isolation.
Do not cite a final Codex baseline until the new measured run is available.
