# Reliability and evaluation improvements

Work performed on `m2/praveen/agents`. This is a reliability pass, not a claim
of increased model accuracy. Existing classification instructions, tactic
policy and datasets were preserved. No commit, push or live model call was
made.

## Changes

- `run_eval.py`: validates systems/limits before model initialization; rules
  mode is fully offline; records actual provider options, selected-input and
  context/manifest/code fingerprints and prediction hashes. Only compatible
  saved systems enter a comparison. Interrupted runs do not leave an older
  report looking current.
- `soc/run_artifacts.py`: exclusive output-directory lock, archive preservation,
  per-system metadata and hash-checked compatible-result loading. Old traces
  move into the archive so partial runs do not expose old traces as current.
- `soc/agent.py`: when no usable submission exists, retains the operational
  fail-safe verdict/action but adds explicit failed status and an explanation.
- `soc/eval_metrics.py`: missing/failed/parse-failure classifications count as
  incorrect, independently of coincidentally correct fallback labels. Failures
  are distinguished from verdict misses/under-escalations; zero-miss bounds
  require zero observed misses and no failed attack classifications. Token
  reporting no longer falsely claims cached usage is fresh. Unequal rater
  lengths are rejected instead of producing invalid agreement statistics.
- `tests/test_m2_run_integrity.py`: regression tests for provenance mismatches,
  modified results, locks, archives, interrupted runs, offline rules execution,
  truthful seed reporting and failure denominators.

## Verification

Initial suite: 49 tests passed. Final suite: 69 tests passed, using:

```bash
.venv/bin/python -m pytest -q tests
git diff --check
git diff --stat
```

The tests use scripted model responses and mock interruptions. They are not
measurements of Ollama, OpenAI, Gemini or agent accuracy on a live model.

An actual full dev-set rules-only smoke was run without a model service:

```bash
.venv/bin/python run_eval.py --dataset dev --systems rules --out outputs/m2_integrity_smoke
```

It retained the expected results on all 28 dev alerts: 23/28 verdict accuracy
(82.1%), 16/28 tactic accuracy (57.1%), and zero execution failures out of 28.
The output is separate from previously committed measurements:
`outputs/m2_integrity_smoke/dev/results.md`, with predictions and metadata
alongside it. Its recorded input/context/code and prediction hashes were
checked against the actual files.

## Limits

Historic model predictions and their reports were not regenerated. Old files
without new provenance sidecars are excluded rather than treated as compatible.
An interrupted system may need to be restarted; completed model calls can
still be served by the existing response cache. Cache billing and backend
model snapshot guarantees are not introduced by this change. A killed process
can leave a lock requiring manual review. Full model-based integration and
any effect on model/agent accuracy remain unmeasured.
