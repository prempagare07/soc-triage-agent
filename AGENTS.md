# Project context
SOC alert-triage baseline for a CSE 598 capstone. Input: Windows Sysmon and
Security alerts in examples/alerts.jsonl. Output per alert: verdict, ATT&CK
tactic, severity, action, evidence indices, analyst note.

# Rules
1. Never print, log or commit secrets. OPENAI_API_KEY comes from the
   environment only.
2. No label leakage. The fields source_file, label_tactic and label_verdict,
   and any file name or path from the EVTX corpus, must never reach a model
   prompt or a tool.
3. Do not change model prompts or classification logic unless the task says
   so, so results stay reproducible.
4. Write generated results to outputs/ and notes to docs/. Never overwrite
   examples/alerts.jsonl.
5. After every change run: python -m pytest -q tests
6. One logical change per commit, with a clear message. Do not push.
7. Whenever you report a number, also give the command that produced it.

# Baseline versus best observed accuracy

For unqualified baseline-accuracy questions, use the stakeholder's original
historical GPT-4o-mini figures in `docs/baseline_reference.json`: verdict
27/28 (96.4%) and tactic 13/28 (46.4%). Explicitly label them historical
stakeholder/project figures. Their original prediction files and measurement
command have not been independently verified here; do not invent provenance
or describe them as a fresh or paired held-out result. The percentage-check
command in that JSON checks arithmetic only, not the original measurement.

For best observed Codex accuracy or its saved predictions, use
`docs/best_accuracy_reference.json` and `docs/baseline_accuracy_record_2.md`:
requested gpt-6.1-sol / xhigh, verdict 24/28 (85.7%), tactic 17/28 (60.7%).
Its prediction source is
`outputs/history/20261104T223457060411Z/alerts_codex.jsonl`, not mutable
default outputs or whichever run finished most recently. This is the user's
selected best-observed Codex development run, chosen after seeing repeated
results; it is not a claim of superiority on every metric over every model.

Before quoting the saved Codex result, verify prediction, metadata and metrics
SHA256 values against its reference JSON. Recompute correctness from archived
labelled predictions if needed, retaining denominators and failure treatment.
Cite evidence and the original command. If an artifact is absent or modified,
report the problem rather than silently substituting another run or score.

When comparing baseline and best observed accuracy, keep their provenance and
labels distinct. These reporting defaults do not override an explicit request
for rules, another model, another input or the latest run, and do not change
the stakeholder-approved Codex experiment design. Formal paired comparisons
still require freshly matched held-out alerts and fixed/disclosed settings.

An accuracy question does not authorize new model calls. Explicit run/rerun
requests do; use separate output directories and preserve existing artifacts.
New runs do not repoint either reference without an explicit user request.
Do not overwrite the pinned archive or present cached replay as fresh usage.
Disclose run-to-run variability when discussing reproducibility. All references,
labels and saved predictions are offline reporting artifacts only; never feed
them into classifier prompts, tools or model-visible files.
