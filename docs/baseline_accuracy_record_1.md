# Baseline accuracy record

Current reporting terminology: **stakeholder baseline accuracy** refers to
the historical GPT-4o-mini figures below: verdict 27/28 (96.4%) and tactic
13/28 (46.4%). **Best observed Codex accuracy** refers separately to the
user-selected run in [record 2](baseline_accuracy_record_2.md): verdict
24/28 (85.7%) and tactic 17/28 (60.7%). These are distinct references, not
a verified paired comparison. The original historical measurement command
and prediction artifacts remain unavailable; see Historical API figures
below and [baseline_reference.json](baseline_reference.json). Record 2
contains the exact command and saved evidence for the Codex measurement.

Latest rerun status and stable evidence are in
[record 3](baseline_accuracy_record_3.md), including an overlapping run
that replaced shared output files. Earlier figures below are historical.

Historical status: the pending-Codex statements below are superseded by
[the completed xhigh baseline record](baseline_accuracy_record_2.md).
The fresh Codex run achieved 24/28 verdict accuracy (85.7%) and 17/28 tactic
accuracy (60.7%), using the exact commands recorded in that new note.

Recorded: 2026-11-04.

Current requested Codex configuration: **gpt-6.1-sol / xhigh**, explicitly
selected by the user for the new full run. Its fresh xhigh preflight was
blocked before inference by the app sandbox; full-run accuracy is pending.
The medium-effort smoke described below is historical, not the requested
configuration for the new run.

Rerun update: rules were freshly measured again on 2026-11-04 with the
same results below. Prior artifacts were preserved under
`outputs/history/20261104T213333948877Z/`. Codex preflight with CLI 0.166.0
failed before inference due to app-sandbox startup restrictions; no new
Codex model accuracy was measured. See [rerun status](baseline_rerun_2026-11-04.md).

| Baseline | Verdict accuracy | Tactic accuracy | Evidence status |
|---|---:|---:|---|
| Deterministic rules classifier (no LLM) | 82.1% (23/28) | 57.1% (16/28) | Measured development-set results; saved predictions and run metadata verified. |
| Original GPT-4o-mini API baseline | 96.4% (27/28) | 46.4% (13/28) | Historical figures supplied in the project instructions; original prediction files and producing command have not been independently verified here. |
| Stakeholder-approved Codex CLI classifier | Pending | Pending | No saved full-dataset run. Requested configuration for the successful single-alert smoke was gpt-6.1-sol, medium reasoning effort; actual resolved model was not exposed. |

The completed rules evaluation uses the development set, not a held-out
test set. Its denominator includes all 28 labelled alerts, including failed
classifications if present. These rules percentages must not be attributed
to Codex or gpt-6.1-sol. A single-alert smoke test does not establish
full-dataset accuracy or support a comparison between models.

## Rules provenance

Original measurement command (from the repository root):

```bash
python run_baseline.py --input examples/alerts.jsonl --mode rules
```

Saved evidence:

- [Predictions](../outputs/alerts_rules.jsonl)
- [Run metadata](../outputs/run_meta_alerts_rules.json)
- [Metrics report](../outputs/m1_rules_metrics.md)

Input SHA256: `f4fe76b73de02ad87be2b03023a4ca4c48d68f911d1edc192387d8672dd88672`.

Output SHA256: `9c38f6e2147a335f19d1868c032ea93b0a8d921ced11299c5ab11b1e496521e2`.

## Historical API figures

The user's baseline-reproduction instructions identified 27/28 verdict
and 13/28 tactic accuracy as historical original-API results, not Codex
targets. The displayed percentages are those fractions multiplied by 100,
rounded to one decimal place. Their arithmetic can be checked with:

```bash
python -c 'print(f"Historical verdict: {27/28:.1%}; historical tactic: {13/28:.1%}")'
```

This command verifies the percentage conversion only. The command that
produced the historical predictions is unavailable, so these figures
must retain the historical/unverified-provenance qualification.

The stakeholder's +15 percentage-point tactic-accuracy improvement goal is
a target for comparisons on the same held-out alerts, not a measured result.
