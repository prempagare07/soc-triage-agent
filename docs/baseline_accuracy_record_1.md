# Baseline accuracy record

Recorded: 2026-11-04.

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
