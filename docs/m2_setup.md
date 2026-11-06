# Milestone 2: how to set up and run

You can run everything for free on a local model. gpt-4o-mini, the model Prem's Milestone 1 baseline
used, is optional and costs about $1 for the whole evaluation, with a hard $3 cap built into the code.

## 1. Setup

```bash
git clone https://github.com/prempagare07/soc-triage-agent && cd soc-triage-agent
python3 -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python -m pytest -q tests
```

**Free local model.** Install Ollama from ollama.com (or `brew install ollama` on a Mac), start it, then:

```bash
ollama pull qwen2.5:7b        # about 4.7 GB; needs 16 GB of RAM to run comfortably
```

**gpt-4o-mini (optional).** Put your own key in `.env`, which git ignores. Never commit it or paste it anywhere:

```bash
echo 'OPENAI_API_KEY=your-key' >> .env
```

Every paid call is added to `outputs/openai_spend.json`, and a run stops before the total passes $3.
Cached answers are free, so rerunning a command never pays twice.

## 2. Run the comparison

Each command runs four systems on the same alerts: the rules baseline, the single-call baseline,
the fixed-workflow baseline and the agent. The model-based systems all use the same model and settings.

```bash
python run_eval.py --dataset dev --limit 3                        # quick check that the model answers
python run_eval.py --dataset dev                                  # 28 dev alerts (tuning only)
python run_eval.py --dataset evtx_val                             # 23 validation alerts (tuning only)
python run_eval.py --dataset evtx_heldout                         # 81 held-out EVTX attacks
python run_eval.py --dataset otrf_pilot                           # 55 OTRF Security-Datasets attacks
python run_eval.py --dataset benign                               # 44 benign alerts (false positives)
python run_eval.py --dataset benign_fresh                         # 20 more benign alerts, built later
python run_eval.py --provider openai --dataset dev --out outputs/m2_openai   # same, on gpt-4o-mini
```

Results land in `outputs/m2/<dataset>/` (or the `--out` folder): one JSONL per system, `results.md`
with the comparison table, `run_meta.json` with the exact command and settings, and one trace per alert
in `traces/`. Model replies are cached in `outputs/llm_cache/`, so a stopped run picks up where it left off.

Add `--verbose` to watch each agent step live. The agent can only *propose* the mocked `isolate_host`;
evaluation runs auto-deny it and log the decision in `approvals.jsonl`. For the live demo, add
`--interactive` and a person approves or denies it.

To read one agent run step by step (what we used for the report screenshots):

```bash
python scripts/show_trace.py outputs/m2_openai/evtx_heldout/traces/H006.json
```

## 3. Checking the baseline is reproduced

### Output integrity and offline checks

The runner now locks each dataset output directory against concurrent writes
and archives previous files/traces under `<out>/<dataset>/history/` before a
new run. Use a different `--out` for simultaneous runs. If a process is killed
without cleanup, its `.run.lock` may remain; confirm the original process has
stopped before manually removing that exact lock file.

Saved systems are included in a comparison only when their per-system
`*.meta.json` sidecars match the selected input, context, manifest, model,
provider/options, base URL, tool budget, interaction mode and local code/
knowledge hashes, and the prediction bytes match their recorded SHA256.
Legacy results without these sidecars remain preserved but are excluded
from new combined reports. Use separate folders for different budgets/models.
This checks recorded local settings; it does not prove an unchanged remote
model snapshot or make model generation deterministic.

Rules-only checks do not initialize Ollama or require a hosted-model key:

```bash
python run_eval.py --dataset dev --systems rules --out outputs/m2_integrity_smoke
```

Parse failures, explicit failures and missing predictions count as incorrect
in all-alert accuracy. Failures are listed separately from completed benign
predictions or under-escalations. A safe fallback action is not a successful
classification. Zero-miss bounds are shown only if no tested attacks were
missed and none failed classification. The report shows actual recorded
model options rather than assuming all providers use a seed. Reported token
totals may include cached-call usage; they are not fresh-usage or billing
measurements. Existing historical reports have not been rewritten.

Our single-call baseline sends exactly Prem's prompt and settings. To confirm on your machine, run his
original script next to ours on the same model and compare the two outputs alert by alert:

```bash
python run_baseline.py --input examples/alerts.jsonl --mode llm --output outputs/prem_check.jsonl   # needs OPENAI_API_KEY
python run_eval.py --provider openai --dataset dev --systems single_call --out outputs/m2_check
```

On Nov 4, 2026 both gave the same verdict and tactic on all 28 dev alerts (12/28 tactic, 26/28 verdict).
With qwen2.5:7b (`OPENAI_BASE_URL=http://localhost:11434/v1 OPENAI_API_KEY=ollama ... --model qwen2.5:7b`)
they also matched on all 28.

## 4. Rebuilding the datasets (optional)

The built sets are committed in `data/eval/`, so this is only needed to check them.

```bash
git clone --depth 1 https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES ../EVTX-ATTACK-SAMPLES
git clone --depth 1 --filter=blob:none --sparse https://github.com/OTRF/Security-Datasets ../Security-Datasets
(cd ../Security-Datasets && git sparse-checkout set datasets/atomic/_metadata \
   datasets/atomic/windows/{credential_access,defense_evasion,discovery,execution,lateral_movement,persistence,privilege_escalation}/host)
python data/build_eval_sets.py --evtx-repo ../EVTX-ATTACK-SAMPLES --otrf-repo ../Security-Datasets
python data/build_benign_set.py
python data/build_attack_index.py --stix enterprise-attack-18.1.json   # from mitre-attack/attack-stix-data
```

## 5. Rules we follow

- Tune only on dev and `evtx_val`. Held-out, OTRF and both benign sets are run once the design is frozen.
- Labels and source file names never reach a model or a tool (`soc/sanitize.py`, `soc/tools.py`).
- Report every number with the command that produced it (`run_meta.json` keeps it).
- Keys live only in `.env`; the code reads them locally and never logs them.
