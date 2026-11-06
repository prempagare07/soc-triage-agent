# Run provenance (outputs/m2_openai, outputs/m2_v22)

The Nov 4 evaluation runs were made from our working copy before the first M2 commit existed.
So `git_commit` in their `run_meta.json` files shows `f7e443c` (Prem's main, the base we
started from), not the code that ran. The code that ran is the M2 code now on main: we checked
it file by file (sha256), and the only differences are that `soc/gemini_llm.py` was removed
(unused by the OpenAI path) and helper scripts were added after the runs finished.

Runs made after the merge record the real commit and file hashes in `run_meta.json`
(`code_sha256`).

To check a result, run from a clean clone of main:

    python run_eval.py --dataset evtx_heldout --provider openai --systems single_call,fixed_workflow,agent

Even at temperature 0, gpt-4o-mini drifts between runs (about 1 to 2 alerts of tactic), so
re-runs will not match to the last alert.

A second-model run (gpt-4.1-mini, 81 held-out alerts) is summarised in
`outputs/varsha_gpt41mini_full/`.
