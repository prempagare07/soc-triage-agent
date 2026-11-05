# Evidence check (two judges)

25 claims sampled at random (seed 20261104) from the 109 claims in the agent's final, verified drafts
on the EVTX held-out set (gpt-4o-mini run in outputs/m2_openai/evtx_heldout). Fill in your own sheet without
looking at the other judge's answers.

For each row, read the claim and the cited events and mark `relevant`:
- **yes**: the cited events support the claim.
- **partly**: they support part of it, or only weakly.
- **no**: they do not support it.

Add a short note when you mark partly or no. When both sheets are done, run
`python scripts/agreement.py` to get the agreement rate and Cohen's kappa for the report.
