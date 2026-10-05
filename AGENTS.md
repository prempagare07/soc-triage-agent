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
