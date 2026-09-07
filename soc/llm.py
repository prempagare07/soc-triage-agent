"""Single-call LLM baseline: alert events -> triage JSON."""
import json, os
from .schema import TACTICS, finalize

SYSTEM = f"""You are a tier-1 SOC analyst triaging a Windows endpoint alert.
You receive a list of Sysmon/Security log events (index, event_id, key fields).
Decide:
- verdict: "malicious" or "benign"
- tactic: one of {json.dumps(TACTICS)}  (use "Benign" only when verdict is benign)
- evidence: list of event indices that justify the verdict (cite only events that exist)
- analyst_note: 2-3 sentences explaining what happened, referencing the evidence indices.
Be conservative: ordinary signed software doing normal things is benign; LOLBins with odd
parents, LSASS access, UAC bypass binaries, tunnels, or remote admin tooling are malicious.
Respond ONLY with a JSON object with keys verdict, tactic, evidence, analyst_note."""


def classify(alert: dict, model: str = "gpt-4o-mini") -> dict:
    from openai import OpenAI
    client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
    events = [{"index": i, **ev} for i, ev in enumerate(alert["events"])]
    resp = client.chat.completions.create(
        model=model, temperature=0, response_format={"type": "json_object"},
        messages=[{"role": "system", "content": SYSTEM},
                  {"role": "user", "content": json.dumps({"host": alert["host"], "events": events})}])
    d = json.loads(resp.choices[0].message.content)
    n = len(alert["events"])
    evidence = [int(i) for i in d.get("evidence", []) if isinstance(i, (int, str)) and str(i).isdigit() and int(i) < n]
    return finalize(alert["alert_id"], d.get("verdict", "malicious"), d.get("tactic", "Execution"),
                    evidence, d.get("analyst_note", ""))
