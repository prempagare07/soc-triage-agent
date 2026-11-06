#!/usr/bin/env python3
"""Print one agent run step by step.

  python scripts/show_trace.py outputs/m2/dev/traces/A014.json
"""
import json, sys, textwrap

trace = json.load(open(sys.argv[1]))
first = json.loads(trace["messages"][1]["content"])
print(f"=== Alert {trace['alert_id']} on {first['host']}: {len(first['events'])} events ===")
for ev in first["events"]:
    fields = {k: v for k, v in ev.items() if k not in ("index", "TimeCreated")}
    print(textwrap.shorten(f"  [{ev['index']}] {json.dumps(fields)}", 150))
for hit in first.get("rule_hits", []):
    print(f"rule hit: {hit['tactic']} {hit['indicators']} in events {hit['events']}")
steps = trace["trace"]
enrich = [s for s in steps if s["step"] == "enrich"]
if enrich:
    print(f"\n--- standard enrichment: {len(enrich)} tool calls ---")
    for s in enrich:
        print(textwrap.shorten(f"  {s['action']}({json.dumps(s['args'])}) -> {json.dumps(s['observation'].get('result', s['observation']))}", 160))
for n, step in enumerate([s for s in steps if s["step"] != "enrich"], 1):
    print(f"\n--- step {n}: {step['step']} ---")
    if step.get("thought"):
        print(f"thought: {step['thought']}")
    if step["step"] == "first_pass":
        a = step["assessment"]
        print(f"quick decision: {a['verdict']} / {a['tactics']}")
        print(textwrap.shorten(f"note: {a.get('note', '')}", 200))
    elif step["step"] == "tool":
        print(f"call:    {step['action']}({json.dumps(step['args'])})")
        print(textwrap.indent(textwrap.shorten(json.dumps(step["observation"]), 600), "result:  "))
    elif step["step"] == "submit":
        d = step["draft"]
        print(f"draft:   {d['verdict']} / {d['tactics']} / evidence {d['evidence']} / uncertain={d['uncertain']}")
        for c in d["claims"]:
            print(textwrap.shorten(f"claim:   {c.get('text')} <- {c.get('evidence')} quotes={c.get('quotes')}", 200))
        print("verifier: PASS" if not step["verifier_errors"] else "verifier: FAIL\n  - " + "\n  - ".join(step["verifier_errors"]))
    else:
        print(textwrap.shorten(json.dumps(step), 300))
