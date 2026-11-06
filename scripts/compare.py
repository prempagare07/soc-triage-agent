#!/usr/bin/env python3
"""Show what each system decided on one alert, next to the label.

  python scripts/compare.py outputs/m2_openai/evtx_heldout H053 [--brief]
"""
import json, sys
from pathlib import Path

folder, alert_id = Path(sys.argv[1]), sys.argv[2]
brief = "--brief" in sys.argv
for name in ("rules", "single_call", "fixed_workflow", "agent"):
    path = folder / f"{name}.jsonl"
    if not path.exists():
        continue
    rec = next((json.loads(l) for l in path.open() if json.loads(l)["alert_id"] == alert_id), None)
    if rec is None:
        sys.exit(f"{alert_id} is not in {path}")
    ranked = " > ".join(rec.get("tactics") or [rec["tactic"]])
    extra = f"  claims {rec['claims_valid']}/{rec['claims_total']} verified" if "claims_total" in rec else ""
    print(f"{name:<15} {rec['verdict']:<9} {ranked:<38} {rec['severity']:<8} {rec['action']}{extra}")
    if not brief:
        print(f"{'':<15} note: {rec['analyst_note'][:300]}")
