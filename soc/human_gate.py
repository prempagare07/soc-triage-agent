"""Human approval for the mocked isolate_host. Eval runs auto-deny; every decision is logged."""
import json
from datetime import datetime, timezone
from pathlib import Path


class HumanGate:
    def __init__(self, interactive=False, log_path="outputs/approvals.jsonl"):
        self.interactive, self.log_path = interactive, Path(log_path)

    def review(self, record):
        if not record.get("propose_isolate_host"):
            return None
        if self.interactive:
            print(f"\nAgent proposes isolate_host({record['host']}) for {record['alert_id']}: "
                  f"{record['verdict']} / {record['tactic']} / {record['action']}")
            print(f"Note: {record['analyst_note'][:300]}")
            approved = input("Approve isolation? [y/N] ").strip().lower() == "y"
            mode = "interactive"
        else:
            approved, mode = False, "non-interactive (auto-deny)"
        decision = {"time": datetime.now(timezone.utc).isoformat(), "alert_id": record["alert_id"],
                    "host": record["host"], "action": "isolate_host", "approved": approved, "mode": mode,
                    "result": "mock: host isolated" if approved else "not isolated"}
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.log_path.open("a") as f:
            f.write(json.dumps(decision) + "\n")
        return decision
