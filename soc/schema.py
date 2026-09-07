"""Label set, severity policy, and output validation for SOC triage."""

TACTICS = ["Command and Control", "Credential Access", "Defense Evasion", "Discovery",
           "Execution", "Lateral Movement", "Persistence", "Privilege Escalation", "Benign"]

SEVERITY = {
    "Credential Access": "critical", "Lateral Movement": "critical", "Command and Control": "high",
    "Privilege Escalation": "high", "Persistence": "high", "Defense Evasion": "medium",
    "Execution": "medium", "Discovery": "low", "Benign": "info",
}
ACTION = {"critical": "escalate_tier2", "high": "escalate_tier2", "medium": "investigate",
          "low": "monitor", "info": "close"}

OUTPUT_KEYS = ["alert_id", "verdict", "tactic", "severity", "action", "evidence", "analyst_note"]


def finalize(alert_id: str, verdict: str, tactic: str, evidence: list, note: str) -> dict:
    if tactic not in TACTICS:
        tactic = "Benign" if verdict == "benign" else "Execution"
    if verdict == "benign":
        tactic = "Benign"
    sev = SEVERITY[tactic]
    return {"alert_id": alert_id, "verdict": verdict, "tactic": tactic, "severity": sev,
            "action": ACTION[sev], "evidence": evidence, "analyst_note": note}


def validate(rec: dict) -> None:
    missing = [k for k in OUTPUT_KEYS if k not in rec]
    if missing:
        raise ValueError(f"missing keys: {missing}")
    if rec["verdict"] not in {"malicious", "benign"}:
        raise ValueError(f"bad verdict {rec['verdict']}")
    if rec["tactic"] not in TACTICS:
        raise ValueError(f"bad tactic {rec['tactic']}")
    if not isinstance(rec["evidence"], list):
        raise ValueError("evidence must be a list of event indices")
