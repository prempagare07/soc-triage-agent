"""Indicator-based rule baseline. No API key. Floor the LLM/agent must beat."""
import json
from .schema import finalize

INDICATORS = {
    "Credential Access": ["lsass", "sekurlsa", "mimikatz", "hashdump", "samlib", "ntds.dit", "0x1010", "0x1fffff", "logonpasswords", "zerologon", "anonymous logon"],
    "Lateral Movement": ["psexec", "wmic /node", "admin$", "\\c$", "winrm", "schtasks /s ", "powercat", "logontype\": \"3", "pass the hash", "sekurlsa::pth", "-w hidden -e"],
    "Command and Control": ["3389", "tunnel", "plink", "ngrok", "chisel", "tunna", "reverse", "-l 4444", "beacon", "rdp"],
    "Privilege Escalation": ["fodhelper", "eventvwr", "sdclt", "uacme", "computerdefaults", "cmstp", "slui", "wsreset", "highest", "\\ms-settings", "bypassuac"],
    "Persistence": ["\\currentversion\\run", "schtasks /create", "startup", "new-service", "sc create", "7045", "winlogon", "appcompat", "shim", "sdb", "comhijack", "inprocserver32", "rid", "userinit"],
    "Defense Evasion": ["wevtutil", "clear-eventlog", "eventlog", "disablerealtimemonitoring", "fdenytsconnections", "amsi", "dllhijack", "renamed", "timestomp", "userauthentication", "rdp-tcp"],
    "Discovery": ["whoami", "net user", "net group", "nltest", "bloodhound", "sharphound", "psloggedon", "userhunter", "adfind", "ldap", "net view", "systeminfo", "qwinsta"],
    "Execution": ["rundll32", "regsvr32", "mshta", "wscript", "cscript", "powershell -", "-enc", "pcalua", "vshadow", "msbuild", "installutil", "lolbin", "certutil"],
}


def classify(alert: dict) -> dict:
    scores, hits = {}, {}
    for i, ev in enumerate(alert["events"]):
        blob = json.dumps(ev).lower()
        for tactic, kws in INDICATORS.items():
            for kw in kws:
                if kw in blob:
                    scores[tactic] = scores.get(tactic, 0) + 1
                    hits.setdefault(tactic, []).append((i, kw))
    if not scores:
        return finalize(alert["alert_id"], "benign", "Benign", [], "No known attack indicators matched; rule baseline defaults to benign.")
    best = max(scores, key=scores.get)
    ev_idx = sorted({i for i, _ in hits[best]})
    kws = sorted({kw for _, kw in hits[best]})
    return finalize(alert["alert_id"], "malicious", best, ev_idx,
                    f"Rule match for {best}: indicators {kws} in events {ev_idx}.")
