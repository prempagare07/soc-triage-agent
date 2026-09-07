"""Build examples/alerts.jsonl from the EVTX-ATTACK-SAMPLES repo (real attack logs).

Usage: python data/build_dataset.py --repo /path/to/EVTX-ATTACK-SAMPLES-master --per-tactic 3
Requires: python-evtx. Output is committed to examples/alerts.jsonl so the TA does NOT need
to run this step.
"""
import argparse, json, random, xml.etree.ElementTree as ET
from pathlib import Path
import Evtx.Evtx as evtx

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
TACTICS = ["Command and Control", "Credential Access", "Defense Evasion", "Discovery",
           "Execution", "Lateral Movement", "Persistence", "Privilege Escalation"]
KEEP_IDS = {"1", "3", "7", "8", "10", "11", "13", "4624", "4625", "4648", "4672", "4688", "4698",
            "4720", "4728", "4732", "5140", "5145", "7045", "4104", "4103"}
FIELDS = ["Image", "CommandLine", "ParentImage", "ParentCommandLine", "User", "TargetImage",
          "SourceImage", "GrantedAccess", "TargetObject", "Details", "DestinationIp", "DestinationPort",
          "NewProcessName", "SubjectUserName", "TargetUserName", "LogonType", "IpAddress",
          "ShareName", "RelativeTargetName", "ServiceName", "ImagePath", "TaskName", "ScriptBlockText",
          "ImageLoaded", "TargetFilename", "QueryName"]
NOISE = ("Sysmon.exe", "sysmon", "Sysmon64", "svchost.exe -k", "unsecapp.exe")


def parse(path: Path, max_events=20):
    events = []
    with evtx.Evtx(str(path)) as log:
        for rec in log.records():
            try:
                x = ET.fromstring(rec.xml())
            except Exception:
                continue
            eid = x.find(".//e:EventID", NS).text
            if eid not in KEEP_IDS:
                continue
            data = {d.get("Name"): (d.text or "") for d in x.findall(".//e:Data", NS)}
            ev = {"event_id": int(eid)}
            for f in FIELDS:
                if data.get(f) and data[f] not in ("-", ""):
                    ev[f] = data[f][:300]
            blob = json.dumps(ev)
            if len(ev) > 1 and not any(n in blob for n in NOISE):
                events.append(ev)
    return events[-max_events:]  # attack activity is usually at the end of the capture


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True)
    ap.add_argument("--per-tactic", type=int, default=3)
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()
    random.seed(args.seed)
    out, n = [], 1
    for tactic in TACTICS:
        files = sorted((Path(args.repo) / tactic).glob("*.evtx"))
        random.shuffle(files)
        picked = 0
        for f in files:
            evs = parse(f)
            if len(evs) < 3:
                continue
            out.append({"alert_id": f"A{n:03d}", "source_file": f.name, "host": "WIN-LAB",
                        "events": evs, "label_tactic": tactic, "label_verdict": "malicious"})
            n += 1; picked += 1
            if picked >= args.per_tactic:
                break
    Path("examples/alerts.jsonl").write_text("\n".join(json.dumps(a) for a in out) + "\n")
    print(f"wrote {len(out)} alerts")


if __name__ == "__main__":
    main()
