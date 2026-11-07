"""Build the M2 eval sets (EVTX held-out, OTRF pilot) and the context the tools read.

  python data/build_eval_sets.py --evtx-repo ../EVTX-ATTACK-SAMPLES --otrf-repo ../Security-Datasets
"""
import argparse, hashlib, json, random, re, sys, zipfile
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from data.build_dataset import KEEP_IDS, FIELDS, NOISE, NS, TACTICS

EXTRA_FIELDS = ["Hashes", "PipeName", "DestinationHostname", "SourceIp", "SourcePort",
                "ObjectName", "AccessMask", "ProcessName", "ParentProcessName"]
OTRF_FOLDERS = {"command_and_control": "Command and Control", "credential_access": "Credential Access",
                "defense_evasion": "Defense Evasion", "discovery": "Discovery", "execution": "Execution",
                "lateral_movement": "Lateral Movement", "persistence": "Persistence",
                "privilege_escalation": "Privilege Escalation"}
HOSTS = [f"HOST-{i:02d}" for i in range(1, 11)]
# Lab agents that fill OTRF captures with routine events
OTRF_NOISE = ("VBoxService", "VBoxTray", "winlogbeat", "Splunk", "MsMpEng", "SearchIndexer",
              "SearchProtocolHost", "nxlog", "osqueryd", "WmiPrvSE.exe -Embedding")
MATCH_FIELDS = ("CommandLine", "ParentCommandLine", "ScriptBlockText", "Image", "NewProcessName",
                "TargetFilename", "PipeName", "ServiceName", "ImagePath", "TaskName", "TargetObject", "ShareName",
                "RelativeTargetName", "ImageLoaded", "TargetImage")
STOP = {"empire", "windows", "remote", "dataset", "datasets", "local", "using", "execution", "via", "with",
        "from", "service", "process", "registry", "command", "network", "domain", "sysmon", "events"}
SEED, CAP, MAX_EVENTS = 20261004, 15, 20


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def to_event(eid, data, when):
    ev = {"event_id": int(eid)}
    if when:
        ev["TimeCreated"] = when
    for f in FIELDS + EXTRA_FIELDS:
        v = data.get(f)
        if v not in (None, "", "-"):
            ev[f] = str(v)[:300]
    blob = json.dumps(ev)
    if len(ev) <= (2 if when else 1) or any(n in blob for n in NOISE):
        return None
    return ev


def evtx_events(path):
    import Evtx.Evtx as evtx
    out = []
    with evtx.Evtx(str(path)) as log:
        for rec in log.records():
            try:
                x = ET.fromstring(rec.xml())
            except Exception:
                continue
            eid = x.find(".//e:EventID", NS).text
            tc = x.find(".//e:TimeCreated", NS)
            data = {d.get("Name"): (d.text or "") for d in x.findall(".//e:Data", NS)}
            ev = to_event(eid, data, tc.get("SystemTime") if tc is not None else None)
            if ev:
                out.append(ev)
    return out


def otrf_events(zip_path):
    out = []
    with zipfile.ZipFile(zip_path) as z:
        for name in z.namelist():
            for line in z.read(name).decode("utf-8", "replace").splitlines():
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if "EventID" not in rec:
                    continue
                ev = to_event(rec["EventID"], rec, rec.get("TimeCreated") or rec.get("@timestamp"))
                if ev and not any(n in json.dumps(ev) for n in OTRF_NOISE):
                    ev["_host"] = rec.get("Hostname", "")
                    out.append(ev)
    out.sort(key=lambda e: e.get("TimeCreated", ""))
    return out


def split_alert(events):
    """Alert = last 20 kept-ID events (M1 rule); the rest becomes tool context."""
    kept = [i for i, e in enumerate(events) if str(e["event_id"]) in KEEP_IDS]
    shown = set(kept[-MAX_EVENTS:])
    return [events[i] for i in sorted(shown)], [e for i, e in enumerate(events) if i not in shown]


def otrf_tokens(meta):
    words = re.findall(r"[A-Za-z][A-Za-z0-9_\-]{4,}", meta.get("title", ""))
    for tool in (meta.get("simulation") or {}).get("tools") or []:
        for key in ("name", "module"):
            if tool.get(key):
                words += re.findall(r"[A-Za-z][A-Za-z0-9_\-]{3,}", str(tool[key]))
    return {w.lower() for w in words if w.lower() not in STOP}


def otrf_split(events, tokens):
    """Start the alert at the first event matching the documented simulation, like a detection firing."""
    kept = [i for i, e in enumerate(events) if str(e["event_id"]) in KEEP_IDS]
    anchor = next((i for i in kept if any(t in " ".join(str(events[i].get(f, "")) for f in MATCH_FIELDS).lower()
                                          for t in tokens)), None)
    if anchor is None:
        return [], events
    host = events[anchor]["_host"]
    same = [i for i in kept if events[i]["_host"] == host]
    pos = same.index(anchor)
    shown = set(same[max(0, pos - 3): max(0, pos - 3) + MAX_EVENTS])
    clean = lambda e: {k: v for k, v in e.items() if k != "_host"}
    return ([clean(events[i]) for i in sorted(shown)],
            [clean(e) for i, e in enumerate(events) if i not in shown and e["_host"] == host])


def host_for(alert_id):
    return HOSTS[int(hashlib.sha256(alert_id.encode()).hexdigest(), 16) % len(HOSTS)]


def write(name, alerts, context, manifest):
    out = ROOT / "data" / "eval"
    out.mkdir(parents=True, exist_ok=True)
    if alerts is not None:
        (out / f"{name}.jsonl").write_text("".join(json.dumps(a) + "\n" for a in alerts))
    (out / f"{name}_context.jsonl").write_text(
        "".join(json.dumps({"alert_id": k, "events": v}) + "\n" for k, v in context.items()))
    (out / f"{name}_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"{name}: {len(manifest['alerts'])} alerts")


def sample(by_tactic):
    rng = random.Random(SEED)
    picked = {}
    for t in TACTICS:
        files = sorted(by_tactic.get(t, []))
        picked[t] = files if len(files) <= CAP else sorted(rng.sample(files, CAP))
    return picked


def build_dev(evtx_repo):
    alerts = [json.loads(l) for l in (ROOT / "examples/alerts.jsonl").read_text().splitlines() if l.strip()]
    context, rows = {}, []
    for a in alerts:
        if a["label_verdict"] != "malicious":
            context[a["alert_id"]] = []
            continue
        path = Path(evtx_repo) / a["label_tactic"] / a["source_file"]
        shown, extra = split_alert(evtx_events(path))
        context[a["alert_id"]] = extra
        rows.append({"alert_id": a["alert_id"], "source": str(path.relative_to(evtx_repo)), "sha256": sha256(path)})
    write("dev", None, context, {"dataset": "dev", "alerts": rows})


def usable_evtx(evtx_repo):
    dev = {json.loads(l)["source_file"] for l in (ROOT / "examples/alerts.jsonl").read_text().splitlines() if l.strip()}
    usable = {}
    for t in TACTICS:
        for f in sorted((Path(evtx_repo) / t).glob("*.evtx")):
            if f.name in dev:
                continue
            shown, _ = split_alert(evtx_events(f))
            if len(shown) >= 3:
                usable.setdefault(t, []).append(f.name)
    return usable


def evtx_alerts(evtx_repo, picked, prefix):
    alerts, context, rows = [], {}, []
    for t in TACTICS:
        for name in picked.get(t, []):
            path = Path(evtx_repo) / t / name
            shown, extra = split_alert(evtx_events(path))
            aid = f"{prefix}{len(alerts) + 1:03d}"
            alerts.append({"alert_id": aid, "host": host_for(aid), "events": shown,
                           "label_tactic": t, "label_verdict": "malicious"})
            context[aid] = extra
            rows.append({"alert_id": aid, "source": f"{t}/{name}", "sha256": sha256(path)})
    return alerts, context, rows


def build_evtx(evtx_repo):
    usable = usable_evtx(evtx_repo)
    alerts, context, rows = evtx_alerts(evtx_repo, sample(usable), "H")
    write("evtx_heldout", alerts, context, {"dataset": "evtx_heldout", "seed": SEED, "cap": CAP,
          "usable_per_tactic": {t: len(v) for t, v in usable.items()}, "alerts": rows})


def build_val(evtx_repo):
    """Usable captures the held-out sample did not take; the only EVTX data we tune on."""
    usable = usable_evtx(evtx_repo)
    held = sample(usable)
    rest = {t: [f for f in files if f not in held[t]] for t, files in usable.items()}
    alerts, context, rows = evtx_alerts(evtx_repo, sample(rest), "V")
    write("evtx_val", alerts, context, {"dataset": "evtx_val", "seed": SEED, "cap": CAP,
          "note": "tuning split: never overlaps evtx_heldout", "alerts": rows})


def otrf_metadata(otrf_repo):
    import yaml
    meta = {}
    for f in sorted((Path(otrf_repo) / "datasets/atomic/_metadata").glob("SDWIN-*.yaml")):
        m = yaml.safe_load(f.read_text())
        for x in m.get("files") or []:
            if str(x.get("type", "")).lower() == "host":
                meta[x["link"].rsplit("/", 1)[-1]] = m
    return meta


def build_otrf(otrf_repo):
    base = Path(otrf_repo) / "datasets/atomic/windows"
    meta = otrf_metadata(otrf_repo)
    usable = {}
    for folder, t in OTRF_FOLDERS.items():
        for z in sorted((base / folder / "host").glob("*.zip")):
            if z.name not in meta:
                continue
            shown, _ = otrf_split(otrf_events(z), otrf_tokens(meta[z.name]))
            if len(shown) >= 3:
                usable.setdefault(t, []).append(z.name)
    picked = sample(usable)
    alerts, context, rows, n = [], {}, [], 1
    folder_of = {t: f for f, t in OTRF_FOLDERS.items()}
    for t in TACTICS:
        for name in picked.get(t, []):
            z = base / folder_of[t] / "host" / name
            shown, extra = otrf_split(otrf_events(z), otrf_tokens(meta[name]))
            aid = f"O{n:03d}"; n += 1
            alerts.append({"alert_id": aid, "host": host_for(aid), "events": shown,
                           "label_tactic": t, "label_verdict": "malicious"})
            context[aid] = extra[-200:]
            rows.append({"alert_id": aid, "source": f"{folder_of[t]}/host/{name}", "sha256": sha256(z),
                         "otrf_id": meta[name]["id"], "title": meta[name]["title"]})
    write("otrf_pilot", alerts, context, {"dataset": "otrf_pilot", "seed": SEED, "cap": CAP,
          "usable_per_tactic": {t: len(v) for t, v in usable.items()}, "alerts": rows})


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--evtx-repo", required=True)
    ap.add_argument("--otrf-repo")
    ap.add_argument("--only", choices=["dev", "evtx", "val", "otrf"])
    a = ap.parse_args()
    if a.only in (None, "dev"):
        build_dev(a.evtx_repo)
    if a.only in (None, "evtx"):
        build_evtx(a.evtx_repo)
    if a.only in (None, "val"):
        build_val(a.evtx_repo)
    if a.only in (None, "otrf"):
        build_otrf(a.otrf_repo)
