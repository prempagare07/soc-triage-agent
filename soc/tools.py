"""Mocked SOC tools. They never see labels or file names, and their output is checked before it is returned."""
import json, re
from pathlib import Path

KNOWLEDGE = Path(__file__).resolve().parent / "knowledge"
ATTACK = json.loads((KNOWLEDGE / "attack_v18_1.json").read_text())
IOCS = json.loads((KNOWLEDGE / "ioc_list.json").read_text())
ASSETS = json.loads((KNOWLEDGE / "asset_inventory.json").read_text())["hosts"]
MAX_LOGS = 10
GENERIC = {"exe", "dll", "the", "and", "for", "with", "from", "port", "ports", "destination", "source", "process",
           "processes", "file", "files", "event", "events", "network", "connection", "connections", "windows",
           "system", "user", "suspicious", "malicious", "activity", "command", "line", "using", "via"}

SCHEMAS = {
    "get_more_logs": {"event_id": "int, optional", "keyword": "string, optional", "limit": "int <= 10"},
    "lookup_technique": {"query": "string: a binary name, command or behaviour"},
    "check_ioc": {"indicator": "string: file name, hash, IP, domain or pipe"},
    "get_asset_context": {"host": "string"},
}


class ToolError(Exception):
    pass


def main_binaries(alert, k=3):
    seen = []
    for ev in alert["events"]:
        for f in ("Image", "NewProcessName", "TargetImage", "ImageLoaded"):
            name = re.split(r"[\\/]", ev.get(f, ""))[-1].lower()
            if name and name not in seen:
                seen.append(name)
    return seen[:k]


def playbook(alert):
    """The standard enrichment a tier-1 analyst runs first: recent host logs, ATT&CK and IOC checks
    for the main binaries, and the asset record. Shared by the fixed workflow and the agent."""
    plan = [("get_more_logs", {"limit": 10})]
    for b in main_binaries(alert):
        plan += [("lookup_technique", {"query": b}), ("check_ioc", {"indicator": b})]
    plan.append(("get_asset_context", {"host": alert["host"]}))
    return plan[:8]


def rule_hits(events):
    """The detection rules that fired on this alert, like the rule name a SIEM attaches to an alert."""
    from .rules import INDICATORS
    hits = {}
    for i, ev in enumerate(events):
        blob = json.dumps(ev).lower()
        for tactic, words in INDICATORS.items():
            for w in words:
                if w in blob:
                    h = hits.setdefault(tactic, {"tactic": tactic, "indicators": [], "events": []})
                    if w not in h["indicators"]:
                        h["indicators"].append(w)
                    if i not in h["events"]:
                        h["events"].append(i)
    return sorted(hits.values(), key=lambda h: (-len(h["indicators"]), -len(h["events"]), h["tactic"]))


def _short(ev, limit=200):
    return {k: (v[:limit] if isinstance(v, str) else v) for k, v in ev.items()}


class ToolBox:
    def __init__(self, alert, context_events, forbidden=()):
        self.host = alert["host"]
        self.context = context_events or []
        self.next_index = len(alert["events"])
        self.fetched = {}
        self.asset_fact = None
        self.forbidden = {t.lower() for t in forbidden if t}
        self.calls = []

    def call(self, name, args):
        if name not in SCHEMAS:
            raise ToolError(f"unknown tool {name!r}")
        if not isinstance(args, dict):
            raise ToolError("args must be a JSON object")
        result = getattr(self, name)(**{k: v for k, v in args.items() if k in SCHEMAS[name]})
        blob = json.dumps(result).lower()
        if any(t in blob for t in self.forbidden):
            raise ToolError("tool output withheld: it contained evaluation metadata")
        self.calls.append({"tool": name, "args": args})
        return result

    def get_more_logs(self, event_id=None, keyword=None, limit=MAX_LOGS):
        try:
            limit = max(1, min(int(limit), MAX_LOGS))
            event_id = int(event_id) if event_id not in (None, "") else None
        except (TypeError, ValueError):
            raise ToolError("event_id and limit must be integers")
        hits = [e for e in self.context
                if (event_id is None or e["event_id"] == event_id)
                and (not keyword or str(keyword).lower() in json.dumps(e).lower())]
        out = []
        for ev in hits[-limit:]:
            seen = next((i for i, e in self.fetched.items() if e is ev), None)
            if seen is None:
                seen, self.next_index = self.next_index, self.next_index + 1
                self.fetched[seen] = ev
            out.append({"index": seen, **_short(ev)})
        return {"matched": len(hits), "returned": len(out), "events": out}

    def lookup_technique(self, query=""):
        words = [w for w in re.findall(r"[a-z0-9]+", str(query).lower())
                 if len(w) > 2 and not w.isdigit() and w not in GENERIC]
        if not str(query).strip():
            raise ToolError("query is empty")
        if not words:
            return {"attack_version": ATTACK["attack_version"], "results": [],
                    "hint": "search by binary name, command or behaviour, not port numbers or generic words"}
        scored = []
        for t in ATTACK["techniques"]:
            name, desc = t["name"].lower(), t["description"].lower()
            score = sum(3 * (w in name) + (w in desc) for w in words) + 5 * (str(query).lower() == t["id"].lower())
            if score:
                scored.append((score, t))
        scored.sort(key=lambda x: (-x[0], x[1]["id"]))
        return {"attack_version": ATTACK["attack_version"],
                "results": [{"id": t["id"], "name": t["name"], "tactics": t["tactics"],
                             "description": t["description"][:140]} for _, t in scored[:3]]}

    def check_ioc(self, indicator=""):
        value = str(indicator).strip().lower()
        if not value:
            raise ToolError("indicator is empty")
        base = re.split(r"[\\/]", value)[-1]
        for kind in ("known_bad", "dual_use"):
            for key, desc in IOCS[kind].items():
                if key in (base, value) or (len(key) > 4 and key in value):
                    return {"indicator": indicator, "verdict": kind, "match": key, "description": desc}
        return {"indicator": indicator, "verdict": "unknown"}

    def get_asset_context(self, host=""):
        host = str(host).strip() or self.host
        if host not in ASSETS:
            raise ToolError(f"host {host!r} not in inventory")
        self.asset_fact = {"host": host, **ASSETS[host]}
        return self.asset_fact
