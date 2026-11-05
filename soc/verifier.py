"""Blocking rule check on the agent's draft. Returns a list of problems; empty means pass."""
import json
from .schema import TACTICS

ATTACK_TACTICS = set(TACTICS) - {"Benign"}


def _norm(text):
    return " ".join(text.lower().replace("\\\\", "\\").strip(" '\"").split())


def _searchable(cited):
    parts = []
    for ev in cited:
        for k, v in ev.items():
            parts += [str(v), f"{k}: {v}", f"{k}={v}", f'"{k}": "{v}"']
    return _norm(" | ".join(parts))


def _found(quote, text):
    q = _norm(quote)
    return bool(q) and q in text


# Core Windows and AV processes that read LSASS as part of normal work
LSASS_READERS = {"msmpeng.exe", "mssense.exe", "csrss.exe", "wininit.exe", "services.exe", "svchost.exe",
                 "lsass.exe", "wmiprvse.exe", "smartscreen.exe", "taskmgr.exe"}


def hard_signals(events, observations=()):
    """Facts that rule out a benign verdict: LSASS opened by an unexpected process, a known-bad IOC,
    or two or more Credential Access / Lateral Movement rule indicators."""
    from .tools import rule_hits
    found = []
    for i, ev in events.items():
        target = str(ev.get("TargetImage", "")).lower()
        source = str(ev.get("SourceImage", "")).replace("/", "\\").split("\\")[-1].lower()
        if ev.get("event_id") in (8, 10) and target.endswith("lsass.exe") and source not in LSASS_READERS:
            found.append(f"event {i}: {source or 'a process'} opened lsass.exe")
    for obs in observations:
        res = obs.get("result") or {}
        if obs.get("tool") == "check_ioc" and res.get("verdict") == "known_bad":
            found.append(f"check_ioc: {res.get('indicator')} is known bad")
    ordered = sorted(events)
    for h in rule_hits([events[i] for i in ordered]):
        if h["tactic"] in ("Credential Access", "Lateral Movement") and len(h["indicators"]) >= 2:
            found.append(f"{h['tactic']} rule indicators {h['indicators']} in events {[ordered[j] for j in h['events']]}")
    return found


def check(draft, events, asset_fact=None, signals=()):
    errors = []
    verdict = draft.get("verdict")
    tactics = draft.get("tactics")
    if verdict not in ("malicious", "benign"):
        errors.append("verdict must be 'malicious' or 'benign'")
    if not isinstance(tactics, list) or not 1 <= len(tactics) <= 2 or any(t not in TACTICS for t in tactics):
        errors.append(f"tactics must be a list of one or two names from {TACTICS}")
    elif verdict == "benign" and tactics[0] != "Benign":
        errors.append("a benign verdict must rank 'Benign' first")
    elif verdict == "malicious" and tactics[0] not in ATTACK_TACTICS:
        errors.append("a malicious verdict needs an attack tactic ranked first")

    evidence = draft.get("evidence")
    if not isinstance(evidence, list) or (verdict == "malicious" and not evidence):
        errors.append("evidence must be a non-empty list of event indices")
    else:
        bad = [i for i in evidence if i not in events]
        if bad:
            errors.append(f"evidence cites events that do not exist: {bad}")

    claims = draft.get("claims")
    if not isinstance(claims, list) or not claims:
        errors.append("give at least one claim with its cited events")
        claims = []
    for n, claim in enumerate(claims):
        if not isinstance(claim, dict) or not str(claim.get("text", "")).strip():
            errors.append(f"claim {n} has no text"); continue
        cites = claim.get("evidence") or []
        if not cites:
            errors.append(f"claim {n} cites nothing"); continue
        cited = []
        for c in cites:
            if c == "asset":
                if asset_fact is None:
                    errors.append(f"claim {n} cites 'asset' but get_asset_context was never called")
                else:
                    cited.append(asset_fact)
            elif c in events:
                cited.append(events[c])
            else:
                errors.append(f"claim {n} cites event {c} which does not exist")
        text = _searchable(cited)
        for q in claim.get("quotes") or []:
            if not _found(str(q), text):
                errors.append(f"claim {n}: quote {str(q)[:60]!r} is not in the cited events "
                              "(copy one field value exactly, without the field name)")

    if verdict == "benign" and signals and not draft.get("uncertain"):
        errors.append("a benign verdict conflicts with: " + "; ".join(signals)
                      + ". Change the verdict to malicious, or set \"uncertain\": true to hand it to tier 2")
    note = draft.get("note")
    if not isinstance(note, dict) or any(not str(note.get(k, "")).strip() for k in ("what", "why", "next")):
        errors.append("note needs non-empty 'what', 'why' and 'next'")
    return errors


def claim_validity(draft, events, asset_fact=None):
    """Claims that pass every citation and quote check."""
    claims = draft.get("claims") if isinstance(draft.get("claims"), list) else []
    if not claims:
        return 0, 0
    ok = 0
    for claim in claims:
        probe = {"verdict": "malicious", "tactics": ["Execution"], "evidence": [0] if 0 in events else [],
                 "claims": [claim], "note": {"what": "x", "why": "x", "next": "x"}}
        ok += not [e for e in check(probe, events, asset_fact) if e.startswith("claim")]
    return ok, len(claims)
