"""Build the ATT&CK v18.1 index for lookup_technique (v19 split Defense Evasion, our labels did not).

  python data/build_attack_index.py --stix enterprise-attack-18.1.json
"""
import argparse, json, re
from pathlib import Path

PHASES = {"command-and-control": "Command and Control", "credential-access": "Credential Access",
          "defense-evasion": "Defense Evasion", "discovery": "Discovery", "execution": "Execution",
          "lateral-movement": "Lateral Movement", "persistence": "Persistence",
          "privilege-escalation": "Privilege Escalation"}


def clean(text, limit):
    text = re.sub(r"\(Citation:[^)]*\)", "", text or "")
    text = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", text)
    return " ".join(text.split())[:limit]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--stix", required=True)
    ap.add_argument("--out", default="soc/knowledge/attack_v18_1.json")
    a = ap.parse_args()
    bundle = json.loads(Path(a.stix).read_text())
    version = next((o.get("x_mitre_version") for o in bundle["objects"] if o["type"] == "x-mitre-collection"), None)
    rows = []
    for o in bundle["objects"]:
        if o["type"] != "attack-pattern" or o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        if "windows" not in [p.lower() for p in o.get("x_mitre_platforms", [])]:
            continue
        ext = next((r["external_id"] for r in o.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)
        tactics = [PHASES[k["phase_name"]] for k in o.get("kill_chain_phases", []) if k["phase_name"] in PHASES]
        if ext and tactics:
            rows.append({"id": ext, "name": o["name"], "tactics": tactics,
                         "description": clean(o.get("description"), 400),
                         "detection": clean(o.get("x_mitre_detection"), 300)})
    rows.sort(key=lambda r: r["id"])
    Path(a.out).write_text(json.dumps({"attack_version": version, "techniques": rows}, indent=1) + "\n")
    print(f"ATT&CK {version}: {len(rows)} Windows techniques -> {a.out}")


if __name__ == "__main__":
    main()
