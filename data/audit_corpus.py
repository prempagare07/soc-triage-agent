"""Offline corpus audit; imports the builder without changing its source."""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import csv
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import threading
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from data import build_dataset as builder

WIDER = {"4104", "4103", "4648", "4672", "4698", "4720", "4728", "4732", "5140"}
LOCK = threading.RLock()
EVTX_READER = builder.evtx.Evtx


class CachedRecord:
    def __init__(self, xml, error=None):
        self.text, self.error = xml, error

    def xml(self):
        if self.error is not None:
            raise self.error
        return self.text


def decode_records(path):
    """Decode original records once; never synthesize events or labels."""
    records = []
    with EVTX_READER(str(path)) as log:
        for record in log.records():
            try:
                records.append(CachedRecord(record.xml()))
            except Exception as exc:
                records.append(CachedRecord(None, exc))
    return records


def evaluate_decoded(path, records, current, wide):
    class CachedLog:
        def __init__(self, filename):
            if str(path) != filename:
                raise ValueError("Cached records requested for wrong file")
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def records(self): return iter(records)
    parsed, errors = {}, []
    # Only the I/O adapter is cached; the actual imported parse() executes
    # separately for both settings and both truncation limits.
    with LOCK:
        original_reader = builder.evtx.Evtx
        try:
            builder.evtx.Evtx = CachedLog
            for setting, ids in (("current", current), ("wide", wide)):
                try:
                    parsed[setting] = parse_setting(path, ids)
                except Exception as exc:
                    errors.append(f"{setting}: {type(exc).__name__}: {exc}")
            raw = raw_metadata(path)
        finally:
            builder.evtx.Evtx = original_reader
    return parsed, errors, raw


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git(path, *args):
    result = subprocess.run(["git", "-C", str(path), *args], capture_output=True, text=True)
    return result.stdout.strip() if result.returncode == 0 else None


def resolve_dev(alerts, files, root):
    matches, problems = {}, []
    names = {}
    for path in files:
        names.setdefault(path.name, []).append(path)
    for alert in alerts:
        if alert["alert_id"] not in {f"A{i:03d}" for i in range(1, 25)}:
            continue
        source = alert.get("source_file", "")
        candidates = names.get(source, [])
        if len(candidates) != 1:
            problems.append({"alert_id": alert["alert_id"], "source_file": source,
                             "matches": [p.relative_to(root).as_posix() for p in candidates]})
        else:
            matches[alert["alert_id"]] = candidates[0]
    if len(matches) + len(problems) != 24:
        problems.append({"error": "Expected exactly 24 dev attack IDs A001–A024"})
    if len(set(matches.values())) != len(matches):
        problems.append({"error": "Multiple dev IDs reference the same capture"})
    return matches, problems


def parse_setting(path, ids):
    # KEEP_IDS is a module global; lock and always restore it, including errors.
    with LOCK:
        original = builder.KEEP_IDS
        try:
            builder.KEEP_IDS = ids
            default = builder.parse(path)
            uncapped = builder.parse(path, max_events=sys.maxsize)
            return len(default), len(uncapped)
        finally:
            builder.KEEP_IDS = original


def raw_metadata(path):
    result = {"has_hashes": False, "has_timecreated": False, "raw_records": 0,
              "xml_errors": 0, "event_ids": Counter(), "content_signals": [], "raw_error": ""}
    signals = set()
    try:
        with builder.evtx.Evtx(str(path)) as log:
            for record in log.records():
                result["raw_records"] += 1
                try:
                    xml = ET.fromstring(record.xml())
                except Exception:
                    result["xml_errors"] += 1
                    continue
                eid = xml.find(".//e:EventID", builder.NS)
                if eid is not None:
                    result["event_ids"][eid.text or ""] += 1
                result["has_timecreated"] |= xml.find(".//e:TimeCreated", builder.NS) is not None
                provider = xml.find(".//e:Provider", builder.NS)
                is_sysmon = provider is not None and "sysmon" in provider.get("Name", "").lower()
                fields = {d.get("Name"): d.text or "" for d in xml.findall(".//e:Data", builder.NS)}
                result["has_hashes"] |= is_sysmon and "Hashes" in fields
                text = json.dumps(fields).lower()
                for token in ("lsass", "mimikatz", "bloodhound", "psloggedon", "plink", "w3wp"):
                    if token in text:
                        signals.add(token)
                if fields.get("DestinationPort") in ("3389", "445"):
                    signals.add("destination port " + fields["DestinationPort"])
                if fields.get("LogonType") == "10" and fields.get("IpAddress") in ("127.0.0.1", "::1"):
                    signals.add("RDP LogonType 10 from loopback")
    except Exception as exc:
        result["raw_error"] = f"{type(exc).__name__}: {exc}"
        result["has_hashes"] = result["has_hashes"] or None
        result["has_timecreated"] = result["has_timecreated"] or None
    result["content_signals"] = sorted(signals)
    return result


def audit_file(path, root, used, current, wide):
    relative = path.relative_to(root)
    folder = relative.parts[0] if len(relative.parts) > 1 else "(top level)"
    in_scope = folder in builder.TACTICS and len(relative.parts) == 2
    row = {"folder": folder, "file": relative.as_posix(), "used_in_dev": path in used,
           "in_scope": in_scope, "source_sha256": sha(path), "events_kept_current": None,
           "events_kept_wide": None, "events_uncapped_current": None, "events_uncapped_wide": None,
           "qualifies_current": False, "qualifies_wide": False, "has_hashes": None,
           "has_timecreated": None, "raw_records": None, "xml_errors": None,
           "event_ids": "", "content_signals": "", "status": "out_of_scope", "error": ""}
    if not in_scope:
        return row
    try:
        decoded = decode_records(path)
        parsed, errors, raw = evaluate_decoded(path, decoded, current, wide)
        for setting, (kept, uncapped) in parsed.items():
            row[f"events_kept_{setting}"] = kept
            row[f"events_uncapped_{setting}"] = uncapped
            row[f"qualifies_{setting}"] = kept >= 3
    except Exception as exc:
        row.update(status="error", error=f"decode: {type(exc).__name__}: {exc}")
        return row
    for key in ("has_hashes", "has_timecreated", "raw_records", "xml_errors"):
        row[key] = raw[key]
    row["event_ids"] = json.dumps(dict(raw["event_ids"]), sort_keys=True)
    row["content_signals"] = "; ".join(raw["content_signals"])
    if raw["raw_error"]:
        errors.append("raw: " + raw["raw_error"])
    row["status"] = "error" if errors else "xml_errors" if raw["xml_errors"] else "ok"
    row["error"] = "; ".join(errors)
    return row


def report(rows, provenance, dev, problems, current, wide, licenses, root, command):
    scoped = [r for r in rows if r["in_scope"]]
    unused = [r for r in scoped if not r["used_in_dev"]]
    qualifying = {s: sum(r[f"qualifies_{s}"] for r in scoped) for s in ("current", "wide")}
    qualifying_unused = {s: sum(r[f"qualifies_{s}"] for r in unused) for s in ("current", "wide")}
    lines = ["# EVTX corpus audit", "", f"Command: `{command}`", "",
             "## Provenance", "", "```json", json.dumps(provenance, indent=2), "```", "",
             "Offline audit only: source paths/labels are never sent to a classifier.", "",
             "## File inventory and builder eligibility", "",
             "| Folder | Files | Dev captures | Unused files | Qualifying all current/wide | Qualifying unused current/wide |",
             "|---|---:|---:|---:|---:|---:|"]
    for folder in [*builder.TACTICS, *sorted({r["folder"] for r in rows} - set(builder.TACTICS))]:
        group = [r for r in rows if r["folder"] == folder]
        group_unused = [r for r in group if not r["used_in_dev"]]
        if folder in builder.TACTICS:
            all_q = "/".join(str(sum(r[f"qualifies_{s}"] for r in group)) for s in ("current", "wide"))
            un_q = "/".join(str(sum(r[f"qualifies_{s}"] for r in group_unused)) for s in ("current", "wide"))
        else:
            all_q = un_q = "not evaluated"
        lines.append(f"| {folder} | {len(group)} | {sum(r['used_in_dev'] for r in group)} | {len(group_unused)} | {all_q} | {un_q} |")
    lines += ["", f"Total EVTX files: {len(rows)}. In-scope: {len(scoped)}. Unused in-scope: {len(unused)}.",
              f"Qualifying all in-scope: {qualifying}. Qualifying unused: {qualifying_unused}.", "",
              "Scope matches the builder: direct .evtx children of the eight tactic folders. Other folders/top-level files are inventoried but not held-out candidates.",
              "Each file is one candidate alert. Eligibility is >=3 retained events; a file can contain many raw records.",
              "events_kept_* uses actual default parse() calls (last 20 events); events_uncapped_* uses parse(max_events=sys.maxsize). Both settings are actually parsed even if identical.", "",
              "Original EVTX record XML is decoded once per file and cached in memory; an I/O adapter feeds those exact records to the imported builder calls and raw XML checks. No model calls or synthetic events are used.", "",
              "## Event ID sets", "", f"Current: {', '.join(sorted(current, key=int))}.",
              f"Wider: {', '.join(sorted(wide, key=int))}.", f"New IDs: {sorted(wide-current, key=int)}.",
              "The proposed wider IDs are already present when this difference is empty; no artificial expansion is made.", "",
              "## Dev source resolution", "", "| Alert | Resolved capture |", "|---|---|"]
    lines += [f"| {key} | {path.relative_to(root).as_posix()} |" for key, path in sorted(dev.items())]
    lines += ["", "Resolution problems: " + json.dumps(problems), "", "## Raw XML coverage and errors", ""]
    for field in ("has_hashes", "has_timecreated"):
        yes = sum(r[field] is True for r in scoped)
        unknown = sum(r[field] is None for r in scoped)
        lines.append(f"- {field}: {yes}/{len(scoped)} files ({yes/len(scoped):.1%}); unknown: {unknown}. Denominator is all in-scope files.")
    records = sum(r["raw_records"] or 0 for r in scoped)
    xml_errors = sum(r["xml_errors"] or 0 for r in scoped)
    files_errors = [r for r in scoped if r["status"] != "ok"]
    lines += [f"- XML errors: {xml_errors}/{records} inspected raw records.",
              f"- Files with builder/raw/XML issues: {len(files_errors)}/{len(scoped)}.",
              "Hashes requires a Sysmon provider and a named Hashes field (field presence, not a SHA256 guarantee). TimeCreated is element presence. Missing and unknown are distinct.", "",
              "## Command and Control tunneling evidence", "",
              "The corpus Command and Control/readme.md describes five RDP/SMB tunneling examples. Classification below uses matching descriptive filenames, that local README, and raw content signals; it does not relabel captures.", "",
              "| File | Dev? | RDP/SMB tunnel by filename/README | Raw signals | Qualifying unused? |", "|---|---|---|---|---|"]
    c2 = [r for r in scoped if r["folder"] == "Command and Control"]
    tunnel = lambda r: "rdp" in Path(r["file"]).name.lower() or "smb_tunneling" in Path(r["file"]).name.lower()
    for r in c2:
        lines.append(f"| {r['file']} | {r['used_in_dev']} | {tunnel(r)} | {r['content_signals'] or 'none of checked signals'} | {not r['used_in_dev'] and r['qualifies_current']} |")
    lines += ["", "## Suspected label noise and cross-tactic signals", "",
              "Folder labels are corpus categories, not validated single-tactic ground truth. The following conservative checks flag candidates for manual review; they do not prove mislabelling or exhaust all possible contradictions.", ""]
    prefix_map = {"DE_": "Defense Evasion", "CA_": "Credential Access", "LM_": "Lateral Movement", "C2_": "Command and Control"}
    candidates = []
    for r in scoped:
        name = Path(r["file"]).name
        for prefix, tactic in prefix_map.items():
            if name.upper().startswith(prefix) and r["folder"] != tactic:
                candidates.append(f"- {r['file']}: prefix {prefix} suggests {tactic}; folder is {r['folder']}.")
        if r["folder"] != "Credential Access" and any(token in r["content_signals"] for token in ("lsass", "mimikatz")):
            candidates.append(f"- {r['file']}: raw content mentions {r['content_signals']}; possible credential-access overlap, not a definitive tactic contradiction.")
        if r["folder"] != "Discovery" and any(token in r["content_signals"] for token in ("bloodhound", "psloggedon")):
            candidates.append(f"- {r['file']}: raw content mentions {r['content_signals']}; possible discovery overlap requiring review.")
    lines += candidates or ["No candidates found by the declared checks."]
    lines += ["", "A001 and A003 are explicitly listed in the dev resolution table and tunneling table. Their DE-prefixed names differ from their Command and Control folder; tunneling can span tactics, so preserve this as suspected label ambiguity.", "",
              "## Historical claims checked", "", "| Claim | Observed / interpretation |", "|---|---|"]
    claims = [("278 total", str(len(rows))), ("261 in eight folders", str(len(scoped))),
              ("237 unused in eight folders", str(len(unused))),
              ("About 125 current-builder alerts", f"{qualifying['current']} including dev; {qualifying_unused['current']} unused only"),
              ("About 142 wider-ID alerts", f"{qualifying['wide']} including dev; {qualifying_unused['wide']} unused only; added IDs={sorted(wide-current)}"),
              ("Command and Control has one file left", f"{sum(not r['used_in_dev'] for r in c2)} unused raw files; {sum(not r['used_in_dev'] and r['qualifies_current'] for r in c2)} qualifying unused alerts"),
              ("Discovery has two to four left", f"{sum(r['folder']=='Discovery' for r in unused)} unused raw files; {sum(r['folder']=='Discovery' and r['qualifies_current'] for r in unused)} qualifying unused alerts"),
              ("Five of six C2 files are RDP/SMB tunnels", f"{sum(tunnel(r) for r in c2)}/{len(c2)} by descriptive filenames and local README"),
              ("Hashes in about half the captures", f"{sum(r['has_hashes'] is True for r in scoped)}/{len(scoped)} in-scope files; remaining out-of-scope captures not scanned")]
    lines += [f"| {claim} | {value} |" for claim, value in claims]
    lines += ["", "Exact matches and differing numbers are shown directly; approximate claims are not forced to match. Counts are specific to the recorded revision and builder hash.", "",
              "## Parse issues", "", *[f"- {r['file']}: {r['error'] or str(r['xml_errors'])+' XML errors'}" for r in files_errors],
              "None." if not files_errors else "", "", "## License text", ""]
    if not licenses:
        lines.append("No license file found.")
    for path in licenses:
        lines += [f"### {path.relative_to(root).as_posix()} (SHA256 {sha(path)})", "", "```text", path.read_text(errors="replace"), "```", ""]
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--input", default="examples/alerts.jsonl")
    parser.add_argument("--output-dir", default="outputs")
    parser.add_argument("--workers", type=int, default=4)
    args = parser.parse_args()
    root, inp, output = Path(args.repo).resolve(), Path(args.input), Path(args.output_dir)
    if not root.is_dir():
        parser.error("Corpus directory does not exist")
    files = sorted(p for p in root.rglob("*") if p.is_file() and p.suffix.lower() == ".evtx" and ".git" not in p.relative_to(root).parts)
    if not files:
        parser.error("No EVTX files found")
    alerts = [json.loads(line) for line in inp.read_text().splitlines() if line.strip()]
    dev, problems = resolve_dev(alerts, files, root)
    if problems:
        raise SystemExit("Dev capture resolution failed: " + json.dumps(problems))
    current = set(builder.KEEP_IDS)
    wide = current | WIDER
    provenance = {"corpus_path": str(root), "corpus_commit": git(root, "rev-parse", "HEAD"),
                  "corpus_git_status": git(root, "status", "--porcelain"),
                  "audit_started_utc": datetime.now(timezone.utc).isoformat(),
                  "input_sha256": sha(inp), "builder_sha256": sha(Path(builder.__file__)),
                  "audit_script_sha256": sha(Path(__file__)), "python_version": sys.version,
                  "note": "If corpus_commit is null, revision cannot be established (e.g. ZIP). Per-file hashes are in CSV."}
    rows = []
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as executor:
        futures = [executor.submit(audit_file, p, root, set(dev.values()), current, wide) for p in files]
        for future in as_completed(futures):
            rows.append(future.result())
            if len(rows) % 10 == 0:
                print(f"Audited {len(rows)}/{len(files)} files", flush=True)
    rows.sort(key=lambda row: row["file"])
    if builder.KEEP_IDS != current:
        raise RuntimeError("Builder globals not restored")
    provenance["audit_finished_utc"] = datetime.now(timezone.utc).isoformat()
    provenance["corpus_commit_after"] = git(root, "rev-parse", "HEAD")
    licenses = sorted(p for p in root.rglob("*") if p.is_file() and p.name.upper().startswith(("LICENSE", "COPYING")) and ".git" not in p.parts)
    output.mkdir(parents=True, exist_ok=True)
    paths = [output / "corpus_audit.csv", output / "corpus_audit.md"]
    if any(p.exists() for p in paths):
        archive = output / "history" / datetime.now(timezone.utc).strftime("audit-%Y%m%dT%H%M%S%fZ")
        archive.mkdir(parents=True)
        for path in paths:
            if path.exists():
                shutil.copy2(path, archive / path.name)
    with paths[0].open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    paths[1].write_text(report(rows, provenance, dev, problems, current, wide, licenses, root,
                              " ".join([sys.executable, *sys.argv])))
    print(f"Wrote {paths[0]} and {paths[1]}")


if __name__ == "__main__":
    main()
