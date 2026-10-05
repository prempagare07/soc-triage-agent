"""Hash an offline JSONL split and deterministically resolve its EVTX sources."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import subprocess


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def corpus_provenance(corpus):
    corpus = Path(corpus).resolve()
    def git(*args):
        run = subprocess.run(["git", "-C", str(corpus), *args], capture_output=True, text=True)
        return run.stdout.strip() if run.returncode == 0 else None
    top = git("rev-parse", "--show-toplevel")
    if top is None or Path(top).resolve() != corpus:
        return {"commit": None, "dirty": None, "status": None,
                "explanation": "Corpus is not a standalone Git checkout; commit unavailable (e.g. ZIP)."}
    status = git("status", "--porcelain", "--untracked-files=all")
    return {"commit": git("rev-parse", "HEAD"), "dirty": bool(status) if status is not None else None,
            "status": status, "explanation": None}


def evtx_inventory(corpus):
    corpus = Path(corpus).resolve()
    return sorted((p for p in corpus.rglob("*") if p.is_file() and p.suffix.lower() == ".evtx"),
                  key=lambda p: p.relative_to(corpus).as_posix())


def resolve_source(source, corpus, files=None):
    corpus = Path(corpus).resolve()
    normalized = source.replace("\\", "/")
    relative = PurePosixPath(normalized)
    if relative.is_absolute() or ".." in relative.parts or ":" in normalized:
        raise ValueError("Source must be a corpus-relative path or an unambiguous basename")
    files = evtx_inventory(corpus) if files is None else files
    if len(relative.parts) > 1:
        candidates = [p for p in files if p.relative_to(corpus).as_posix() == normalized]
    else:
        candidates = [p for p in files if p.name == normalized]
    if len(candidates) != 1:
        names = [p.relative_to(corpus).as_posix() for p in candidates]
        raise ValueError(f"Missing or ambiguous source {source!r}: {names}")
    if not candidates[0].resolve().is_relative_to(corpus):
        raise ValueError("Source resolves outside corpus")
    return candidates[0]


def build_manifest(split, corpus, demo=False):
    split, corpus = Path(split).resolve(), Path(corpus).resolve()
    if not corpus.is_dir():
        raise ValueError("Corpus directory does not exist")
    raw = split.read_bytes()
    files = evtx_inventory(corpus)
    records, ids, captures = [], set(), set()
    before = corpus_provenance(corpus)
    for number, line in enumerate(raw.splitlines(keepends=True), 1):
        if not line.strip():
            raise ValueError(f"Blank alert line {number}")
        alert = json.loads(line)
        if not isinstance(alert, dict):
            raise ValueError(f"Alert line {number} must be a JSON object")
        alert_id = alert.get("alert_id")
        if not isinstance(alert_id, str) or not alert_id or alert_id in ids:
            raise ValueError(f"Missing or duplicate alert ID at line {number}")
        ids.add(alert_id)
        source = alert.get("source_file")
        if not isinstance(source, str) or not source:
            raise ValueError(f"Missing source_file at line {number}")
        record = {"alert_id": alert_id, "line_number": number, "line_sha256": sha256(line),
                  "source_file": source, "capture_path": None, "capture_sha256": None}
        if source.lower().endswith(".evtx"):
            path = resolve_source(source, corpus, files)
            if path in captures:
                raise ValueError("Duplicate source capture in split")
            captures.add(path)
            record.update(source_kind="evtx", capture_path=path.relative_to(corpus).as_posix(),
                          capture_sha256=sha256(path.read_bytes()), provenance_note=None)
        elif (source.startswith("synthetic_benign_") and source.endswith(".json")
              and alert.get("label_verdict") == "benign"):
            record.update(source_kind="synthetic_benign",
                          provenance_note="Synthetic example; no real benign EVTX capture exists.")
        else:
            raise ValueError(f"Unsupported source at line {number}; do not invent capture provenance")
        records.append(record)
    if not records:
        raise ValueError("Split is empty")
    after = corpus_provenance(corpus)
    if before != after or split.read_bytes() != raw:
        raise ValueError("Provenance or split changed while hashing")
    return {"manifest_version": 1, "created_utc": datetime.now(timezone.utc).isoformat(),
            "purpose": "dev_demo" if demo else "candidate_split_manifest",
            "held_out_frozen": False,
            "approval_note": "Hashing does not approve selection or labels; approval is a separate prerequisite.",
            "split_path": str(split), "split_sha256": sha256(raw), "corpus_path": str(corpus),
            "corpus": before,
            "line_hash_convention": "Exact stored UTF-8 JSONL line bytes, including LF/CRLF when present; final unterminated line has no added newline.",
            "source_resolution": "Exact relative path; bare filename must be unique across the entire corpus. No folder-label fallback.",
            "alert_count": len(records), "evtx_capture_count": len(captures),
            "synthetic_count": sum(r["source_kind"] == "synthetic_benign" for r in records),
            "alerts": records}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--corpus", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--demo", action="store_true")
    args = parser.parse_args()
    if args.output.exists():
        parser.error("Output already exists; preserve it and choose a new output path")
    try:
        manifest = build_manifest(args.input, args.corpus, args.demo)
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"Wrote {args.output}: {manifest['alert_count']} alerts; purpose={manifest['purpose']}; held_out_frozen=false")


if __name__ == "__main__":
    main()
