"""Offline run provenance, output preservation, and compatible-result loading."""
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def signature(configuration):
    return hashlib.sha256(json.dumps(configuration, sort_keys=True).encode()).hexdigest()


@contextmanager
def output_lock(directory):
    """Do not let simultaneous runs overwrite the same dataset directory."""
    directory.mkdir(parents=True, exist_ok=True)
    lock = directory / ".run.lock"
    try:
        handle = lock.open("x")
    except FileExistsError as exc:
        raise ValueError(f"Output directory is already locked: {directory}; use a different --out") from exc
    try:
        with handle:
            handle.write(datetime.now(timezone.utc).isoformat())
        yield
    finally:
        lock.unlink()


def preserve_existing(directory):
    files = [p for p in directory.iterdir() if p.is_file() and p.name != ".run.lock"]
    traces = directory / "traces"
    if not files and not traces.exists():
        return None
    archive = directory / "history" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    archive.mkdir(parents=True)
    for path in files:
        shutil.copy2(path, archive / path.name)
    if traces.exists():
        shutil.move(str(traces), str(archive / "traces"))
    return archive


def save_system(directory, name, records, configuration):
    output = directory / f"{name}.jsonl"
    output.write_text("".join(json.dumps(r) + "\n" for r in records))
    metadata = {"configuration": configuration, "signature": signature(configuration),
                "output_sha256": sha256(output)}
    (directory / f"{name}.meta.json").write_text(json.dumps(metadata, indent=2) + "\n")


def load_compatible(directory, name, configuration, alert_ids):
    output, metadata = directory / f"{name}.jsonl", directory / f"{name}.meta.json"
    try:
        saved = json.loads(metadata.read_text())
        if (saved["configuration"] != configuration or saved["signature"] != signature(configuration)
                or saved["output_sha256"] != sha256(output)):
            return None
        records = [json.loads(line) for line in output.read_text().splitlines() if line.strip()]
        if [r["alert_id"] for r in records] != alert_ids:
            return None
        return records
    except (OSError, ValueError, KeyError, TypeError):
        return None
