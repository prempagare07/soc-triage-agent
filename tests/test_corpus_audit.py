import sys
from pathlib import Path

import pytest

from data import audit_corpus as audit


def test_parse_setting_restores_ids_after_error(monkeypatch):
    original = audit.builder.KEEP_IDS
    def fail(*args, **kwargs):
        assert audit.builder.KEEP_IDS == {"999"}
        raise ValueError("bad capture")
    monkeypatch.setattr(audit.builder, "parse", fail)
    with pytest.raises(ValueError):
        audit.parse_setting(Path("unused.evtx"), {"999"})
    assert audit.builder.KEEP_IDS is original


def test_parse_counts_default_and_uncapped_separately(monkeypatch):
    calls = []
    def parse(path, max_events=20):
        calls.append(max_events)
        return list(range(min(max_events, 35)))
    monkeypatch.setattr(audit.builder, "parse", parse)
    assert audit.parse_setting(Path("unused.evtx"), {"1"}) == (20, 35)
    assert calls == [20, sys.maxsize]


def test_dev_resolution_detects_ambiguous_names(tmp_path):
    files = [tmp_path / folder / f"capture-{i}.evtx" for i in range(1, 25) for folder in ("a",)]
    alerts = [{"alert_id": f"A{i:03d}", "source_file": f"capture-{i}.evtx"} for i in range(1, 25)]
    files.append(tmp_path / "b" / "capture-1.evtx")
    matched, problems = audit.resolve_dev(alerts, files, tmp_path)
    assert "A001" not in matched
    assert len(problems[0]["matches"]) == 2


def test_raw_xml_checks_sysmon_provider_and_errors(monkeypatch):
    good = '''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>3</EventID>
    <TimeCreated SystemTime="2026-01-01"/></System>
    <EventData><Data Name="Hashes">SHA256=abc</Data>
    <Data Name="DestinationPort">3389</Data><Data Name="Image">plink.exe</Data></EventData></Event>'''
    class Record:
        def __init__(self, text): self.text = text
        def xml(self): return self.text
    class Log:
        def __init__(self, *args): pass
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def records(self): return [Record(good), Record("broken XML")]
    monkeypatch.setattr(audit.builder.evtx, "Evtx", Log)
    result = audit.raw_metadata(Path("fake.evtx"))
    assert result["has_hashes"] and result["has_timecreated"]
    assert result["raw_records"] == 2 and result["xml_errors"] == 1
    assert "destination port 3389" in result["content_signals"]


def test_out_of_scope_file_not_eligible(tmp_path):
    path = tmp_path / "Other" / "sample.evtx"
    path.parent.mkdir()
    path.write_bytes(b"inventory only")
    row = audit.audit_file(path, tmp_path, set(), {"1"}, {"1"})
    assert row["status"] == "out_of_scope"
    assert not row["qualifies_current"]
    assert row["events_kept_current"] is None


def test_cached_records_preserve_actual_builder_results(tmp_path):
    xml = '''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>3</EventID>
    <TimeCreated SystemTime="2026-01-01"/></System>
    <EventData><Data Name="Image">plink.exe</Data><Data Name="DestinationPort">3389</Data></EventData></Event>'''
    original = audit.builder.evtx.Evtx
    ids = audit.builder.KEEP_IDS
    parsed, errors, raw = audit.evaluate_decoded(tmp_path / "real-records.evtx",
        [audit.CachedRecord(xml) for i in range(35)], {"3"}, {"3"})
    assert parsed == {"current": (20, 35), "wide": (20, 35)}
    assert not errors and raw["raw_records"] == 35
    assert audit.builder.evtx.Evtx is original
    assert audit.builder.KEEP_IDS is ids
