"""Milestone 2: blocking verifier, policy table and the finalize() fix."""
from m2_fixtures import ALERT, GOOD
from soc.schema import decide, finalize
from soc.verifier import check, hard_signals


def test_verifier_catches_bad_citations_and_quotes():
    events = {0: ALERT["events"][0], 1: ALERT["events"][1]}
    draft = {**GOOD, "evidence": [0, 9], "claims": [{"text": "x", "evidence": [0], "quotes": ["mimikatz"]}]}
    errors = check(draft, events)
    assert any("do not exist" in e for e in errors) and any("not in the cited events" in e for e in errors)
    assert check({**GOOD, "evidence": [0], "claims": GOOD["claims"][:1]}, events) == []


def test_policy_and_finalize_fix():
    assert decide("malicious", "Discovery", "critical") == ("medium", "investigate", True)
    assert decide("malicious", "Credential Access", "critical") == ("critical", "escalate_tier2", False)
    assert decide("malicious", "Discovery", None, uncertain=True)[1] == "escalate_tier2"
    rec = finalize("X", "malicious", "Made Up", [], "")
    assert rec["action"] == "escalate_tier2" and rec["uncertain"]


def test_quotes_may_include_the_field_name():
    events = {0: ALERT["events"][0]}
    claim = {"text": "pcalua ran", "evidence": [0],
             "quotes": ["Image: C:\\Windows\\System32\\pcalua.exe", "'pcalua.exe -a calc.exe'"]}
    assert check({**GOOD, "evidence": [0], "claims": [claim]}, events) == []


LSASS_DUMP = {0: {"event_id": 1, "Image": "C:\\Windows\\System32\\rdrleakdiag.exe", "CommandLine": "rdrleakdiag.exe /p 668 /fullmemdmp"},
              1: {"event_id": 8, "SourceImage": "C:\\Windows\\System32\\rdrleakdiag.exe", "TargetImage": "C:\\Windows\\System32\\lsass.exe"}}
BENIGN = {**GOOD, "verdict": "benign", "tactics": ["Benign"], "evidence": [0],
          "claims": [{"text": "a Windows diagnostic tool", "evidence": [0], "quotes": ["rdrleakdiag.exe /p 668 /fullmemdmp"]}]}


def test_benign_is_blocked_by_hard_signals_unless_flagged_uncertain():
    signals = hard_signals(LSASS_DUMP)
    assert signals and "rdrleakdiag.exe opened lsass.exe" in signals[0]
    assert any("conflicts with" in e for e in check(BENIGN, LSASS_DUMP, None, signals))
    assert check({**BENIGN, "uncertain": True}, LSASS_DUMP, None, signals) == []


def test_defender_reading_lsass_is_not_a_hard_signal():
    av = {0: {"event_id": 10, "SourceImage": "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18\\MsMpEng.exe",
              "TargetImage": "C:\\Windows\\system32\\lsass.exe", "GrantedAccess": "0x1410"}}
    assert hard_signals(av) == []
    assert hard_signals({0: {"event_id": 1, "CommandLine": "mimikatz sekurlsa::logonpasswords"}})
