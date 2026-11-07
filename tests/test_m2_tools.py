"""Milestone 2: the four mocked tools and their leakage guard."""
from m2_fixtures import ALERT, CONTEXT
import pytest
from soc.tools import ToolBox, ToolError


def test_get_more_logs_numbers_new_events_after_the_alert():
    box = ToolBox(ALERT, CONTEXT)
    out = box.call("get_more_logs", {"event_id": 3})
    assert out["events"][0]["index"] == 2 and box.fetched[2]["DestinationPort"] == "4444"
    assert box.call("get_more_logs", {"event_id": 3})["events"][0]["index"] == 2


def test_tools_refuse_to_return_metadata():
    box = ToolBox(ALERT, [{"event_id": 1, "CommandLine": "run exec_secret_capture"}], forbidden=("exec_secret_capture",))
    with pytest.raises(ToolError):
        box.call("get_more_logs", {})


def test_lookup_ioc_and_asset():
    box = ToolBox(ALERT, [])
    assert any(r["id"] == "T1202" for r in box.call("lookup_technique", {"query": "pcalua.exe"})["results"])
    assert box.call("check_ioc", {"indicator": "C:\\tools\\mimikatz.exe"})["verdict"] == "known_bad"
    assert box.call("check_ioc", {"indicator": "notepad.exe"})["verdict"] == "unknown"
    assert box.call("get_asset_context", {"host": "HOST-01"})["criticality"] == "critical"
    with pytest.raises(ToolError):
        box.call("get_asset_context", {"host": "NOPE"})


def test_lookup_ignores_generic_words_and_numbers():
    box = ToolBox(ALERT, [])
    assert box.call("lookup_technique", {"query": "destination port 62053"})["results"] == []
