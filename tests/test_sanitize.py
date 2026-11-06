"""Labels and source names never reach a classifier."""
import json
import pytest
import m2_fixtures  # noqa: F401
from soc import rules
from soc.sanitize import strip_alert
from m2_fixtures import ALERT


def test_strip_alert_keeps_only_model_fields():
    clean = strip_alert({**ALERT, "source_file": "CA_secret_dump.evtx"})
    assert set(clean) == {"alert_id", "host", "events"}


def test_embedded_metadata_is_rejected():
    leaky = {**ALERT, "source_file": "CA_secret_dump.evtx",
             "events": ALERT["events"] + [{"event_id": 1, "CommandLine": "copy CA_secret_dump.evtx"}]}
    with pytest.raises(ValueError):
        strip_alert(leaky)


def test_hidden_fields_do_not_change_rules_output():
    a = rules.classify({**ALERT, "label_tactic": "Execution"})
    b = rules.classify({**ALERT, "label_tactic": "Benign", "source_file": "x_other_name.evtx"})
    assert json.dumps(a) == json.dumps(b)
