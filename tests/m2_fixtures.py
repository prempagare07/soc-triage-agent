"""Shared fixtures for the Milestone 2 tests."""
import json, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

ALERT = {"alert_id": "T001", "host": "HOST-08", "label_tactic": "Execution", "label_verdict": "malicious",
         "events": [{"event_id": 1, "Image": "C:\\Windows\\System32\\pcalua.exe", "CommandLine": "pcalua.exe -a calc.exe",
                     "ParentImage": "C:\\Windows\\System32\\cmd.exe"},
                    {"event_id": 1, "Image": "C:\\Windows\\System32\\calc.exe", "ParentImage": "C:\\Windows\\System32\\pcalua.exe"}]}
CONTEXT = [{"event_id": 11, "TargetFilename": "C:\\Users\\a\\payload.dll"},
           {"event_id": 3, "Image": "C:\\Windows\\System32\\calc.exe", "DestinationIp": "10.0.0.5", "DestinationPort": "4444"}]


class FakeLLM:
    """Scripted model. `first_pass`, if given, answers the agent's quick first decision without using the script."""
    def __init__(self, replies, first_pass=None):
        self.replies, self.seen, self.first_pass = list(replies), [], first_pass

    def chat(self, messages, json_mode=True):
        self.seen.append(messages[-1]["content"])
        if self.first_pass is not None and messages[0]["content"].startswith("You are a tier-1 SOC analyst triaging"):
            return json.dumps(self.first_pass), {"prompt_tokens": 10, "completion_tokens": 5, "seconds": 0.1}
        r = self.replies.pop(0)
        return (r if isinstance(r, str) else json.dumps(r)), {"prompt_tokens": 10, "completion_tokens": 5, "seconds": 0.1}


GOOD = {"action": "submit", "verdict": "malicious", "tactics": ["Execution", "Defense Evasion"], "evidence": [0, 2],
        "claims": [{"text": "pcalua launched calc", "evidence": [0], "quotes": ["pcalua.exe -a calc.exe"]},
                   {"text": "calc called out on 4444", "evidence": [2], "quotes": ["4444"]}],
        "note": {"what": "pcalua.exe ran calc.exe", "why": "proxy execution (0) and odd connection (2)", "next": "isolate"},
        "uncertain": False}

