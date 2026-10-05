"""Keep evaluation labels outside classifier inputs."""
from copy import deepcopy
import re


def _check_content(value, forbidden):
    if isinstance(value, dict):
        for key, child in value.items():
            _check_content(key, forbidden)
            _check_content(child, forbidden)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _check_content(child, forbidden)
    elif isinstance(value, str):
        if any(token in value.casefold() for token in forbidden):
            # Do not echo the offending value into logs or model input.
            raise ValueError("Evaluation metadata embedded in classifier input")


def strip_alert(alert):
    """Copy the classifier fields; reject recognizable nested label leakage.

    Keep actual event fields and their order intact. Arbitrary semantic hints
    cannot be detected universally; dataset construction also needs an audit.
    """
    forbidden = {"source_file", "label_tactic", "label_verdict", "evtx-attack-samples"}
    source = alert.get("source_file")
    if isinstance(source, str) and source:
        filename = re.split(r"[/\\]", source)[-1]
        forbidden.update(token.casefold() for token in
                         (source, filename, filename.rsplit(".", 1)[0]) if token)
    result = deepcopy({key: alert[key] for key in ("alert_id", "host", "events")})
    _check_content(result, forbidden)
    return result
