"""Single-call and fixed-workflow baselines, on the same local model as the agent."""
import json, time
from .llm import SYSTEM
from .schema import finalize
from .sanitize import strip_alert
from .tools import ToolBox, ToolError, playbook, rule_hits
from .local_llm import StopRun


def _ask(llm, messages):
    """One request, retried once on invalid JSON."""
    usage_total = {"prompt_tokens": 0, "completion_tokens": 0, "seconds": 0.0, "llm_calls": 0}
    for _ in range(2):
        try:
            text, usage = llm.chat(messages)
        except StopRun:
            raise
        except Exception:
            return None, usage_total
        for k in ("prompt_tokens", "completion_tokens", "seconds"):
            usage_total[k] += usage.get(k, 0)
        usage_total["llm_calls"] += 1
        try:
            d = json.loads(text)
            if isinstance(d, dict):
                return d, usage_total
        except ValueError:
            pass
    return None, usage_total


def _record(alert_id, d, n_events, usage, start, extra=None):
    if d is None:
        rec = finalize(alert_id, "malicious", None, [], "")
        rec["parse_failure"] = True
    else:
        verdict = str(d.get("verdict", "malicious")).strip().lower()
        verdict = verdict if verdict in ("malicious", "benign") else "malicious"
        evidence = [int(i) for i in d.get("evidence", []) if str(i).isdigit() and int(i) < n_events]
        rec = finalize(alert_id, verdict, d.get("tactic"), evidence, d.get("analyst_note", ""))
    rec["usage"] = {**usage, "seconds_total": round(time.time() - start, 2)}
    if extra:
        rec.update(extra)
    return rec


def single_call(alert, llm):
    alert, start = strip_alert(alert), time.time()
    events = [{"index": i, **ev} for i, ev in enumerate(alert["events"])]
    messages = [{"role": "system", "content": SYSTEM},
                {"role": "user", "content": json.dumps({"host": alert["host"], "events": events})}]
    d, usage = _ask(llm, messages)
    return _record(alert["alert_id"], d, len(events), usage, start)


def fixed_workflow(alert, llm, context_events, forbidden=()):
    alert, start = strip_alert(alert), time.time()
    tools = ToolBox(alert, context_events, forbidden)
    observations, errors = [], 0
    for name, args in playbook(alert):
        try:
            observations.append({"tool": name, "args": args, "result": tools.call(name, args)})
        except ToolError as exc:
            errors += 1
            observations.append({"tool": name, "args": args, "error": str(exc)})
    events = [{"index": i, **ev} for i, ev in enumerate(alert["events"])]
    messages = [{"role": "system", "content": SYSTEM},
                {"role": "user", "content": json.dumps({"host": alert["host"], "rule_hits": rule_hits(alert["events"]),
                 "events": events, "extra_context_from_tools": observations})}]
    d, usage = _ask(llm, messages)
    n = len(events) + len(tools.fetched)
    return _record(alert["alert_id"], d, n, usage, start,
                   {"agent": {"tool_calls": len(observations), "tool_errors": errors}})
