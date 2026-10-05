"""Isolated, single-alert classification through subscription-authenticated Codex."""
import hashlib
import json
import os
import re
from pathlib import Path
import subprocess
import tempfile

from .llm import SYSTEM
from .sanitize import strip_alert
from .schema import TACTICS, finalize, validate

ROOT = Path(__file__).resolve().parents[1]


def code_hashes():
    return {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
            for name in ("soc/codex_cli.py", "soc/sanitize.py", "soc/schema.py", "soc/llm.py")}

OUTPUT_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "properties": {
        "verdict": {"type": "string", "enum": ["malicious", "benign"]},
        "tactic": {"type": "string", "enum": TACTICS},
        "evidence": {"type": "array", "items": {"type": "integer", "minimum": 0}},
        "analyst_note": {"type": "string"},
    },
    "required": ["verdict", "tactic", "evidence", "analyst_note"],
}
DISABLED = ["shell_tool", "unified_exec", "apps", "plugins", "remote_plugin",
            "multi_agent", "multi_agent_v2", "browser_use", "computer_use",
            "image_generation", "view_image", "code_mode", "code_mode_host",
            "skill_search", "skill_mcp_dependency_install", "shell_snapshot",
            "hooks", "memories", "sleep_tool", "artifact", "tool_suggest"]
CONFIG = ["forced_login_method=\"chatgpt\"", "web_search=\"disabled\"",
          "mcp_servers={}", "project_doc_max_bytes=0", "personality=\"none\"",
          "features.skip_host_skill_discovery=true"]


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def redact_diagnostic(message):
    """Retain CLI diagnostics without persisting known credentials."""
    text = str(message)
    for name, value in os.environ.items():
        if len(value) >= 8 and any(word in name.upper() for word in ("TOKEN", "SECRET", "PASSWORD", "API_KEY")):
            text = text.replace(value, "[REDACTED]")
    text = re.sub(r"(?i)Bearer\s+\S+", "Bearer [REDACTED]", text)
    text = re.sub(r"\bsk-[A-Za-z0-9_-]+", "[REDACTED]", text)
    text = re.sub(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "[REDACTED]", text)
    return text[:2000]


class CodexError(RuntimeError):
    pass


class Classifier:
    def __init__(self, model, effort="medium", timeout=180, cache_dir=None, executable="codex"):
        self.model, self.effort, self.timeout = model, effort, timeout
        self.cache_dir = Path(cache_dir) if cache_dir else None
        self.executable = executable
        self.version = subprocess.run([executable, "--version"], capture_output=True,
                                      text=True, check=True, timeout=15).stdout.strip()
        self.configuration = {"config": CONFIG, "disabled_features": DISABLED,
                              "sandbox": "read-only", "ignore_user_config": True,
                              "ignore_rules": True, "ephemeral": True,
                              "model": model, "reasoning_effort": effort,
                              "stdin": "host and indexed events only",
                              "output": "JSON schema + final response file",
                              "removed_environment_keys": ["OPENAI_API_KEY", "CODEX_API_KEY"]}
        self.last_metadata = {}

    def classify(self, alert):
        alert = strip_alert(alert)
        events = [{**ev, "index": i} for i, ev in enumerate(alert["events"])]
        payload = {"host": alert["host"], "events": events}
        request = {"payload": payload, "instructions": SYSTEM, "schema": OUTPUT_SCHEMA,
                   "configuration": self.configuration, "cli_version": self.version,
                   "code_sha256": code_hashes()}
        key = digest(request)
        self.last_metadata = {"request_sha256": key, "cache_hit": False, "retries": 0,
                              "attempted": False,
                              "usage": None, "actual_model": None, "effective_effort": None}
        cache = self.cache_dir / f"{key}.json" if self.cache_dir else None
        if cache and cache.exists():
            saved = json.loads(cache.read_text())
            result = self._parse(saved["response"], alert)
            self.last_metadata.update(saved["metadata"], cache_hit=True, attempted=False)
            self.last_metadata["raw_response"] = saved["response"]
            return result
        with tempfile.TemporaryDirectory(prefix="soc-codex-") as directory:
            root = Path(directory)
            instructions, schema, response = root / "instructions.txt", root / "schema.json", root / "response.json"
            instructions.write_text(SYSTEM)
            schema.write_text(json.dumps(OUTPUT_SCHEMA))
            command = [self.executable, "exec", "--ignore-user-config", "--ignore-rules",
                       "--ephemeral", "--skip-git-repo-check", "--sandbox", "read-only",
                       "--cd", directory, "--model", self.model, "--json",
                       "--output-schema", str(schema), "--output-last-message", str(response)]
            for setting in CONFIG + [f'model_reasoning_effort="{self.effort}"',
                                     f'model_instructions_file={json.dumps(str(instructions))}']:
                command.extend(["-c", setting])
            for feature in DISABLED:
                command.extend(["--disable", feature])
            command.append("-")
            self.last_metadata["cli_arguments"] = [
                value.replace(directory, "<isolated_directory>") for value in command[1:]]
            env = dict(os.environ)
            for name in ("OPENAI_API_KEY", "CODEX_API_KEY"):
                env.pop(name, None)
            try:
                self.last_metadata["attempted"] = True
                run = subprocess.run(command, input=json.dumps(payload), text=True,
                                     capture_output=True, cwd=directory, env=env, timeout=self.timeout)
            except subprocess.TimeoutExpired as exc:
                raise CodexError(f"Codex timed out after {self.timeout}s") from exc
            except OSError as exc:
                raise CodexError("Could not start Codex CLI") from exc
            if run.returncode:
                # Do not copy arbitrary stderr into result files: it may contain local context.
                if "failed to initialize in-process app-server client: Operation not permitted" in run.stderr:
                    raise CodexError("Sandbox blocked initialization of the in-process app-server (Operation not permitted)")
                raise CodexError(f"Codex exited with status {run.returncode}; check login and CLI configuration")
            completed = False
            failed_turn = False
            event_types, item_types, rejected_types = set(), set(), set()
            diagnostics = []
            def safe_type(value):
                return value if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", value) else "invalid_type"
            for line in run.stdout.splitlines():
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                event_types.add(safe_type(event.get("type")))
                if event.get("type") in ("turn.failed", "error"):
                    failed_turn = True
                item = event.get("item", {})
                item_type = item.get("type")
                if item_type is not None:
                    item_types.add(safe_type(item_type))
                if item_type == "error":
                    # A diagnostic item is not an executed tool. A fatal turn
                    # remains a failure via exit status / turn.failed / error.
                    diagnostics.append({"type": "error", "message": redact_diagnostic(
                        item.get("message", "CLI diagnostic without a message"))})
                if item_type not in (None, "agent_message", "reasoning", "error"):
                    rejected_types.add(safe_type(item_type))
                if event.get("type") == "turn.completed":
                    completed = True
                    self.last_metadata["usage"] = event.get("usage")
            # Never save tool arguments/results or arbitrary event bodies.
            # Diagnostic messages are redacted; retain usage on rejection.
            self.last_metadata.update(event_types=sorted(event_types), item_types=sorted(item_types),
                                      rejected_item_types=sorted(rejected_types), diagnostics=diagnostics)
            if rejected_types:
                raise CodexError("Tool activity detected; classification rejected (item types: " +
                                 ", ".join(sorted(rejected_types)) + ")")
            if failed_turn:
                raise CodexError("Codex reported a failed turn")
            if not completed or not response.exists():
                raise CodexError("Codex did not complete with a final response")
            raw = response.read_text()
            result = self._parse(raw, alert)
            self.last_metadata["raw_response"] = raw
        if cache:
            cache.parent.mkdir(parents=True, exist_ok=True)
            cache.write_text(json.dumps({"response": raw, "metadata": self.last_metadata}, indent=2))
        return result

    @staticmethod
    def _parse(raw, alert):
        try:
            data = json.loads(raw)
            if set(data) != set(OUTPUT_SCHEMA["required"]):
                raise ValueError("unexpected response keys")
            if data["verdict"] not in ("benign", "malicious") or data["tactic"] not in TACTICS:
                raise ValueError("invalid classification")
            if not isinstance(data["analyst_note"], str) or not isinstance(data["evidence"], list):
                raise ValueError("invalid note or evidence")
            if any(type(i) is not int or not 0 <= i < len(alert["events"]) for i in data["evidence"]):
                raise ValueError("evidence index outside alert")
            result = finalize(alert["alert_id"], data["verdict"], data["tactic"],
                              data["evidence"], data["analyst_note"])
            validate(result)
            return result
        except (ValueError, TypeError, KeyError) as exc:
            raise CodexError(f"Invalid classification JSON: {exc}") from exc
