"""Minimal client for a local Ollama server, with an on-disk response cache."""
import hashlib, json, time, urllib.error, urllib.request
from pathlib import Path


class LLMError(Exception):
    pass


class StopRun(Exception):
    """A problem no retry will fix (missing key, daily quota): stop the whole run instead of escalating alerts."""


class OllamaLLM:
    def __init__(self, model="qwen2.5:7b", base_url="http://localhost:11434",
                 cache_dir="outputs/llm_cache", num_ctx=16384, timeout=300):
        self.model, self.base_url, self.timeout = model, base_url.rstrip("/"), timeout
        self.options = {"temperature": 0, "seed": 0, "num_ctx": num_ctx}
        self.cache = Path(cache_dir) if cache_dir else None
        if self.cache:
            self.cache.mkdir(parents=True, exist_ok=True)

    def chat(self, messages, json_mode=True):
        body = {"model": self.model, "messages": messages, "stream": False, "options": self.options}
        if json_mode:
            body["format"] = "json"
        key = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
        path = self.cache / f"{key}.json" if self.cache else None
        if path and path.exists():
            saved = json.loads(path.read_text())
            return saved["text"], {**saved["usage"], "cache_hit": True}
        start = time.time()
        req = urllib.request.Request(f"{self.base_url}/api/chat", data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json"})
        for attempt in range(3):
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    data = json.loads(resp.read())
                break
            except (urllib.error.HTTPError, TimeoutError) as exc:
                if attempt == 2:
                    raise LLMError(f"Ollama failed three times: {exc}") from exc
                time.sleep(5 * (attempt + 1))
        text = data["message"]["content"]
        usage = {"prompt_tokens": data.get("prompt_eval_count", 0),
                 "completion_tokens": data.get("eval_count", 0),
                 "seconds": round(time.time() - start, 2)}
        if path:
            path.write_text(json.dumps({"text": text, "usage": usage}))
        return text, {**usage, "cache_hit": False}
