"""Clients for hosted models (Gemini free tier, OpenAI) with the same chat() interface and cache as OllamaLLM.

Keys come from an environment variable or a KEY=... line in .env (.env is git-ignored); they are never logged.
Calls are spaced out to stay under each provider's per-minute limit.
"""
import hashlib, json, os, re, time, urllib.error, urllib.request
from pathlib import Path
from .local_llm import LLMError, StopRun

URL = "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"


def api_key(name="GEMINI_API_KEY"):
    if os.environ.get(name):
        return os.environ[name].strip()
    env = Path(".env")
    if env.exists():
        for line in env.read_text().splitlines():
            if line.startswith(name + "="):
                return line.split("=", 1)[1].strip().strip('"')
    raise StopRun(f"no key: set {name} or add {name}=... to .env")


class GeminiLLM:
    URL, KEY, PROVIDER, SEED = URL, "GEMINI_API_KEY", "gemini", False

    def __init__(self, model="gemini-3.5-flash", cache_dir="outputs/llm_cache", per_minute=4, timeout=120):
        self.model, self.timeout, self.key = model, timeout, api_key(self.KEY)
        self.options = {"temperature": 0, "provider": self.PROVIDER}
        if self.SEED:
            self.options["seed"] = 0
        self.gap, self.last = 60 / per_minute, 0.0
        self.cache = Path(cache_dir) if cache_dir else None
        if self.cache:
            self.cache.mkdir(parents=True, exist_ok=True)

    def before_send(self):
        pass

    def chat(self, messages, json_mode=True):
        body = {"model": self.model, "messages": messages, "temperature": 0}
        if self.SEED:
            body["seed"] = 0
        if json_mode:
            body["response_format"] = {"type": "json_object"}
        key = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
        path = self.cache / f"{key}.json" if self.cache else None
        if path and path.exists():
            saved = json.loads(path.read_text())
            return saved["text"], {**saved["usage"], "cache_hit": True}
        self.before_send()
        req = urllib.request.Request(self.URL, data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json", "Authorization": f"Bearer {self.key}"})
        start = time.time()
        for attempt in range(6):
            time.sleep(max(0.0, self.last + self.gap - time.time()))
            self.last = time.time()
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    data = json.loads(resp.read())
                break
            except urllib.error.HTTPError as exc:
                detail = exc.read().decode("utf-8", "replace")
                if exc.code == 429 and re.search(r"PerDay|per day|daily", detail, re.I):
                    raise StopRun(f"{self.PROVIDER} daily quota used up; rerun the same command tomorrow (finished calls are cached)")
                if exc.code in (400, 401, 403, 404) or "insufficient_quota" in detail:
                    raise StopRun(f"{self.PROVIDER} refused the request (HTTP {exc.code}): {detail[:200]}")
                if exc.code not in (429, 500, 503) or attempt == 5:
                    raise LLMError(f"{self.PROVIDER} HTTP {exc.code}: {detail[:400]}") from exc
                time.sleep(65 if exc.code == 429 else 15)  # a per-minute limit resets within a minute
            except (urllib.error.URLError, TimeoutError) as exc:
                if attempt == 5:
                    raise LLMError(f"{self.PROVIDER} unreachable: {exc}") from exc
                time.sleep(10)
        text = data["choices"][0]["message"]["content"] or ""
        text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text.strip())
        u = data.get("usage") or {}
        usage = {"prompt_tokens": u.get("prompt_tokens", 0), "completion_tokens": u.get("completion_tokens", 0),
                 "seconds": round(time.time() - start, 2)}
        if path:
            path.write_text(json.dumps({"text": text, "usage": usage}))
        return text, {**usage, "cache_hit": False}


class OpenAILLM(GeminiLLM):
    """gpt-4o-mini, the model Prem's Milestone 1 baseline used, called with exactly his settings
    (temperature 0, JSON mode, no seed). Every paid call is added to a running spend file, and the run
    stops before the total passes the cap (cached replies cost nothing)."""
    URL, KEY, PROVIDER, SEED = "https://api.openai.com/v1/chat/completions", "OPENAI_API_KEY", "openai", False
    PRICE = {"gpt-4o-mini": (0.15, 0.60)}  # USD per million input / output tokens

    def __init__(self, model="gpt-4o-mini", cache_dir="outputs/llm_cache", per_minute=200, timeout=120,
                 cap_usd=3.0, spend_file="outputs/openai_spend.json"):
        if model not in self.PRICE:
            raise StopRun(f"no price on file for {model}; add it to OpenAILLM.PRICE first")
        super().__init__(model, cache_dir, per_minute, timeout)
        self.cap, self.spend_file = cap_usd, Path(spend_file)

    def spent(self):
        return json.loads(self.spend_file.read_text())["usd"] if self.spend_file.exists() else 0.0

    def before_send(self):
        if self.spent() >= self.cap:
            raise StopRun(f"spending cap reached (${self.spent():.2f} of ${self.cap:.2f}); nothing more was sent")

    def chat(self, messages, json_mode=True):
        text, usage = super().chat(messages, json_mode)
        if not usage.get("cache_hit"):
            price_in, price_out = self.PRICE[self.model]
            cost = (usage["prompt_tokens"] * price_in + usage["completion_tokens"] * price_out) / 1e6
            total = self.spent() + cost
            self.spend_file.parent.mkdir(parents=True, exist_ok=True)
            self.spend_file.write_text(json.dumps({"usd": round(total, 6), "cap": self.cap}))
        return text, usage
