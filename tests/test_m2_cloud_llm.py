"""Milestone 2: hosted-model clients (Gemini free tier, OpenAI) and the OpenAI spending cap."""
from m2_fixtures import ALERT  # noqa: F401  (puts the repo on sys.path)


def test_gemini_client_parses_caches_and_stops_on_daily_quota(tmp_path, monkeypatch):
    import io, urllib.error, pytest
    from soc import cloud_llm as gemini_llm
    from soc.local_llm import StopRun
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    replies = [b'{"choices": [{"message": {"content": "```json\\n{\\"a\\": 1}\\n```"}}], "usage": {"prompt_tokens": 7, "completion_tokens": 2}}']

    def fake_open(req, timeout):
        assert req.headers["Authorization"] == "Bearer test-key"
        if not replies:
            raise urllib.error.HTTPError(req.full_url, 429, "x", {}, io.BytesIO(b"Quota exceeded: GenerateRequestsPerDay"))
        return io.BytesIO(replies.pop())
    monkeypatch.setattr(gemini_llm.urllib.request, "urlopen", fake_open)
    llm = gemini_llm.GeminiLLM(cache_dir=tmp_path, per_minute=6000)
    text, usage = llm.chat([{"role": "user", "content": "hi"}])
    assert text == '{"a": 1}' and usage["prompt_tokens"] == 7
    assert llm.chat([{"role": "user", "content": "hi"}])[1]["cache_hit"]
    with pytest.raises(StopRun):
        llm.chat([{"role": "user", "content": "new"}])


def test_openai_client_matches_prem_settings_and_uses_its_own_key(tmp_path, monkeypatch):
    import io, json as js
    from soc import cloud_llm
    monkeypatch.setenv("OPENAI_API_KEY", "oa-test")
    sent = {}

    def fake_open(req, timeout):
        sent.update(js.loads(req.data), auth=req.headers["Authorization"], url=req.full_url)
        return io.BytesIO(b'{"choices": [{"message": {"content": "{}"}}], "usage": {"prompt_tokens": 3, "completion_tokens": 1}}')
    monkeypatch.setattr(cloud_llm.urllib.request, "urlopen", fake_open)
    llm = cloud_llm.OpenAILLM(cache_dir=tmp_path, per_minute=6000, cap_usd=1e-6, spend_file=tmp_path / "spend.json")
    llm.chat([{"role": "user", "content": "x"}])
    assert sent["model"] == "gpt-4o-mini" and "seed" not in sent and sent["auth"] == "Bearer oa-test"
    assert sent["temperature"] == 0 and sent["response_format"] == {"type": "json_object"}
    assert sent["url"].startswith("https://api.openai.com/") and llm.spent() > 0
    assert llm.chat([{"role": "user", "content": "x"}])[1]["cache_hit"]  # over the cap, but cached replies are free
    import pytest
    from soc.local_llm import StopRun
    with pytest.raises(StopRun):
        llm.chat([{"role": "user", "content": "new question"}])
