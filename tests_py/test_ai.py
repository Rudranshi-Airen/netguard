"""AI-merge tests: no network.  Demo mode uses examples/ai_cache; the live path
is exercised with a fake model (and a fake urlopen for the HTTP request)."""

import io
import json
import os

import pytest

from conftest import EXAMPLES, binary_path

import ai
import app as webapp


def example(name):
    with open(os.path.join(EXAMPLES, name), encoding="utf-8") as f:
        return f.read()


FIXTURE_CACHE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "ai_cache")


@pytest.fixture
def client(monkeypatch):
    # Hand-written caches with a known wrong first attempt, independent of the
    # (re-recordable) real Gemini replies in examples/ai_cache/.
    monkeypatch.setattr(ai, "CACHE_DIR", FIXTURE_CACHE)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    webapp.app.config["TESTING"] = True
    with webapp.app.test_client() as c:
        yield c


def test_demo_rejects_then_accepts(client):
    r = client.post("/api/ai-merge", json={"source": example("firewall_anomalies.fw"), "syntax": "fw"}).get_json()
    assert r["ok"] and r["mode"] == "demo"
    assert "HAND-WRITTEN" in r["cache"]["provenance"]
    first, second = r["attempts"]
    assert first["parsed"] and first["equivalent"] is False
    cx = first["counterexample"]
    assert cx["text"] and first["action_original"] != first["action_suggested"]
    assert second["equivalent"] is True
    assert r["accepted"] is True
    assert (r["rules_before"], r["rules_after_optimizer"], r["rules_after_ai"]) == (10, 5, 4)
    assert r["final_text"] == second["text"]


def test_demo_counterexample_is_real(client):
    """The counterexample really separates the original from attempt 1."""
    r = client.post("/api/ai-merge", json={"source": example("firewall_anomalies.fw"), "syntax": "fw"}).get_json()
    pkt = r["attempts"][0]["counterexample"]["text"]
    orig = webapp.app.test_client().post("/api/classify", json={"source": example("firewall_anomalies.fw"),
                                                                 "syntax": "fw", "packet": pkt}).get_json()
    sugg = webapp.app.test_client().post("/api/classify", json={"source": r["attempts"][0]["text"],
                                                                 "syntax": "fw", "packet": pkt}).get_json()
    assert orig["decision"] == r["attempts"][0]["action_original"]
    assert sugg["decision"] == r["attempts"][0]["action_suggested"]
    assert orig["decision"] != sugg["decision"]


def test_demo_equivalent_but_not_fewer_is_not_accepted(client):
    r = client.post("/api/ai-merge", json={"source": example("tax.ng"), "syntax": "ng"}).get_json()
    assert r["attempts"][0]["equivalent"] is False
    assert r["attempts"][-1]["equivalent"] is True
    assert r["proven_equivalent"] is True and r["accepted"] is False
    assert r["final_text"] == r["optimizer_text"]


def test_demo_without_cache(client):
    resp = client.post("/api/ai-merge", json={"source": example("firewall_basic.fw"), "syntax": "fw"})
    assert resp.status_code == 422
    assert "GEMINI_API_KEY" in resp.get_json()["error"]


def test_bad_requests(client):
    assert client.post("/api/ai-merge", json={"syntax": "fw"}).status_code == 400
    assert client.post("/api/ai-merge", json={"source": "x", "syntax": "fw", "example": "../x"}).status_code == 400
    resp = client.post("/api/ai-merge", json={"source": example("errors.fw"), "syntax": "fw"})
    assert resp.status_code == 422 and resp.get_json()["diagnostics"]


GOOD = example("firewall_anomalies.fw")


def test_live_retry_feeds_back_counterexample_and_diagnostics():
    replies = [
        "ALLOW TCP FROM ANY TO ANY PORT 443\nALLOW UDP FROM ANY TO ANY PORT 53\nDEFAULT DENY\n",       # wrong
        "```\nALLOW TCP FROM ANY TO ANY PORT 443\nALOW UDP FROM ANY TO ANY PORT 53\n```",               # parse error
        "ALLOW TCP FROM ANY TO ANY PORT 443\nALLOW UDP FROM ANY TO ANY PORT 53\n"
        "ALLOW TCP FROM 192.168.0.0/16 TO ANY PORT 80-100\nALLOW TCP FROM ANY TO 172.16.0.0/24 PORT 8000-8100\n"
        "DEFAULT DENY\n",                                                                              # correct
    ]
    prompts = []

    def fake(prompt, key, model):
        assert key == "secret-key"
        prompts.append(prompt)
        return replies[len(prompts) - 1]

    r = ai.ai_merge(binary_path(), GOOD, "fw", api_key="secret-key", model="m", call=fake)
    assert r["mode"] == "live" and len(r["attempts"]) == 3
    assert [a["equivalent"] for a in r["attempts"]] == [False, False, True]
    assert r["attempts"][1]["parsed"] is False
    assert "Counterexample packet" in prompts[1] and r["attempts"][0]["counterexample"]["text"] in prompts[1]
    assert "Line 2, column 1" in prompts[2]
    assert "first match wins" in prompts[0].lower() and "ALLOW TCP FROM ANY TO ANY PORT 443" in prompts[0]
    assert r["accepted"] is True and r["rules_after_ai"] == 4
    assert "secret-key" not in json.dumps(r)


def test_live_failure_falls_back_to_demo(monkeypatch):
    monkeypatch.setattr(ai, "CACHE_DIR", FIXTURE_CACHE)

    def broken(prompt, key, model):
        raise ai.AIError("Gemini API not reachable (URLError)")

    r = ai.ai_merge(binary_path(), GOOD, "fw", api_key="k", call=broken)
    assert r["mode"] == "demo" and "not reachable" in r["fallback_reason"]
    assert r["accepted"] is True


def test_call_gemini_request_format(monkeypatch):
    seen = {}

    class Resp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_urlopen(req, timeout):
        seen["url"], seen["timeout"] = req.full_url, timeout
        seen["key"] = req.get_header("X-goog-api-key")
        seen["body"] = json.loads(req.data.decode())
        return Resp(json.dumps({"candidates": [{"content": {"parts": [{"text": "DEFAULT DENY"}]}}]}).encode())

    monkeypatch.setattr(ai.urllib.request, "urlopen", fake_urlopen)
    assert ai.call_gemini("hello", "KEY123", "gemini-3.5-flash", timeout=30) == "DEFAULT DENY"
    assert seen["url"] == "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.5-flash:generateContent"
    assert seen["key"] == "KEY123" and seen["timeout"] == 30
    assert seen["body"] == {"contents": [{"parts": [{"text": "hello"}]}], "generationConfig": {"temperature": 0.2}}


def test_strip_fences():
    assert ai.strip_fences("```fw\nDEFAULT DENY\n```") == "DEFAULT DENY\n"
    assert ai.strip_fences("DEFAULT DENY") == "DEFAULT DENY\n"


def test_call_gemini_retries_once_and_hides_key(monkeypatch):
    calls = []

    def flaky(req, timeout):
        calls.append(1)
        raise ai.urllib.error.HTTPError(req.full_url, 503, "busy", {}, io.BytesIO(
            b'{"error": {"message": "overloaded for KEY123"}}'))

    monkeypatch.setattr(ai.urllib.request, "urlopen", flaky)
    monkeypatch.setattr(ai.time, "sleep", lambda s: None)
    with pytest.raises(ai.AIError) as e:
        ai.call_gemini("hi", "KEY123", "m")
    assert len(calls) == 2 and "503" in str(e.value) and "KEY123" not in str(e.value)


def test_replay_recorded_reply_skips_the_api(monkeypatch):
    monkeypatch.setattr(ai, "CACHE_DIR", FIXTURE_CACHE)

    def must_not_call(prompt, key, model):
        raise AssertionError("the API must not be called when a recorded reply is replayed")

    r = ai.ai_merge(binary_path(), GOOD, "fw", api_key="k", call=must_not_call, prefer_cache=True)
    assert r["mode"] == "demo" and "requested" in r["fallback_reason"]
    assert r["attempts"][0]["equivalent"] is False and r["accepted"] is True
    assert r["cache"]["real"] is False


def test_replay_without_recording_calls_the_api(monkeypatch, tmp_path):
    monkeypatch.setattr(ai, "CACHE_DIR", str(tmp_path))
    replies = ["DEFAULT DENY\n"]
    r = ai.ai_merge(binary_path(), "DENY TCP FROM ANY TO ANY PORT 22\nDEFAULT DENY\n", "fw", api_key="k",
                    call=lambda p, k, m: replies[0], prefer_cache=True)
    assert r["mode"] == "live" and r["attempts"][0]["equivalent"] is True


def test_recorded_caches_are_valid_and_labelled():
    """Every cache in examples/ai_cache names its provenance and re-proves cleanly."""
    for f in sorted(os.listdir(ai.CACHE_DIR)):
        c = json.load(open(os.path.join(ai.CACHE_DIR, f), encoding="utf-8"))
        assert c["provenance"].startswith(("REAL Gemini reply", "HAND-WRITTEN")), f
        assert c["attempts"] and os.path.isfile(os.path.join(EXAMPLES, c["example"])), f
