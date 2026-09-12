import json

from asv.config import Config
from asv.llm import MockProvider, Router, parse_json

cfg = Config.load()


def test_parse_json_handles_fenced_and_wrapped_output():
    assert parse_json('{"a": 1}') == {"a": 1}
    assert parse_json('```json\n{"a": 2}\n```') == {"a": 2}
    assert parse_json('here you go: {"a": 3} thanks') == {"a": 3}
    assert parse_json("not json at all") is None
    assert parse_json("") is None


def test_mock_provider_is_deterministic():
    p = MockProvider()
    prompt = "id: V6\nstatic_precheck: true\n## FUNCTION UNDER AUDIT\nconsult();\n"
    a = p.complete("auditor", prompt, 0.7).text
    b = p.complete("auditor", prompt, 0.7).text
    assert a == b
    assert json.loads(a)["vuln_id"] == "V6"


def test_mock_respects_the_static_precheck():
    p = MockProvider()
    yes = json.loads(p.complete("auditor", "id: V1\nstatic_precheck: true\n", 0).text)
    no = json.loads(p.complete("auditor", "id: V1\nstatic_precheck: false\n", 0).text)
    assert yes["property_match"] is True
    assert no["property_match"] is False


def test_router_falls_back_to_mock_without_keys():
    r = Router(cfg, order=["mock"], cache=False)
    assert r.active == ["mock"]
    assert r.complete("s", "u", 0.0).ok


# --- regressions from the router / parser audit -----------------------------

def test_parse_json_survives_prose_around_the_object():
    """A greedy {.*} spanned from the first brace to the last and failed,
    which was then recorded as an abstention against the model."""
    from asv.llm import parse_json
    out = parse_json('Analysis {a note} then:\n'
                     '{"vuln_id":"V6","property_match":true,"confidence":0.8}')
    assert out is not None and out["vuln_id"] == "V6"


def test_parse_json_ignores_braces_inside_strings():
    from asv.llm import parse_json
    out = parse_json('x\n{"vuln_id":"V4","attack_path":"uses {braces} inside"}')
    assert out is not None and out["attack_path"] == "uses {braces} inside"


def test_parse_json_prefers_the_richest_object():
    from asv.llm import parse_json
    out = parse_json('{"a":1} then {"vuln_id":"V9","property_match":true,"confidence":0.7}')
    assert out is not None and out.get("vuln_id") == "V9"


def test_parse_json_returns_none_for_non_dict_and_empty():
    from asv.llm import parse_json
    assert parse_json("") is None
    assert parse_json("I cannot answer.") is None
    assert parse_json("[1,2,3]") is None


# --- a dead endpoint must never look like a model abstention ----------------
class _FakeResponse:
    def __init__(self, payload, status=200):
        self._payload, self.status_code, self.text = payload, status, json.dumps(payload)

    def json(self):
        return self._payload


def _fake_post(payload, status=200):
    def post(url, headers=None, json=None, timeout=None):   # noqa: A002
        return _FakeResponse(payload, status)
    return post


def test_an_empty_completion_is_reported_as_a_provider_error(monkeypatch):
    """HTTP 200 with no content is a transport failure, not an answer.

    Gemini 2.5 bills hidden thinking tokens against max_tokens and returns an
    EMPTY message with finish_reason='length' when the budget runs out. The
    empty string used to reach the caller with error='', where it was counted
    as the model declining to answer.
    """
    from asv.llm import OpenAICompatible
    import asv.llm as llm

    prov = OpenAICompatible("gemini", {"base_url": "https://x/v1", "default_model": "m"})
    prov.api_key = "k"
    monkeypatch.setattr(llm.requests, "post", _fake_post({
        "choices": [{"message": {"content": ""}, "finish_reason": "length"}],
        "usage": {"completion_tokens": 1400},
    }))
    resp = prov.complete("s", "u", 0.0, max_tokens=1400)
    assert not resp.ok
    assert "empty content" in resp.error and "length" in resp.error
    assert resp.finish_reason == "length"


def test_provider_extra_params_reach_the_payload(monkeypatch):
    from asv.llm import OpenAICompatible
    import asv.llm as llm

    seen = {}

    def post(url, headers=None, json=None, timeout=None):    # noqa: A002
        seen.update(json)
        return _FakeResponse({"choices": [{"message": {"content": '{"ok": true}'}}]})

    prov = OpenAICompatible("gemini", {"base_url": "https://x/v1", "default_model": "m",
                                       "extra_params": {"reasoning_effort": "none"}})
    prov.api_key = "k"
    monkeypatch.setattr(llm.requests, "post", post)
    assert prov.complete("s", "u", 0.0).ok
    assert seen["reasoning_effort"] == "none"


def test_router_counts_failures_and_keeps_the_last_error(monkeypatch):
    import asv.llm as llm

    r = Router(cfg, order=["mock"], cache=False)
    monkeypatch.setattr(r.providers[0], "complete",
                        lambda *a, **k: llm.LLMResponse("", "mock", "m", error="HTTP 401"))
    resp = r.complete("s", "u", 0.0)
    assert not resp.ok and r.errors == 1 and r.successes == 0
    assert r.last_error == "HTTP 401" and resp.error == "HTTP 401"
