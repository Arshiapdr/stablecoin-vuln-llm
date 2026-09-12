"""Provider-agnostic LLM client with cascading fallback, caching and a
deterministic offline mock.

All hosted providers used here expose an OpenAI-compatible /chat/completions
endpoint, so one implementation covers Gemini, Mistral, NVIDIA NIM, OpenRouter,
Groq and a local llama.cpp server. If a provider is rate-limited or missing a
key, the router moves to the next one and records which model answered.
"""
from __future__ import annotations

import hashlib
import json
import os
import random
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

import requests


@dataclass
class LLMResponse:
    text: str
    provider: str
    model: str
    cached: bool = False
    latency_s: float = 0.0
    error: str = ""
    finish_reason: str = ""

    @property
    def ok(self) -> bool:
        return bool(self.text) and not self.error


class RateLimited(Exception):
    pass


# ---------------------------------------------------------------------------
class OpenAICompatible:
    def __init__(self, name: str, spec: dict, timeout: int = 120):
        self.name = name
        self.spec = spec
        self.base_url = (spec.get("base_url") or "").rstrip("/")
        self.model = spec.get("default_model", "")
        self.timeout = timeout
        env = spec.get("api_key_env")
        self.api_key = os.getenv(env, "") if env else ""

    @property
    def available(self) -> bool:
        if self.name == "local":
            return True                      # llama-server needs no key
        return bool(self.api_key and self.base_url)

    def complete(self, system: str, user: str, temperature: float,
                 model: str | None = None, max_tokens: int = 1400) -> LLMResponse:
        url = f"{self.base_url}/chat/completions"
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        payload = {
            "model": model or self.model,
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": user}],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        # Per-provider knobs from models.yaml, e.g. `extra_params: {reasoning_effort: none}`
        # to stop a reasoning model from spending the whole output budget on
        # hidden thinking tokens and returning an empty message.
        payload.update(self.spec.get("extra_params") or {})
        t0 = time.time()
        r = requests.post(url, headers=headers, json=payload, timeout=self.timeout)
        if r.status_code in (429, 503, 529):
            raise RateLimited(f"{self.name}: HTTP {r.status_code}")
        if r.status_code >= 400:
            return LLMResponse("", self.name, payload["model"],
                               error=f"HTTP {r.status_code}: {r.text[:200]}")
        data = r.json()
        try:
            choice = data["choices"][0]
            text = choice["message"]["content"] or ""
        except (KeyError, IndexError):
            return LLMResponse("", self.name, payload["model"],
                               error=f"unexpected response: {str(data)[:200]}")
        finish = str(choice.get("finish_reason") or "")
        if not text.strip():
            # HTTP 200 with an empty message. The usual cause is a reasoning
            # model spending the entire `max_tokens` budget on thinking tokens
            # (finish_reason="length"), which returns no visible content at all.
            # Reported as an explicit provider error: an empty string that
            # reaches the caller silently is later miscounted as the MODEL
            # abstaining, which is a claim about the model rather than about
            # the transport.
            usage = data.get("usage") or {}
            return LLMResponse("", self.name, payload["model"], finish_reason=finish,
                               error=(f"empty content (finish_reason={finish or 'none'}, "
                                      f"max_tokens={max_tokens}, usage={usage})"))
        return LLMResponse(text, self.name, payload["model"], finish_reason=finish,
                           latency_s=round(time.time() - t0, 2))


class MockProvider:
    """Deterministic offline backend.

    It is NOT a language model. It applies the knowledge base's own static
    rules and emits the same JSON shape a model would. Two uses:
      * CI and dry runs with no network and no account;
      * the "structure without an LLM" ablation baseline in the evaluation.
    """
    name = "mock"

    def __init__(self, spec: dict | None = None, timeout: int = 0):
        self.spec = spec or {}
        self.model = "deterministic-rule-mock"

    available = True

    def complete(self, system: str, user: str, temperature: float,
                 model: str | None = None, max_tokens: int = 1400) -> LLMResponse:
        if '"correctness"' in system or "adversarial reviewer" in system.lower():
            return LLMResponse(json.dumps({
                "correctness": 7, "severity": 6, "profitability": 5,
                "verdict": "confirmed",
                "rebuttal": "mock critic: accepted on static evidence alone",
            }), self.name, self.model)

        vuln_id = _extract(user, r"^id:\s*(V\d+)", "V1")
        code = _section(user, "## FUNCTION UNDER AUDIT")
        must_call = re.findall(r'must_call_hint:\s*(.+)', user)
        # the caller injects the resolved static verdict as a hint line
        verdict = "true" in _extract(user, r"static_precheck:\s*(\w+)", "false").lower()
        seed = int(hashlib.sha256((vuln_id + code[:200]).encode()).hexdigest()[:8], 16)
        rnd = random.Random(seed)
        return LLMResponse(json.dumps({
            "vuln_id": vuln_id,
            "scenario_match": verdict,
            "property_match": verdict,
            "confidence": round(0.55 + 0.35 * rnd.random(), 2) if verdict else 0.05,
            "key_variables": (must_call[0].split(",")[:3] if must_call else []),
            "vulnerable_statements": [code.strip().splitlines()[0][:120]] if code.strip() else [],
            "attack_path": ("mock: static preconditions for this class are all satisfied "
                            "in this function") if verdict else "",
            "severity": "high" if verdict else "low",
        }), self.name, self.model)


def _extract(text: str, pattern: str, default: str = "") -> str:
    m = re.search(pattern, text, re.M)
    return m.group(1) if m else default


def _section(text: str, header: str) -> str:
    i = text.find(header)
    if i == -1:
        return ""
    j = text.find("\n## ", i + len(header))
    return text[i + len(header): j if j != -1 else len(text)]


# ---------------------------------------------------------------------------
class Router:
    """Tries providers in order; falls through on rate limits and errors."""

    def __init__(self, cfg, order: list[str] | None = None, cache: bool | None = None):
        self.cfg = cfg
        self.timeout = int(cfg.get("llm.request_timeout_s", 120))
        self.max_retries = int(cfg.get("llm.max_retries", 4))
        self.backoff = float(cfg.get("llm.backoff_base_s", 2.0))
        self.order = order or cfg.provider_order
        self.cache_enabled = cfg.get("llm.cache_responses", True) if cache is None else cache
        self.cache_dir = cfg.root / cfg.get("paths.cache", ".cache") / "llm"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.providers: list = []
        for name in self.order:
            try:
                spec = cfg.provider(name)
            except KeyError:
                continue
            prov = MockProvider(spec) if spec.get("kind") == "mock" \
                else OpenAICompatible(name, spec, self.timeout)
            if prov.available:
                self.providers.append(prov)
        self.calls = 0
        self.cache_hits = 0
        self.errors = 0
        self.successes = 0
        self.last_error = ""
        self.max_output_tokens = int(cfg.get("llm.max_output_tokens", 1400))

    @property
    def active(self) -> list[str]:
        return [p.name for p in self.providers]

    def _key(self, system: str, user: str, temperature: float) -> Path:
        h = hashlib.sha256(
            f"{self.active[0] if self.active else ''}|{system}|{user}|{temperature}".encode()
        ).hexdigest()
        return self.cache_dir / f"{h}.json"

    def complete(self, system: str, user: str, temperature: float = 0.0,
                 max_tokens: int | None = None) -> LLMResponse:
        max_tokens = int(max_tokens or self.max_output_tokens)
        if self.cache_enabled:
            kp = self._key(system, user, temperature)
            if kp.exists():
                d = json.loads(kp.read_text("utf-8"))
                self.cache_hits += 1
                return LLMResponse(**{**d, "cached": True})

        last_err = "no provider available"
        for prov in self.providers:
            for attempt in range(self.max_retries):
                try:
                    resp = prov.complete(system, user, temperature, max_tokens=max_tokens)
                    self.calls += 1
                    if resp.ok:
                        self.successes += 1
                        if self.cache_enabled:
                            self._key(system, user, temperature).write_text(
                                json.dumps(resp.__dict__), "utf-8")
                        return resp
                    last_err = resp.error
                    break                       # hard error: next provider
                except RateLimited as e:
                    last_err = str(e)
                    time.sleep(self.backoff * (2 ** attempt))
                except requests.RequestException as e:
                    last_err = f"{prov.name}: {type(e).__name__}: {e}"
                    break
        self.errors += 1
        self.last_error = last_err
        return LLMResponse("", "none", "none", error=last_err or "provider returned nothing")


# ---------------------------------------------------------------------------
def _json_objects(text: str) -> list[str]:
    """Every balanced {...} region, outermost first, ignoring braces in strings.

    A greedy `\\{.*\\}` spans from the first brace to the last one, so a reply
    like `Thoughts {a note} then {"vuln_id": ...}` produced one unparseable
    blob. Because `parse_json` returning None is recorded as an abstention and
    lowers effective F1, a weak parser is scored against the model.
    """
    out: list[str] = []
    depth = start = 0
    in_str = False
    esc = False
    for i, c in enumerate(text):
        if in_str:
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
            continue
        if c == '"':
            in_str = True
        elif c == "{":
            if depth == 0:
                start = i
            depth += 1
        elif c == "}":
            if depth:
                depth -= 1
                if depth == 0:
                    out.append(text[start:i + 1])
    return out


def parse_json(text: str) -> dict | None:
    """Best-effort structured-output parsing. Returns None on failure so the
    caller can count it as an abstention (needed for effective-F1)."""
    if not text:
        return None
    t = text.strip()
    if t.startswith("```"):
        t = re.sub(r"^```[a-zA-Z]*\n?|```\s*$", "", t).strip()
    try:
        obj = json.loads(t)
        return obj if isinstance(obj, dict) else None
    except json.JSONDecodeError:
        pass
    # Prefer the richest valid object: models often emit a short preamble
    # object before the real answer.
    best: dict | None = None
    for cand in _json_objects(t):
        try:
            obj = json.loads(cand)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict) and (best is None or len(obj) > len(best)):
            best = obj
    return best
