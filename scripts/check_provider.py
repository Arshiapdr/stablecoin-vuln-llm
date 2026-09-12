#!/usr/bin/env python3
"""One real call to a provider, with the failure printed instead of swallowed.

`asv detect` needs ~1700 calls. Finding out only afterwards that every one of
them returned nothing costs a run and, worse, produces a findings.json full of
empty results that the evaluator scores as 0.0 across the board. Run this first.

    python scripts/check_provider.py                 # default: gemini
    python scripts/check_provider.py --provider mistral --model gemini-2.5-flash-lite

Reads .env itself, so it works whether or not the variables are exported.
"""
import argparse
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import requests                                     # noqa: E402

from asv.config import Config                       # noqa: E402
from asv.llm import Router, parse_json              # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--provider", default="gemini")
ap.add_argument("--model", default=None)
ap.add_argument("--max-tokens", type=int, default=None)
ap.add_argument("--all", action="store_true",
                help="Probe every configured provider and report which ones answer "
                     "from this machine.")
args = ap.parse_args()

# .env is not auto-loaded by the package; load it here so the check reflects the
# key on disk rather than whatever the shell happens to have exported.
env_file = ROOT / ".env"
if env_file.exists():
    for line in env_file.read_text("utf-8").splitlines():
        m = re.match(r"^\s*(\w+)\s*=\s*(.+?)\s*$", line)
        if m and not os.getenv(m.group(1)):
            os.environ[m.group(1)] = m.group(2).strip().strip('"').strip("'")

cfg = Config.load()


def probe(name: str) -> str:
    """One short call to `name`. Returns a one-line verdict."""
    try:
        sp = cfg.provider(name)
    except KeyError:
        return "not configured"
    if sp.get("kind") == "mock":
        return "OK (offline rule-based mock, not a language model)"
    k_env = sp.get("api_key_env")
    k = os.getenv(k_env, "") if k_env else ""
    if not k and name != "local":
        return f"skipped: {k_env} not set in .env"
    body = {"model": sp.get("default_model"),
            "messages": [{"role": "user", "content": "Reply with the single word OK."}],
            "temperature": 0.0, "max_tokens": 2048}
    body.update(sp.get("extra_params") or {})
    hdr = {"Content-Type": "application/json"}
    if k:
        hdr["Authorization"] = f"Bearer {k}"
    try:
        rr = requests.post((sp.get("base_url") or "").rstrip("/") + "/chat/completions",
                           headers=hdr, json=body, timeout=45)
    except requests.RequestException as e:
        return f"unreachable: {type(e).__name__}"
    if rr.status_code >= 400:
        html = "html" in rr.headers.get("content-type", "").lower() \
            or rr.text.lstrip()[:9].lower().startswith("<!doctype")
        if html:
            return f"HTTP {rr.status_code} (HTML page) -- blocked before the API: region/network"
        try:
            msg = str((rr.json().get("error") or {}).get("message", ""))[:90]
        except ValueError:
            msg = rr.text[:90].replace("\n", " ")
        return f"HTTP {rr.status_code}: {msg}"
    try:
        c = (rr.json()["choices"][0]["message"]["content"] or "").strip()
    except (KeyError, IndexError, ValueError):
        return "200 but no message in the response"
    return f"OK -- answered {c[:40]!r}" if c else \
        "200 but EMPTY content (raise llm.max_output_tokens / disable thinking)"


if args.all:
    names = list(cfg.provider_order)
    print("probing every configured provider from this machine\n")
    width = max(len(n) for n in names)
    usable = []
    for n in names:
        verdict = probe(n)
        print(f"  {n:{width}}  {verdict}")
        if verdict.startswith("OK") and n != "mock":
            usable.append(n)
    print()
    if usable:
        print(f"usable from here: {', '.join(usable)}")
        print(f"run:  asv detect --provider {usable[0]} --limit 200")
    else:
        print("No hosted provider answers from this machine.")
        print("Options, in order of preference for the thesis:")
        print("  1. `local`  -- llama.cpp on your own hardware. No account, no network,")
        print("     bit-reproducible. See `local` in configs/models.yaml for the command,")
        print("     then: asv detect --provider local --limit 200")
        print("  2. `mock`   -- the offline rule-based baseline. NOT a language model:")
        print("     it is the 'structure without an LLM' ablation, and must be reported")
        print("     as such, never as an LLM result.")
    sys.exit(0)

spec = cfg.provider(args.provider)
key_env = spec.get("api_key_env")
key = os.getenv(key_env, "") if key_env else ""
model = args.model or spec.get("default_model")
max_tokens = args.max_tokens or int(cfg.get("llm.max_output_tokens", 4096))

print(f"provider     : {args.provider}")
print(f"base_url     : {spec.get('base_url')}")
print(f"model        : {model}")
print(f"max_tokens   : {max_tokens}")
if key_env:
    print(f"{key_env:13}: {'set, ' + str(len(key)) + ' chars' if key else 'NOT SET'}")
    if key and (key != key.strip() or key[0] in "\"'"):
        print("  WARNING: the key has surrounding quotes or whitespace -- strip them in .env")
if not key and spec.get("kind") != "mock" and args.provider != "local":
    sys.exit(f"\n{key_env} is empty. Put the key in .env, no quotes, no spaces.")

payload = {
    "model": model,
    "messages": [
        {"role": "system", "content": "You are a JSON-only API. Output one JSON object, nothing else."},
        {"role": "user", "content": 'Return exactly {"ok": true, "note": "hello"}'},
    ],
    "temperature": 0.0,
    "max_tokens": max_tokens,
}
payload.update(spec.get("extra_params") or {})
url = (spec.get("base_url") or "").rstrip("/") + "/chat/completions"
headers = {"Content-Type": "application/json"}
if key:
    headers["Authorization"] = f"Bearer {key}"

print("\n--- request ---")
try:
    r = requests.post(url, headers=headers, json=payload,
                      timeout=int(cfg.get("llm.request_timeout_s", 120)))
except requests.RequestException as e:
    sys.exit(f"network error: {type(e).__name__}: {e}")

print(f"HTTP {r.status_code}")
if r.status_code >= 400:
    ctype = r.headers.get("content-type", "")
    body_is_html = "html" in ctype.lower() or r.text.lstrip()[:9].lower().startswith("<!doctype")
    print(r.text[:500])
    if body_is_html:
        # The API answers errors in JSON. An HTML page means the request was
        # refused by the provider's edge before reaching the API at all --
        # geographic restriction, network filtering, or a captive proxy. No
        # key, model or quota change can affect it.
        sys.exit(
            f"\n=> BLOCKED BEFORE THE API. The body is an HTML error page, not the "
            f"JSON this API returns for key/quota/model problems.\n"
            f"   {args.provider} is not reachable from this network or region. "
            f"Nothing about the key, the model name or the token budget will change it.\n"
            f"   Find a provider that does answer from here:\n"
            f"       python scripts/check_provider.py --all\n"
            f"   If none do, run the detector against a local model instead "
            f"(no account, fully reproducible):\n"
            f"       see `local` in configs/models.yaml, then: asv detect --provider local")
    hint = {401: "the key is wrong, revoked, or issued for a different account",
            403: "the key is valid but the API is not enabled for this project, "
                 "or this account/region is not permitted",
            404: f"the model name {model!r} does not exist on this endpoint -- "
                 "check `models:` in configs/models.yaml",
            429: "rate limited: the free tier caps requests per minute"}.get(r.status_code)
    sys.exit(f"\n=> {hint}" if hint else "")

data = r.json()
choice = (data.get("choices") or [{}])[0]
content = (choice.get("message") or {}).get("content")
print(f"finish_reason: {choice.get('finish_reason')}")
print(f"usage        : {data.get('usage')}")
print(f"content      : {content!r}")

if not (content or "").strip():
    print("\n=> HTTP 200 but the message is EMPTY.")
    print("   Almost always a reasoning model spending the whole output budget on")
    print("   hidden thinking tokens (look for finish_reason='length' and a large")
    print("   completion_tokens above). Fixes, in order:")
    print("     1. raise llm.max_output_tokens in configs/pipeline.yaml")
    print("     2. add to the provider in configs/models.yaml:")
    print("          extra_params: {reasoning_effort: none}")
    print("     3. switch to a non-reasoning model, e.g. --model gemini-2.5-flash-lite")
    sys.exit(1)

parsed = parse_json(content)
print(f"parsed JSON  : {parsed}")
if parsed is None:
    sys.exit("\n=> the model answered but the reply is not JSON. Not fatal: the "
             "auditor prompt is far more explicit than this probe.")

print("\nOK - this provider answers and returns parseable JSON.")
print("Now confirm the router agrees:")
router = Router(cfg, order=[args.provider])
resp = router.complete("You are a JSON-only API.", 'Return {"ok": true}', 0.0)
print(f"  router: provider={resp.provider} model={resp.model} ok={resp.ok} "
      f"error={resp.error or 'none'}")
