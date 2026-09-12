# Running it yourself with a free LLM

Follow this in order. Steps 1–3 cost nothing and take about ten minutes; you
will have seen an actual model read an actual contract and answer.

---

## Step 0 — install and build the inputs (no key needed)

```bash
cd algostable
python -m pip install -e ".[dev]"

asv corpus     # clones 16 protocol repos      (~3 min)
asv slice      # cuts ~8,200 function slices   (~1 min)
asv status     # shows which providers are usable
```

At this point `asv status` will list only `mock` and `local` as usable, because
no key is set yet.

---

## Step 1 — read the prompt before you spend anything

```bash
asv trace --dry-run --function handleSwapRequest
```

This prints, for Terra's swap handler:

* the exact code slice
* which of the 10 classes retrieval picked, with scores
* the static pre-check verdict
* **the complete prompt that would be sent to the model**

It stops there. No model call, no quota. Read the prompt — everything the model
will see is on your screen.

---

## Step 2 — get a free key (2 minutes, no credit card)

Go to **https://aistudio.google.com/apikey**, sign in with a Google account,
click *Create API key*. Copy it.

```bash
cp .env.example .env
# open .env and paste the key after GEMINI_API_KEY=

# Linux / macOS
set -a; source .env; set +a

# Windows PowerShell
Get-Content .env | ForEach-Object {
  if ($_ -match '^(\w+)=(.+)$') {
    [Environment]::SetEnvironmentVariable($matches[1], $matches[2])
  }
}

asv status     # gemini should now appear under providers_usable_now
```

---

## Step 3 — one real call, fully visible

```bash
asv trace --provider gemini --function handleSwapRequest --out trace_terra.md
```

Now you see the whole exchange:

| Section | What you are looking at |
|---|---|
| 4 | the prompt, exactly as sent |
| 5 | **the raw reply from Gemini, verbatim** — not parsed, not cleaned |
| 6 | that reply parsed into JSON (or a parse failure, which counts against the model) |
| 7 | the critic prompt and the critic's raw reply |
| 8 | the gate: critic scores, static confirmation, final score, detected yes/no |

Two API calls total. `trace_terra.md` is a ready-made thesis appendix — it is
the literal answer to *"what query is given to the LLM"*.

Try a few more to build intuition:

```bash
asv trace --provider gemini --function refreshCollateralRatio   # V7, latency
asv trace --provider gemini --function getCollateralPrice       # V6, oracle
asv trace --provider gemini --function setOracle                # V4, admin key
asv trace --provider gemini --function redeem --class V3        # force a class
```

---

## Step 4 — a small scored run

```bash
asv detect --provider gemini --limit 50
asv evaluate
```

`--limit 50` selects a stride across the corpus **and** forces in every
ground-truth function, so the run stays cheap but is still scoreable.

Cost: each slice checks up to 4 classes, and each class costs 2 auditor calls
plus 1 critic call. So ~50 slices ≈ 300–600 calls. On Gemini's free tier
(~10 requests/minute) that is roughly **45–90 minutes**. Leave it running.

Replies are cached in `.cache/`, so re-running the same slices is free.

---

## Step 5 — the comparison that is your actual result

```bash
asv baseline --kind static                 # rules only, no model
asv detect --provider gemini --limit 50 --no-critic     --out findings_no_critic.json
asv detect --provider gemini --limit 50 --no-static     --out findings_no_static.json
asv detect --provider gemini --limit 50 --normalized    --out findings_normalized.json
asv compare
asv report
```

`results/REPORT.md` now holds the figures and tables. The one that matters is
**Figure 5**: the static-rule baseline against the full LLM pipeline. The rule
baseline has recall but almost no precision; if the LLM stage is doing real
work, precision rises sharply while recall holds.

---

## Step 6 — the market side

```bash
asv data fetch
asv data depeg   --series data/raw/market/USTUSDT_1m.csv
asv data monitor --series data/raw/market/USTUSDT_1m.csv
asv report       --series data/raw/market/USTUSDT_1m.csv
```

No key needed — Binance's public archive and DefiLlama are open.

---

## What to expect, honestly

* **The rule baseline over-flags.** That is by design; it is the floor.
* **The critic will reject a lot.** It is told to refuse by default. If almost
  nothing survives, loosen `detect.critic_min_correctness` in
  `configs/pipeline.yaml` and say so in the write-up.
* **Recall is capped by retrieval.** `labels_matched / labels_total` in
  `evaluation.json` is that ceiling. Raise `retrieval.top_k` to lift it, at the
  cost of more calls.
* **Rate limits will interrupt you.** The router falls through to the next
  provider automatically; add a second free key (Mistral) and it will keep going.

## If something goes wrong

| Symptom | Fix |
|---|---|
| `no usable provider` | `asv status`; the key is not in the environment |
| everything returns `parse failed` | the model is wrapping JSON in prose — try `--provider mistral`, or a stronger model in `configs/models.yaml` |
| HTTP 429 constantly | you are over the free tier; wait, lower `--limit`, or add a second key |
| detection finds nothing at all | run `asv trace` on a labelled function and read section 8 to see which gate rejected it |
