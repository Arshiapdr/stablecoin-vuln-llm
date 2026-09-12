# Run environment (LLM track)

The hosted free tiers this project was designed around are not reachable from
the machine the experiments were run on: `generativelanguage.googleapis.com`
answers every request with an HTML 403 served at Google's edge, before the
request reaches the Gemini API, because the API is not offered in the
operator's region. The key, the model name and the token budget are all
irrelevant to that failure -- see `scripts/check_provider.py`, which
distinguishes an edge block (HTML body) from an API-level error (JSON body).

The LLM track was therefore executed against a locally hosted model. This is
the stronger position for reproducibility: a hosted free tier can retire a
model mid-project (Groq removed `llama-3.3-70b-versatile` on 2026-08-16, see
README), whereas the artefacts below are pinned by hash and can be re-obtained
by an examiner exactly as they were used here.

## Inference engine

| | |
|---|---|
| engine | llama.cpp, release **b10456** (2026-08-17) |
| build | `llama-b10456-bin-win-cuda-12.4-x64.zip` + `cudart-llama-bin-win-cuda-12.4-x64.zip` |
| source | https://github.com/ggml-org/llama.cpp/releases/tag/b10456 |
| server | `llama-server -c 16384 -ngl 99 --host 127.0.0.1 --port 8080` |

## Model

| | |
|---|---|
| model | Qwen2.5-Coder-7B-Instruct, Q4_K_M quantisation |
| file | `qwen2.5-coder-7b-instruct-q4_k_m.gguf` |
| size | 4,683,073,536 bytes |
| sha256 | `509287f78cb4d4cf6b3843734733b914b2c158e43e22a7f4bf5e963800894d3c` |
| source | https://huggingface.co/Qwen/Qwen2.5-Coder-7B-Instruct-GGUF |

## Hardware

OMEN by HP Laptop 16-b0080TX: Intel Core i7-11800H (8C/16T), 16 GB DDR4,
NVIDIA GeForce RTX 3060 Laptop GPU with 6 GB GDDR6. The 6 GB VRAM budget is
why a 7B model at Q4_K_M (~4.4 GiB) was selected over the 14B and 20B entries
in `configs/models.yaml`: those exceed the card and spill into system RAM,
which is not viable across the ~930 calls of a `--limit 200` run.

## Scope of the run

Retrieval returns a median of 2 vulnerability classes per slice (ceiling
`retrieval.top_k: 4`), and each pair is audited twice at different
temperatures, with a critic call on roughly a quarter of them. The full corpus
of 8,166 non-benchmark slices is therefore ~36,000 calls, which is days of
continuous GPU time on this hardware. `--limit 200` selects 216 slices --
a deterministic stride across all 16 protocols, unioned with all 16
ground-truth functions so the run stays evaluable -- for ~930 calls.

Every finding in `results/findings.json` records the `provider` and `model`
that produced it, so a mixed or fallen-back run is visible in the output
rather than assumed away.

## Reliability of a 7B critic (measured, and reportable)

On a 46-slice run with Qwen2.5-Coder-7B-Instruct Q4_K_M at temperature 0,
**18 of 83 critic replies contradicted themselves**: 13 wrote
`verdict: "confirmed"` while scoring `correctness: 0`, and 5 scored 10/10
while writing `"rejected"` -- among them Terra's `handleSwapRequest`, the
canonical V1 case. An explicit instruction in the system prompt forbidding the
contradiction did not remove it.

The pipeline therefore derives acceptance from ONE channel, the numeric scores
(`detect.critic_min_correctness`, `detect.critic_min_profitability`), which is
also the channel `quality` and hence the ranked metrics are built from. The
model's `verdict` string is recorded but not gating, and every reply that
disagrees with its own scores is flagged `critic.inconsistent` and counted as
`critic_self_contradictions` in the run summary.

This is a property of the model, not of the method: the same prompts on a
larger model should show a lower contradiction rate, and that rate is worth
reporting as a measure of how much structure a small local model can hold.
Nothing is repaired silently -- the contradiction is counted, and the count
belongs in the results.
