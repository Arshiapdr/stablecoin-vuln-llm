# Method note

Short companion to the answers document. It records *why* each design choice
was made, with the evidence, so the thesis text and the code stay in sync.

## Why function-level slices, not whole contracts

David et al. (arXiv:2306.12338) fed whole contracts to long-context models and
GPTScan re-measured the result on the same data: **precision 4.1%, F1 7.6%**.
GPTScan's function-level slicing with a scenario/property prompt reached
**precision 57%, F1 67.8%** on Web3Bugs. Slicing is therefore not an
optimisation, it is the difference between a usable and an unusable detector.

## Why scenario / property, and why yes-no

Free-form "find the vulnerabilities" output is unparseable and unverifiable.
Decomposing each class into a *scenario* (what functionality must be present)
and a *property* (what makes it vulnerable), then asking two sequential yes/no
questions, produces output that can be validated mechanically. This is
GPTScan's design; we reuse it and add stablecoin-specific classes.

## Why an auditor and a separate critic

GPTLens showed the recall/precision tension is governed by sampling
temperature: high temperature surfaces more true findings *and* more false
ones. Decoupling generation (temperature 0.7, two independent auditors) from
judgement (temperature 0, adversarial critic) lifted contract-level success
from 38.5% to 76.9% in their experiments.

## Why static confirmation is mandatory

The critic reduces false positives but cannot eliminate hallucinated
statements. Every finding is therefore re-checked against the class's own
`must_call` / `must_lack` / Slither conditions. In GPTScan the equivalent step
cut flagged functions from 647 to 221 — a **65.8%** false-positive reduction.

## Why a parallel run without Slither

Injecting Slither output improves accuracy by roughly 2.7 points
(SmartAuditFlow ablation), but the COMPSAC 2026 benchmark found that agreement
with Slither's verdict rises by up to **354%** — the model mirrors the tool
instead of verifying independently ("stochastic mirror"). Running with and
without the signal separates the two effects.

## Why identifier normalisation

The same COMPSAC study found **4.1–8.5 percentage points** of measured accuracy
comes from descriptive identifier names rather than code semantics. Reporting
both variants makes that contribution visible instead of silently inflating the
headline number.

## Why effective F1

PromptAudit (2026) showed a self-consistency strategy that abstained on 55.2%
of cases still scored 0.420 raw F1 — but 0.197 once coverage was accounted for.
Any metric that ignores unparseable output overstates the model.

## Why the depeg definition is ours

None of the report's nine sources defines a numeric depeg threshold. The
components are borrowed and cited — the $1.00 break point is behaviourally
validated by Anadu et al. (a 34 bp jump in outflow rate below par), the
consecutive-minute persistence rule follows S&P Global's methodology, and the
$0.80 failure line is Fantazzini's sensitivity-tested threshold — but the exact
pairing (1% band, 5 minutes) is this project's parameterisation and is declared
as such. The sensitivity sweep in `asv data depeg` shows the result does not
hinge on it.

## How the evaluation actually works

1. **Ground truth.** `labels/ground_truth.yaml` lists (protocol, file, function,
   class) tuples, each with a citable source. `scripts/check_labels.py` proves
   every label still anchors to a function in the corpus.
2. **Prediction.** A finding is a (slice x class) pair. `detected = true` means
   the auditor asserted the property, the critic confirmed it, and the static
   checks passed.
3. **Matching.** A prediction is a true positive when its
   (protocol, file, function, class) key is in the truth set. Everything else
   predicted is a false positive; unmatched truth keys are false negatives; the
   remaining scored pairs are true negatives.
4. **Retrieval bound.** Recall can never exceed the fraction of labels whose
   class was retrieved for that slice at all. `labels_matched / labels_total`
   reports that ceiling explicitly — currently 12/12.
5. **Uncertainty.** F1 carries a bootstrap 95% confidence interval over 2,000
   resamples, so a small labelled set is not reported as if it were precise.
6. **Comparisons.** `asv compare` scores the main run against the static-rule
   baseline, Slither, and three ablations, using the same matcher.

## Known limitations

* Small labelled set (12 anchored labels). Mitigated by the SmartBugs import
  for implementation-layer classes and by the vulnerable/patched pairing.
* Contamination is reduced, not eliminated. CyberChainBench (2026) measured a
  drop from 36.3% to 20.9% detection accuracy across a knowledge-cutoff split.
* Terra Classic message-level data is unavailable from free sources; the daily
  supply series is a coarser substitute.
* Free-tier availability is unstable — Cerebras, Together and Hugging Face all
  removed free tiers in 2025/2026 and Groq changed its model catalogue. The
  local llama.cpp path is the hedge.

## Evidence strength of the ground truth

Labels are not all equally strong, and the difference is recorded rather than
averaged away. Two kinds of support are distinguished:

* **Cited** — the class is backed by a published paper or incident
  post-mortem. All ten classes have this.
* **Anchored** — a specific function in *this* corpus has been hand-verified
  against the class's property, with the line identified.

As of the current corpus, V1–V8 and V10 are both cited and anchored. **V9 is
cited but not anchored**: the obvious candidate, Fei's $80M Rari/Fuse
reentrancy, lives in the Rari repository rather than in `fei-protocol-core`, so
V9 is measured on the external SmartBugs track instead. A V9 row of zero in the
headline per-class table is therefore *uninformative*, not a real zero, and must
be reported as such.

Two design decisions follow from this, and both are deliberately conservative:

1. **No self-assigned implementation-layer labels.** It would be easy to skim
   the corpus for something reentrancy-shaped and label it V9. That would mean
   the project both writes the exam and grades it. Using SmartBugs' externally
   assigned labels costs recall on paper but keeps the measurement honest.
2. **The benchmark never enters the headline.** SmartBugs contracts are toy
   DASP examples. They are scored in a separate run against a separate label
   file, because 196 synthetic labels would otherwise swamp 16 real ones and the
   reported number would no longer be about stablecoins.

## Controlled comparisons available in the corpus

The corpus supports one true A/B: Beanstalk before and after the April 2022
governance attack, from the same repository at two commits. The pre-attack tree
contains `emergencyCommit` (and 47 governance-facet slices); the post-attack
tree contains neither. Any V5 finding in `beanstalk-patched` is a false positive
by construction, which makes it a sharper precision test than an unrelated
control protocol.

The other controls (Reflexer RAI, Liquity, Mento, Reserve Protocol) are
*different* protocols that never lost their peg, so they test discrimination
across designs rather than across versions of one design.

## Corrections made after an end-to-end audit

Three defects were found by auditing the scoring path rather than by a failing
test. All three were silent: the pipeline produced plausible numbers in every
case. They are recorded here because each one changes previously reported
figures.

**1. Recall was inflated by dropping unretrieved labels.** The truth set was
built by walking the labels and keeping only those that had a corresponding
finding. A label whose function was never selected, or whose class retrieval
never proposed, therefore disappeared from the denominator instead of counting
as a miss. On this corpus with `retrieval.top_k = 1`, 3 of 16 labels were
dropped and recall was reported as **0.769 when the true value was 0.625**
(F1 0.645 vs 0.588). The fix gives every unmatched label a synthetic key that
can never be predicted, so it always scores as a false negative;
`labels_unretrieved` is now reported alongside the metrics, and the retrieval
ceiling is visible rather than absorbed into the score.

**2. The worst critic verdict produced the highest score.** The ranking term
was `confidence * ((correctness + profitability + severity) / 30 or 1.0)`. In
Python `0.0` is falsy, so a critic verdict of 0/0/0 fell through to the `or`
branch and yielded a multiplier of **1.0** — strictly greater than the 0.9 that
a perfect 9/9/9 verdict produced. This inverted the ordering that Top-k and MRR
are computed from. The fallback is removed.

**3. The bootstrap was really a subsample.** `evaluate` keys findings into
sets, so resampling whole findings with replacement collapsed duplicates and
left roughly 63% distinct units per iteration. The resulting interval was too
narrow. The bootstrap now reduces each evaluation unit to its
`(detected, is_true)` outcome once and resamples those, so multiplicity is
honoured. On the current run the 95% interval widened from [0.200, 0.444] to
[0.246, 0.592] — the wider interval is the correct one.

A fourth, smaller issue: V8's static check listed the bare term `rate`.
Matching is a case-insensitive substring test, so it fired on *generate*,
*iterate*, *separate*, *moderate* and *accelerate*, making V8 the noisiest
class in the corpus (1 true positive against 14 false positives). The terms are
now specific enough that they cannot occur inside an unrelated English word,
which raised overall precision from 0.234 to 0.314.

Accuracy is still reported but is now labelled in the output as TN-dominated.
With negatives outnumbering positives by orders of magnitude it is not a
measure of detector quality and should not be quoted as one.

## Corrections to the behavioural track (second audit pass)

The detection path was audited first; the market/monitor path was audited
afterwards and contained a worse defect than anything found on the detection
side.

**1. The early-warning result was almost entirely an artefact.** `lead_time`
selected `prior[0]` — the first alert anywhere in the series that preceded the
event — rather than an alert belonging to *that* event. Every episode after the
first was therefore credited to the earliest alert ever raised, however long
ago and whatever caused it. On the demo series the monitor raised **2 alerts in
total**, and the old code reported that **16 of 16** depeg episodes were
"preceded by an alert", with a median lead time of 424 minutes. The corrected
figure is **1 of 16** episodes warned, median lead 205 minutes.

Two rules now apply: alerts are only admissible within a bounded look-back
window (default 48h, reported in the output), and no alert at or before the end
of the preceding episode may be credited to the next one. Both bounds are
printed in Table 8 so the reader can see what "lead time" was allowed to mean.

**2. A hole in the price data welded separate episodes together.** Runs were
counted in consecutive *samples* while duration was computed from *timestamps*.
A gap — a month Binance never served, a DefiLlama outage — therefore produced a
single event spanning the gap. Six minutes below peg, a three-day hole, then six
more minutes below peg was reported as one depeg lasting three days. A run is
now broken when the spacing between consecutive samples exceeds
`max_gap_steps × step_seconds`, and `fetch_binance_minutes` writes a
`*.missing.json` sidecar naming every month it could not download, instead of
skipping it silently. Overlapping dumps are also de-duplicated on timestamp.

**3. The indicator window was measured in samples, not time.**
`prices[-1440:]` is 24 hours on minute data but **60 days** on hourly data. The
monitor derives `state` from the minimum over that window, so on hourly series
the state latched at the first depeg and never returned to normal — and since
alerts fire only on a state *change*, the monitor then went permanently silent.
The window is now a time span (`indicator_window_minutes`, default 1440).

**4. A zero supply baseline reported the whole supply as growth.** The 24h
growth ratio used `base = past[-1] or 1.0`, so a baseline of exactly zero
became a divisor of one and the growth ratio became the absolute supply — on
Terra's numbers, 5.89e12 rather than "undefined". A zero baseline now yields
NaN and every downstream comparison is NaN-safe.

**5. The Slither baseline was scored on more classes than the LLM.**
`slither_findings` enumerated all ten classes for every slice, while the LLM
run only ever sees `retrieval.top_k` (default 4). The two columns of the
ablation table were therefore not measuring the same task. The baseline now
emits one finding per (slice, retrieved class), exactly as the detector does.

The lesson worth stating in the write-up: every one of these defects made the
system look *better* than it was, and none of them produced an error or a
visibly wrong number. They were found by reading the scoring path and
constructing adversarial inputs, not by running the pipeline and inspecting the
output.

## Corrections to slicing and the model client (third audit pass)

**1. 13% of the corpus shared a slice identity.** The slice id hashed
`protocol:file:contract:signature`. Go methods on different receivers —
`func (k Keeper) GetSigners()` and `func (s Server) GetSigners()` in one file —
produce the same name, the same argument string and (for non-Solidity files)
the same synthetic "contract", so they collapsed to one id. **169 ids covered
1096 of 8166 slices.** Since Slither hits are cached per slice id, a colliding
id silently merges detector output across unrelated functions, and
`asv trace --slice-id` resolves ambiguously. The definition-site offset is now
part of the id; collisions are zero.

**2. State-variable context was keyed on the initialiser, not the name.** The
declared name was taken as `decl.split()[-1].split("=")[0]`, which for
`uint256 public rewardRate = 0;` yields `"0"`. The declaration was then
attached to every function whose body contains a literal 0, and the real
variable never matched at all. Splitting on `=` also broke
`mapping(address => uint256)`, whose `=>` is not an assignment. A proper
`declared_name()` now parses the declaration, ignoring `=>`, comparisons and
anything inside brackets. This changes what the model is shown, so results from
before this fix are not comparable.

**3. The JSON parser was scored against the model.** Extraction used a greedy
`\{.*\}`, which spans from the first brace in the reply to the last. A reply
of the form `Here is my reasoning {an aside} then the answer: {...}` therefore
produced one unparseable blob. Because `parse_json` returning None is counted
as an abstention and lowers **effective F1**, a weak parser was charged to the
model's account. Extraction now scans for balanced objects, ignores braces
inside strings, and takes the richest valid object.

### Known, accepted limitations (not defects)

* **The identifier-normalisation ablation is partial by design.** With
  `--normalized`, the auditor and critic see renamed identifiers, but retrieval
  and static confirmation still run on the original code — and `detected`
  is gated on static confirmation. The ablation therefore measures the model's
  reliance on lexical cues, *not* the whole pipeline's. State that scope when
  reporting it.
* **The response cache is keyed on the first active provider**, not the
  provider that actually answered. If the first provider rate-limits and the
  router falls through, the reply is cached under the first provider's key.
  Attribution inside each record is still correct (`provider`/`model` are
  stored per finding); the only consequence is that changing which keys are set
  invalidates cache entries.
* **`max_tokens` is fixed at 1400.** A verbose model can be truncated
  mid-JSON, which counts as an abstention. Raise it in `configs/models.yaml`
  if coverage is low for a particular provider.

## Separating "is it algorithmic?" from "did it fail?"

The corpus originally carried a single `tier` field meaning both *"is this an
algorithmic design?"* and *"did its peg fail?"*. Those are different questions,
and collapsing them produced two rows that could not be defended:

* **Fei Protocol** sat in the algorithmic study set. It is backed entirely by
  exogenous collateral (Protocol Controlled Value); the one genuinely
  algorithmic feature, the direct-incentives mechanism, was abandoned in 2021;
  and the incident recorded against it is a reentrancy bug in the Rari/Fuse
  pools — a *different repository*, and evidence about a code defect rather
  than about PCV-backing as a monetary mechanism. It was in the study set
  because it was famous, not because of what it is.
* **Reflexer RAI** sat in the controls, despite a PID controller that
  continuously adjusts the redemption rate. That is an algorithmic peg
  mechanism. RAI is *more* algorithmic than Fei.

The fix is two independent fields:

* `algorithmic: pure | partial | none` — a property of the mechanism.
* `tier: study | control` — the protocol's role in the evaluation.

`family` was cleaned up at the same time: `control_cdp`, `control_reserve`,
`control_basket` and `control_patched` re-encoded the role inside the mechanism
descriptor, which is the same conflation one level down. They are now `cdp`,
`reserve_amm`, `basket`, and — for the patched Beanstalk tree — plain
`seigniorage_shares`, because the design is unchanged; only its role differs.

That independence is load-bearing, and two rows demonstrate it: Beanstalk
(patched) is `pure` but a control, and Reflexer RAI is `partial` but a control.

### Report in three layers, never one blended number

`asv layers` writes `results/evaluation_layers.json`, rendered as Table 10:

| Layer | Protocols | Labels | What it means |
|---|---|---|---|
| `pure` | 7 | 10 | The report's actual scope: uncollateralised designs. |
| `partial` | 3 | 6 | Frax, Iron Finance, Angle. Reported beside `pure`, never merged into it. |
| study (pure + partial) | 10 | 16 | The extended set. |
| `control` | 6 | 0 | No positive labels, so precision and recall are undefined; only the false-positive count is meaningful. |

The `partial` protocols keep their place in the study set on evidence, not
convenience: Iron Finance's collapse was a genuine death spiral of its
algorithmic portion, and two ground-truth labels (V2 endogenous collateral, V3
redemption friction) are anchored in its code. They must nevertheless always be
described as *partially* collateralised, never as uncollateralised.

The honest cost of this change is that the headline set falls from 11 protocols
to 7. Seven is small. But a defensible seven beats a contestable eleven, and
the extended row is printed immediately beneath it.

RAI's classification is itself a small finding worth stating: an algorithmic
rate controller that *held*, because it sits on overcollateralised debt. What
breaks these designs is the absorbing token, not the algorithm.

## In-context learning, not fine-tuning

The model's weights are never updated anywhere in this project. The only
dependencies are `click`, `PyYAML` and `requests`; there is no PyTorch, no
transformers, no PEFT. The LLM is called twice per (slice, class) pair over a
plain `POST /chat/completions`, and everything it knows about stablecoin
vulnerabilities arrives in the prompt.

That is a deliberate choice, and the arithmetic behind it is worth stating
because an examiner will ask why the project does not "train" anything:

* **Data.** Fine-tuning, even LoRA on a small model, wants on the order of
  10³ examples. This project has **16** hand-verified labels. Sixteen examples
  would not teach the concept of a death spiral; they would teach the model to
  recognise Terra's `handleSwapRequest` by its identifier names — exactly the
  contamination the normalisation ablation exists to detect.
* **Evaluation.** Fine-tuning consumes the labels it trains on. An 11/5 split
  of 16 labels is not a measurement.
* **Base model.** The free tiers offer inference, not fine-tuning. Training
  locally means a ~7B model in 4-bit, which is a far weaker reasoner than the
  frontier models available for free through the API. The likely outcome is a
  system that scores *worse* than zero-shot for considerably more effort.
* **Explainability.** A finding here is defended by a named scenario, a named
  property, a cited statement, a critic verdict and a mechanical check. A
  fine-tuned checkpoint defends nothing.
* **The contribution.** `knowledge/vulnerabilities.yaml` is the reusable
  artifact of this project. Fine-tuning would dissolve it into weights, and
  adding a class would stop being a YAML edit.

### The one form of learning that is available: worked examples

`asv detect --few-shot` adds a positive and a negative worked example to the
auditor prompt (`src/asv/fewshot.py`). This is in-context learning: no weight
update, no training run, and it can be switched on and off as an ablation.

**Exemplars are selected leave-one-protocol-out.** Showing the model Terra's
`handleSwapRequest` and then scoring the run on Terra's `handleSwapRequest`
would hand it the answer and credit it for repeating it — the same failure
shape as the mock-scaffolding leak. `fewshot.select()` filters on protocol
before any other criterion, and `tests/test_fewshot.py` asserts across every
(class, target) pair that no exemplar shares the audited protocol.

Both polarities are shown on purpose: a ground-truth vulnerable function with
the JSON the auditor should have produced, and a control-protocol function that
does *not* satisfy the property, with a correct rejection. A prompt containing
only positives teaches the model to say yes.

The pool built from the current corpus holds 26 exemplars (16 positive from
ground truth, 10 negative from controls), and the rendered block costs roughly
490 tokens per prompt.

**This ablation is meaningless under `--provider mock`.** The offline backend
is a rule engine that reads two scaffolding lines and ignores the rest of the
prompt, so `llm_few_shot` comes out byte-identical to `llm_full` — verified,
0 differing decisions out of 175 findings. The row is only informative under a
real model, and `results/REPORT.md` says so wherever the backend is `mock`.
