# Adjudication of the 20 false positives (`--limit 200`, static veto on)

## Why this exists

`labels/ground_truth.yaml` annotates 16 functions. Every detection outside
those 16 is scored a false positive whether or not it is correct, so the raw
precision of 0.200 is a LOWER BOUND, not an estimate. This file adjudicates
each of the 20 and reports a band instead.

## Who adjudicated, and the limitation that creates

These verdicts were produced with LLM assistance (Claude) reading each slice,
its class property, and the critic's rebuttal. That is an LLM adjudicating
another LLM's output, and it MUST be disclosed as such: it is a reading aid,
not ground truth. Before any of these numbers go in the thesis the author
should independently verify at least the eleven B verdicts, since those are
what raise the reported precision. Where the author disagrees, the author's
verdict governs.

## Criteria, fixed before the verdicts were assigned

* **A - correct but unlabelled.** The supplied code plainly exhibits the class
  property as written; the label set simply does not cover this function.
* **B - genuinely wrong.** The supplied code contains the safeguard the
  property requires, or the critic's stated reasoning is factually false about
  the code.
* **C - borderline.** The property holds on a literal reading, but the finding
  is not materially informative, or the evidence needed to decide is not in
  the slice.

## Verdicts

| # | protocol | function | class | verdict | reason |
|---|---|---|---|---|---|
| 1 | angle-protocol | `_closePerpetual` | V10 | **B** | no invariant break shown; critic returned 10/10 with an EMPTY rebuttal |
| 2 | angle-protocol | `pause` | V4 | C | guardian-role pause with no timelock in the slice: literally in class, not demonstrable from the code supplied |
| 3 | angle-protocol | `_closePerpetual` | V9 | **B** | claims multiplication overflow; the contract is solc 0.8.x, where that reverts |
| 4 | basis-cash | `setTarget` | V4 | **A** | `onlyOwner`, no timelock - the same pattern as the labelled `setBondOracle[V4]` in the same protocol |
| 5 | beanstalk-patched | `transferOwnership` | V4 | C | two-step candidate transfer, no timelock; literally in class, materially guarded |
| 6 | beanstalk-patched | `refundEth` | V9 | **B** | the low-level call's return value IS checked (`require(success)`); empty rebuttal |
| 7 | fei-protocol | `burnAgToken` | V10 | **B** | oracle-manipulation path claimed, but the function is `onlyPCVController` and bounded by `minFeiOut` |
| 8 | fei-protocol | `grantGovernor` | V4 | C | role granted with no delay in the slice; Fei's governor is a timelock in deployment, invisible here |
| 9 | fei-protocol | `burnAgToken` | V9 | **B** | same claim as #7, same refutation |
| 10 | iron-finance | `claimTreasuryFundRewards` | V1 | **B** | amount is `unclaimedTreasuryFund()`, an accrual bounded per period - the cap the property demands is present in substance |
| 11 | iron-finance | `claimTreasuryFundRewards` | V10 | C | mints without a backing check, which is literally the property, but this is ordinary reward accrual |
| 12 | iron-finance | `withdraw` | V2 | **B** | the asset is an Aave position, i.e. exogenous; the property is about endogenous backing |
| 13 | iron-finance | `setDollar` | V4 | **A** | `onlyOwner`, no timelock - same pattern as the labelled `setOracle[V4]` in the same protocol |
| 14 | iron-finance | `setShareAddress` | V4 | **A** | as #13, and without even a zero-address check |
| 15 | iron-finance | `claimTreasuryFundRewards` | V9 | **B** | no external call, no unchecked arithmetic; empty rebuttal |
| 16 | liquity | `mint` | V1 | C | see below - the most informative of the twenty |
| 17 | mento | `rebalance` | V7 | **B** | `rebalanceCooldown` is present and the critic's own rebuttal says so |
| 18 | mento | `burnStableTokens` | V9 | **B** | burns the caller's own tokens via `safeTransferFrom`/`safeBurn`; empty rebuttal |
| 19 | reflexer-rai | `join` | V9 | **B** | the rebuttal states the external call precedes the state update; the code does the OPPOSITE - `modifyCollateralBalance` runs first |
| 20 | yam-finance | `rebase` | V2 | C | YAM has no separate backing asset at all, so V2's scenario does not really apply; the label set assigns V10 here |

**A = 3, B = 11, C = 6.**

## Adjudicated precision

| basis | precision |
|---|---|
| raw, unlabelled counted as wrong | 5/25 = **0.200** |
| strict adjudication (A counted correct) | 8/25 = **0.320** |
| lenient adjudication (A and C counted correct) | 14/25 = **0.560** |

Report the band **0.32 - 0.56**, with 0.20 as the mechanical lower bound, and
state the adjudication procedure and its LLM assistance.

## The Liquity case is worth a paragraph of its own

`liquity:mint` is `_requireCallerIsBorrowerOperations(); _mint(...)`. LUSD
genuinely has no per-call cap, no global ceiling and no peg-linked circuit
breaker, so V1's property is satisfied word for word. Yet Liquity is a control
protocol precisely because it is over-collateralised: the safeguard is that
minting is gated by collateral deposited in a different contract, which the
slice never sees.

This is a finding about the CLASS, not about the model. V1 as written does not
require the auditor to establish that the backing is endogenous, so it fires on
any uncapped mint, collateralised or not. Either V1's property should carry
that conjunct, or function-level slicing is the wrong granularity for it. Both
are legitimate thesis conclusions; changing the class now, after seeing which
findings it produced, would not be.
