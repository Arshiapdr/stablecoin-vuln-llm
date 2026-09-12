"""Stage 3 — detection: Auditor -> Critic -> static confirmation -> ranking.

The prompts here are exactly the ones documented in the answers document, so
the thesis text and the code cannot drift apart.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .config import Config, file_matches
from .kb import KnowledgeBase, VulnClass, confirm
from .llm import Router, parse_json
from .slicing import Slice, load as load_slices

# --- prompts ----------------------------------------------------------------
AUDITOR_SYSTEM = """You are a senior smart-contract security auditor specialising in
stablecoin protocols. You audit ONE function against ONE vulnerability
class. Every finding must be justified by a concrete line of the supplied
code and must be exploitable for attacker profit or protocol insolvency.
Answer ONLY with JSON matching the schema. No prose outside the JSON."""

AUDITOR_USER = """## TARGET
protocol: {protocol}   contract: {contract}
function: {signature}  compiler: {solc_version}

## FUNCTION UNDER AUDIT
{code}

## STATE VARIABLES / MODIFIERS / CALLEE SIGNATURES
{context}

## STATIC ANALYSIS SIGNALS (Slither)
{slither}

## VULNERABILITY CLASS
id: {vuln_id}
title: {title}
scenario: {scenario}
property: {property}
{mock_scaffold}
{few_shot}## TASK
Step 1 SCENARIO MATCH - does this function implement the scenario? yes/no
Step 2 PROPERTY MATCH - if yes, does it satisfy the vulnerable property? yes/no
Step 3 EVIDENCE - if yes, name the exact key variables and statements, and
        give a concrete attacker profit path in at most 4 sentences.
Decide each step five times internally and report the majority answer.

## OUTPUT SCHEMA
{{"vuln_id":"","scenario_match":false,"property_match":false,
 "confidence":0.0,"key_variables":[],"vulnerable_statements":[],
 "attack_path":"","severity":"high|medium|low"}}"""

# Two rubrics, chosen by the class's LAYER. One rubric cannot serve both.
#
# The knowledge base states most classes as STRUCTURAL properties: V1 is "the
# minted amount has no cap and there is no circuit breaker"; V4 is "authority
# is a single EOA rather than multisig+timelock". Judging those by the
# implementation-exploit standard below -- which zeroes any finding where "the
# attacker cannot obtain the required privilege" -- rejects them BY
# CONSTRUCTION, because privileged control is the subject of the class rather
# than a defence against it. Measured on a 46-slice run: the auditor flagged
# all 16 ground-truth functions at confidence 0.8-1.0 and the critic rejected
# every one with correctness=0, while scoring profitability 7-9 on three of
# them. Recall was structurally pinned at 0 for 8 of the 10 classes.
#
# Both rubrics keep rejection as the default and both demand a named line of
# the SUPPLIED code. What differs is the question asked: exploitability for
# implementation defects, presence-or-absence of the required guard for design
# properties.

_CRITIC_JSON = """The verdict and the scores must agree. Set verdict "confirmed" ONLY if
correctness >= 5 AND profitability >= 3; otherwise set verdict "rejected".
Never output "confirmed" together with correctness 0 -- that is a
contradiction, not a judgement.
Output JSON only:
{"correctness":0,"severity":0,"profitability":0,
 "verdict":"confirmed|rejected","rebuttal":""}"""

CRITIC_SYSTEM = """You are an adversarial reviewer of an IMPLEMENTATION-layer finding
(a concrete code defect). Your default position is that the finding is WRONG.
Accept it only if the supplied code makes the attack path unavoidable.
Score correctness, severity and profitability 0-10.
Set correctness = 0 if: a modifier or require already prevents the path; the
attacker cannot obtain the required privilege; the reasoning relies on code
that was not supplied; or the finding restates a generic risk with no
concrete statement.
""" + _CRITIC_JSON

CRITIC_SYSTEM_DESIGN = """You are an adversarial reviewer of a DESIGN-layer finding
(economic, governance or oracle). The claim is not that an unprivileged
attacker can call this function and steal funds. The claim is that the code
LACKS a specific structural safeguard the vulnerability class names, and that
the protocol fails under stress as a result.

Your default position is still that the finding is WRONG, and every judgement
must cite the SUPPLIED code.

Score correctness 0-10: does the supplied code actually exhibit the claimed
property -- i.e. is the required safeguard genuinely ABSENT?
Set correctness = 0 if: the supplied code DOES contain the safeguard the
property demands (a per-call/per-epoch cap or supply ceiling, a peg-linked
pause or circuit breaker, a timelock or multisig on the privileged role, a
multi-source median or deviation bound on the price, a bounded adjustment
latency); or the reasoning relies on code that was not supplied; or the
finding names no concrete statement or variable and merely restates a generic
risk.
Do NOT set correctness = 0 merely because the function is owner-only,
governance-gated, or not atomically exploitable. For these classes the
privileged or economic path IS the subject of the finding.

Score profitability 0-10 as the economic gain available to whoever triggers
the failure -- the redeemer, the arbitrageur, the mint/burn counterparty, or
the privileged role itself -- under peg stress. Not necessarily atomic, and
not necessarily an outsider.

Score severity 0-10 by the loss to the protocol if the property is exercised.
""" + _CRITIC_JSON

# Classes whose property is a code defect; everything else is judged
# structurally. `layer` comes from knowledge/vulnerabilities.yaml.
IMPLEMENTATION_LAYERS = {"implementation"}


def critic_system(vc: VulnClass) -> str:
    """Pick the reviewing standard that matches how the class is defined."""
    return CRITIC_SYSTEM if vc.layer in IMPLEMENTATION_LAYERS else CRITIC_SYSTEM_DESIGN

CRITIC_USER = """## FUNCTION
{code}

## CLAIMED FINDING
class: {vuln_id} - {title}   (layer: {layer})
property claimed violated: {property}
key variables: {key_variables}
vulnerable statements: {statements}
attack path: {attack_path}

Judge it."""


# --- data -------------------------------------------------------------------
@dataclass
class Finding:
    slice_id: str
    protocol: str
    tier: str
    file: str
    contract: str
    function: str
    start_line: int
    vuln_id: str
    report_category: str
    title: str
    detected: bool
    confidence: float
    severity: str
    key_variables: list[str] = field(default_factory=list)
    statements: list[str] = field(default_factory=list)
    attack_path: str = ""
    critic: dict = field(default_factory=dict)
    static_confirmation: dict = field(default_factory=dict)
    score: float = 0.0
    provider: str = ""
    model: str = ""
    parse_failed: bool = False
    # A transport/API failure (no key, wrong model, empty completion, network).
    # Kept apart from `parse_failed`: an abstention is a statement about the
    # MODEL, and counting a dead endpoint as one reports the provider's outage
    # as the model's judgement.
    provider_error: str = ""
    mitigation: str = ""


# --- pipeline ---------------------------------------------------------------
def _auditor_prompt(sl: Slice, vc: VulnClass, precheck: bool,
                    slither: list[str] | None, normalized: bool,
                    mock_mode: bool = False,
                    exemplars: list | None = None) -> str:
    """Build the auditor prompt.

    `mock_mode` appends the static pre-check verdict and the trigger-term hint.
    Those two lines exist ONLY so the deterministic offline backend can act as a
    stand-in. They are never sent to a real model: doing so would tell it the
    rule engine's answer and make the LLM run an echo of the baseline rather
    than an independent judgement.
    """
    scaffold = (f"static_precheck: {str(precheck).lower()}\n"
                f"must_call_hint: {','.join(vc.static_checks.get('must_call', [])[:6])}\n"
                if mock_mode else "")
    from .fewshot import render_block
    return AUDITOR_USER.format(
        mock_scaffold=scaffold,
        few_shot=render_block(exemplars or []),
        protocol=sl.protocol, contract=sl.contract, signature=sl.signature,
        solc_version=sl.solc_version or "unknown",
        code=(sl.normalized_code if normalized and sl.normalized_code else sl.code),
        context=sl.prompt_context(),
        slither=", ".join(slither) if slither else "none",
        vuln_id=vc.id, title=vc.title,
        scenario=vc.scenario.replace("\n", " "),
        property=vc.property.replace("\n", " "),
    )


def analyse_slice(sl: Slice, kb: KnowledgeBase, router: Router, cfg: Config,
                  slither: dict[str, list[str]] | None = None,
                  normalized: bool = False,
                  use_critic: bool = True,
                  use_static: bool = True,
                  use_slither: bool = True,
                  exemplar_pool: list | None = None) -> list[Finding]:
    top_k = int(cfg.get("retrieval.top_k", 3))
    always = cfg.get("retrieval.always_include", []) or []
    min_score = float(cfg.get("retrieval.min_score", 0.0))
    a_temp = float(cfg.get("detect.auditor_temperature", 0.7))
    c_temp = float(cfg.get("detect.critic_temperature", 0.0))
    n_aud = int(cfg.get("detect.auditors", 2))
    min_corr = int(cfg.get("detect.critic_min_correctness", 5))
    min_prof = int(cfg.get("detect.critic_min_profitability", 3))
    weak = float(cfg.get("detect.static_confirmation_weight", 0.35))

    hits = (slither or {}).get(sl.id, []) if use_slither else []
    mock_mode = bool(router.providers) and all(
        getattr(p, "name", "") == "mock" for p in router.providers)
    findings: list[Finding] = []

    for vc, _ in kb.retrieve(sl.code, top_k=top_k, always=always, min_score=min_score):
        conf = confirm(vc, sl.code, hits if use_slither else None)
        best: dict | None = None
        parse_failed = False
        provider = model = ""

        provider_error = ""
        shots = []
        if exemplar_pool:
            from .fewshot import select
            # leave-one-protocol-out: nothing from the protocol under analysis
            shots = select(exemplar_pool, vc.id, sl.protocol)

        for a in range(max(1, n_aud)):
            prompt = _auditor_prompt(sl, vc, conf.passed, hits, normalized,
                                     mock_mode=mock_mode, exemplars=shots)
            resp = router.complete(AUDITOR_SYSTEM, prompt,
                                   temperature=a_temp if a else max(0.0, a_temp - 0.4))
            if resp.provider != "none":
                provider, model = resp.provider, resp.model
            if not resp.ok:
                provider_error = resp.error or "provider returned nothing"
                continue          # NOT a parse failure: nothing was returned
            data = parse_json(resp.text)
            if data is None:
                parse_failed = True
                continue
            if data.get("property_match") and (
                    best is None or float(data.get("confidence", 0)) > float(best.get("confidence", 0))):
                best = data

        if best is None:
            findings.append(Finding(
                slice_id=sl.id, protocol=sl.protocol, tier=sl.tier, file=sl.file,
                contract=sl.contract, function=sl.function, start_line=sl.start_line,
                vuln_id=vc.id, report_category=vc.report_category, title=vc.title,
                detected=False, confidence=0.0, severity="low",
                static_confirmation=conf.as_dict(), score=0.0,
                provider=provider, model=model, parse_failed=parse_failed,
                provider_error=provider_error, mitigation=vc.mitigation))
            continue

        critic: dict = {}
        if use_critic:
            cprompt = CRITIC_USER.format(
                code=(sl.normalized_code if normalized and sl.normalized_code else sl.code),
                vuln_id=vc.id, title=vc.title, layer=vc.layer,
                property=vc.property.replace("\n", " "),
                key_variables=", ".join(best.get("key_variables", [])[:8]),
                statements=" | ".join(best.get("vulnerable_statements", [])[:4]),
                attack_path=best.get("attack_path", ""))
            cresp = router.complete(critic_system(vc), cprompt, temperature=c_temp)
            critic = parse_json(cresp.text) or {}
            if critic:
                # Which standard judged this finding, recorded in the output so
                # a reader can see it rather than infer it.
                critic["rubric"] = ("implementation" if vc.layer in IMPLEMENTATION_LAYERS
                                    else "design")
                # A reply that says "confirmed" while scoring correctness 0 is
                # internally inconsistent. It is FLAGGED, never repaired: the
                # rate at which a model contradicts its own schema is a result
                # about that model, and silently reinterpreting it would put
                # the pipeline's opinion into the model's mouth.
                _v, _c = critic.get("verdict"), float(critic.get("correctness", 0) or 0)
                _p = float(critic.get("profitability", 0) or 0)
                critic["inconsistent"] = bool(
                    (_v == "confirmed" and (_c < min_corr or _p < min_prof))
                    or (_v == "rejected" and _c >= min_corr and _p >= min_prof))

        corr = float(critic.get("correctness", 10 if not use_critic else 0))
        prof = float(critic.get("profitability", 10 if not use_critic else 0))
        sev = float(critic.get("severity", 5))
        # A self-contradictory critic reply is NOT a judgement, and the
        # pipeline does not get to pick which half to believe.
        #
        # History, kept because it is the honest version: on a 46-slice sample
        # the scores looked like the reliable channel (6 acceptances, 5 of them
        # on-label, none on a control) and acceptance was switched to read the
        # scores alone. On 216 slices that did not replicate. All three rules
        # land inside each other's bootstrap interval --
        #   scores only        det 25  tp 5  P 0.200  R 0.312  F1 0.244
        #   verdict only       det 30  tp 7  P 0.233  R 0.438  F1 0.304
        #   verdict AND scores det 14  tp 3  P 0.214  R 0.188  F1 0.200
        # -- so 16 labels cannot settle which channel to trust, and picking the
        # winner would be fitting the decision rule to the test set.
        #
        # What the larger sample DOES show is that 18 replies scored a finding
        # 10/10 while writing "rejected", every one of them with a substantive
        # rebuttal arguing the finding is wrong, and 16 of those 18 were
        # off-label. Reading the scores alone admitted findings whose own
        # reasoning refuted them.
        #
        # So an inconsistent reply is treated as an ABSTENTION: not accepted,
        # and counted against coverage exactly like unparseable output, which
        # is what `effective_f1` exists to charge for. That neither invents a
        # judgement nor hides the model's failure to give one.
        accepted = (not use_critic) or (
            not critic.get("inconsistent")
            and corr >= min_corr and prof >= min_prof)

        # NB: no `or 1.0` fallback here. `(0+0+0)/30` is falsy, so an `or 1.0`
        # would turn the critic's WORST possible verdict into the HIGHEST
        # multiplier and invert the ranking that top-k and MRR depend on.
        quality = (corr + prof + sev) / 30.0
        score = float(best.get("confidence", 0.5)) * quality
        if use_static and not conf.passed:
            score *= weak
        detected = bool(accepted and (conf.passed or not use_static or not cfg.get(
            "detect.require_static_confirmation", True)))

        findings.append(Finding(
            slice_id=sl.id, protocol=sl.protocol, tier=sl.tier, file=sl.file,
            contract=sl.contract, function=sl.function, start_line=sl.start_line,
            vuln_id=vc.id, report_category=vc.report_category, title=vc.title,
            detected=detected, confidence=float(best.get("confidence", 0.0)),
            severity=str(best.get("severity", vc.severity)),
            key_variables=list(best.get("key_variables", []))[:10],
            statements=list(best.get("vulnerable_statements", []))[:5],
            attack_path=str(best.get("attack_path", ""))[:900],
            critic=critic, static_confirmation=conf.as_dict(),
            score=round(score, 4), provider=provider, model=model,
            parse_failed=parse_failed, provider_error=provider_error,
            mitigation=vc.mitigation))

    return findings


def select_slices(cfg: Config, limit: int | None, protocols: list[str] | None,
                  include_labeled: bool = True) -> list[Slice]:
    """Pick the slices to analyse.

    With a free-tier quota you cannot analyse every slice, so `limit` takes a
    deterministic stride across the corpus (not just the first N, which would
    only ever cover one protocol) and, when `include_labeled` is set, always
    unions in every function that carries a ground-truth label. That keeps a
    small run both cheap and evaluable.
    """
    slices = load_slices(cfg)
    if protocols:
        slices = [s for s in slices if s.protocol in protocols]
    else:
        # Benchmark contracts (SmartBugs) are a separate comparability track and
        # must never leak into the headline stablecoin run. Reach them by naming
        # them explicitly: `asv detect --protocol smartbugs-curated`.
        slices = [s for s in slices if s.tier != "benchmark"]
    if not limit or limit >= len(slices):
        return slices

    from .evaluation import load_labels
    labeled: list[Slice] = []
    if include_labeled:
        labels = load_labels(cfg)
        for lb in labels:
            labeled += [s for s in slices
                        if s.protocol == lb.protocol
                        and file_matches(lb.file_contains, s.file)
                        and s.function == lb.function]

    stride = max(1, len(slices) // max(1, limit))
    sampled = slices[::stride][:limit]
    seen = {s.id for s in sampled}
    for s in labeled:
        if s.id not in seen:
            sampled.append(s)
            seen.add(s.id)
    sampled.sort(key=lambda s: (s.protocol, s.file, s.start_line))
    return sampled


def run(cfg: Config, provider: str | None = None, limit: int | None = None,
        protocols: list[str] | None = None, normalized: bool = False,
        use_critic: bool = True, use_static: bool = True, use_slither: bool = True,
        out_name: str = "findings.json", progress=None,
        include_labeled: bool = True, few_shot: bool = False) -> dict:
    kb = KnowledgeBase.load(cfg.knowledge_dir)
    slices = select_slices(cfg, limit, protocols, include_labeled)

    # Built once from the FULL slice set, not from `slices`: a limited run must
    # still be able to draw an exemplar from a protocol it did not sample.
    # `select()` enforces leave-one-protocol-out at use time.
    exemplar_pool = None
    if few_shot:
        from .fewshot import build_pool
        exemplar_pool = build_pool(cfg, load_slices(cfg), kb)

    order = [provider] if provider else cfg.provider_order
    router = Router(cfg, order=order)
    if not router.providers:
        raise RuntimeError(
            f"no usable LLM provider among {order}. Set an API key (see .env.example) "
            f"or use --provider mock for the offline run.")

    slither_map = _load_slither(cfg)
    fail_fast = int(cfg.get("llm.fail_fast_after_errors", 8))
    findings: list[Finding] = []
    for i, sl in enumerate(slices, 1):
        findings.extend(analyse_slice(sl, kb, router, cfg, slither_map, normalized,
                                      use_critic, use_static, use_slither,
                                      exemplar_pool=exemplar_pool))
        # Stop the moment it is clear the provider is not answering at all.
        # The earlier behaviour was to keep going: a wrong key or an empty
        # completion produced a full-length run of empty findings, an
        # evaluation of 0.0 across every metric, and no visible cause -- the
        # failure looked like a model that never detected anything.
        if fail_fast and router.successes == 0 and router.errors >= fail_fast:
            raise RuntimeError(
                f"aborting after {router.errors} consecutive provider failures with no "
                f"successful call. Last error: {router.last_error}\n"
                f"Nothing was written. Diagnose with:  python scripts/check_provider.py "
                f"--provider {order[0] if order else 'gemini'}")
        if progress:
            progress(i, len(slices))

    out = cfg.path("results") / out_name
    out.write_text(json.dumps([asdict(f) for f in findings], indent=1), "utf-8")

    pos = [f for f in findings if f.detected]
    by_class: dict[str, int] = {}
    for f in pos:
        by_class[f.vuln_id] = by_class.get(f.vuln_id, 0) + 1
    return {
        "slices_analysed": len(slices), "findings_total": len(findings),
        "detected": len(pos), "by_class": by_class,
        "providers": router.active, "llm_calls": router.calls,
        "cache_hits": router.cache_hits,
        "parse_failures": sum(1 for f in findings if f.parse_failed),
        "provider_errors": sum(1 for f in findings if f.provider_error),
        "critic_self_contradictions": sum(
            1 for f in findings if (f.critic or {}).get("inconsistent")),
        "provider_last_error": router.last_error,
        "few_shot": bool(few_shot),
        "exemplar_pool": len(exemplar_pool) if exemplar_pool else 0,
        "output": str(out),
    }


def _load_slither(cfg: Config) -> dict[str, list[str]]:
    p = cfg.path("processed") / "slither.json"
    return json.loads(p.read_text("utf-8")) if p.exists() else {}


def load_findings(cfg: Config, name: str = "findings.json") -> list[Finding]:
    p = cfg.path("results") / name
    if not p.exists():
        raise FileNotFoundError(f"{name} missing — run `asv detect` first")
    return [Finding(**d) for d in json.loads(p.read_text("utf-8"))]
