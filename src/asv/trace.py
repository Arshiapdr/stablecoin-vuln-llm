"""`asv trace` — show every step of the detector for ONE function.

This is the teaching / evidence tool. It prints, in order:

  1. the code slice that was selected
  2. which vulnerability classes retrieval chose, and their scores
  3. the static pre-check verdict
  4. the EXACT auditor prompt (system + user) sent to the model
  5. the RAW model reply, verbatim
  6. the parsed JSON
  7. the EXACT critic prompt and its raw reply
  8. the static confirmation
  9. the final decision and score

With `--dry-run` it stops after step 4, so you can read the prompt without
spending any quota. The markdown output is directly usable as a thesis
appendix — it is the literal answer to "what query is given to the LLM".
"""
from __future__ import annotations

import json
from pathlib import Path

from .config import Config, file_matches
from .detect import (AUDITOR_SYSTEM, CRITIC_USER, _auditor_prompt, critic_system)
from .kb import KnowledgeBase, confirm
from .llm import Router, parse_json
from .slicing import Slice, load as load_slices

RULE = "=" * 78


def _block(title: str, body: str, lines: list[str]) -> None:
    lines += [RULE, f"  {title}", RULE, "", body.rstrip(), ""]


def pick_slice(cfg: Config, function: str | None, protocol: str | None,
               slice_id: str | None) -> Slice:
    slices = load_slices(cfg)
    if slice_id:
        for s in slices:
            if s.id == slice_id:
                return s
        raise SystemExit(f"no slice with id {slice_id}")
    cand = slices
    if protocol:
        cand = [s for s in cand if s.protocol == protocol]
    if function:
        cand = [s for s in cand if s.function == function]
    if not cand:
        raise SystemExit("no slice matched; try --function or --protocol, "
                         "or run `asv slice` first")
    if not function and not protocol:
        # default to a labelled function so the example is a known true positive
        from .evaluation import load_labels
        for lb in load_labels(cfg):
            hit = [s for s in cand if s.protocol == lb.protocol
                   and file_matches(lb.file_contains, s.file)
                   and s.function == lb.function]
            if hit:
                return hit[0]
    return cand[0]


def run(cfg: Config, provider: str | None = None, function: str | None = None,
        protocol: str | None = None, slice_id: str | None = None,
        vuln_id: str | None = None, dry_run: bool = False) -> tuple[str, dict]:
    kb = KnowledgeBase.load(cfg.knowledge_dir)
    sl = pick_slice(cfg, function, protocol, slice_id)

    lines: list[str] = []
    lines += [f"# Trace — {sl.protocol} · {sl.function}", ""]

    # 1 --------------------------------------------------------------------
    _block("1. SELECTED SLICE",
           f"protocol : {sl.protocol}\n"
           f"file     : {sl.file}:{sl.start_line}-{sl.end_line}\n"
           f"contract : {sl.contract}\n"
           f"signature: {sl.signature}\n"
           f"language : {sl.language}   solc: {sl.solc_version or 'n/a'}\n"
           f"size     : {sl.n_chars} chars, ~{sl.approx_tokens} tokens\n\n"
           "```\n" + sl.code + "\n```", lines)

    # 2 --------------------------------------------------------------------
    top_k = int(cfg.get("retrieval.top_k", 4))
    retrieved = kb.retrieve(sl.code, top_k=top_k)
    rows = ["score  class  title",
            "-----  -----  " + "-" * 50]
    for vc, score in retrieved:
        rows.append(f"{score:5.3f}  {vc.id:<5}  {vc.title[:50]}")
    hits_note = ("\nRetrieval is deterministic term matching, not an embedding "
                 "model: score = (matched trigger terms) / sqrt(total terms).")
    _block(f"2. RETRIEVAL — top {top_k} of {len(kb)} classes",
           "\n".join(rows) + hits_note, lines)

    target = None
    if vuln_id:
        target = kb.classes.get(vuln_id)
        if target is None:
            raise SystemExit(f"unknown class {vuln_id}")
    else:
        target = retrieved[0][0]

    # 3 --------------------------------------------------------------------
    conf = confirm(target, sl.code, [])
    _block(f"3. STATIC PRE-CHECK for {target.id}",
           f"scenario : {target.scenario.strip()}\n\n"
           f"property : {target.property.strip()}\n\n"
           f"checks   : {json.dumps(conf.checks)}\n"
           f"captured : {json.dumps(conf.captured)[:400]}\n"
           f"passed   : {conf.passed}\n"
           f"reason   : {conf.reason}", lines)

    # 4 --------------------------------------------------------------------
    order = [provider] if provider else cfg.provider_order
    mock_mode = order[:1] == ["mock"]
    auditor_user = _auditor_prompt(sl, target, conf.passed, [], False,
                                   mock_mode=mock_mode)
    if mock_mode:
        lines += ["", "> NOTE: mock backend selected, so the prompt below carries two extra",
                  "> scaffolding lines (`static_precheck`, `must_call_hint`). A real model",
                  "> never sees them — it must reach its own verdict from the code.", ""]
    _block("4. AUDITOR PROMPT — system message",
           AUDITOR_SYSTEM, lines)
    _block("4. AUDITOR PROMPT — user message (sent verbatim to the model)",
           auditor_user, lines)

    result = {"slice_id": sl.id, "protocol": sl.protocol, "function": sl.function,
              "vuln_id": target.id, "static_passed": conf.passed,
              "prompt_tokens_approx": len(auditor_user) // 4}

    if dry_run:
        _block("DRY RUN",
               "Stopped before calling the model. No quota spent.\n"
               f"This prompt is ~{len(auditor_user)//4} tokens.\n"
               "Re-run without --dry-run to see the model's reply.", lines)
        return "\n".join(lines), result

    # 5 --------------------------------------------------------------------
    router = Router(cfg, order=order, cache=False)
    if not router.providers:
        raise SystemExit(f"no usable provider among {order}. Run `asv status`.")

    a_temp = float(cfg.get("detect.auditor_temperature", 0.7))
    resp = router.complete(AUDITOR_SYSTEM, auditor_user, temperature=a_temp)
    _block(f"5. RAW MODEL REPLY  (provider={resp.provider}  model={resp.model}  "
           f"{resp.latency_s}s)",
           resp.text or f"[no text]  error: {resp.error}", lines)
    result["provider"] = resp.provider
    result["model"] = resp.model

    parsed = parse_json(resp.text)
    _block("6. PARSED JSON",
           json.dumps(parsed, indent=2) if parsed else
           "PARSE FAILED — this counts as an abstention and lowers effective F1.",
           lines)
    result["parsed"] = parsed

    if not parsed or not parsed.get("property_match"):
        _block("RESULT", "The auditor did not assert the property. "
                         "No finding is produced for this class.", lines)
        result["detected"] = False
        return "\n".join(lines), result

    # 7 --------------------------------------------------------------------
    critic_user = CRITIC_USER.format(
        code=sl.code, vuln_id=target.id, title=target.title, layer=target.layer,
        property=target.property.replace("\n", " "),
        key_variables=", ".join(parsed.get("key_variables", [])[:8]),
        statements=" | ".join(parsed.get("vulnerable_statements", [])[:4]),
        attack_path=parsed.get("attack_path", ""))
    _block("7. CRITIC PROMPT — system message", critic_system(target), lines)
    _block("7. CRITIC PROMPT — user message", critic_user, lines)

    cresp = router.complete(critic_system(target), critic_user,
                            temperature=float(cfg.get("detect.critic_temperature", 0.0)))
    _block("7. RAW CRITIC REPLY", cresp.text or f"[no text] error: {cresp.error}", lines)
    critic = parse_json(cresp.text) or {}
    result["critic"] = critic

    # 8/9 ------------------------------------------------------------------
    min_corr = int(cfg.get("detect.critic_min_correctness", 5))
    min_prof = int(cfg.get("detect.critic_min_profitability", 3))
    corr = float(critic.get("correctness", 0))
    prof = float(critic.get("profitability", 0))
    sev = float(critic.get("severity", 5))
    accepted = critic.get("verdict") == "confirmed" and corr >= min_corr and prof >= min_prof
    score = float(parsed.get("confidence", 0.5)) * ((corr + prof + sev) / 30.0)
    weak = float(cfg.get("detect.static_confirmation_weight", 0.35))
    if not conf.passed:
        score *= weak
    detected = bool(accepted and conf.passed)

    _block("8. DECISION",
           f"critic verdict      : {critic.get('verdict')}  "
           f"(correctness {corr}, profitability {prof}, severity {sev})\n"
           f"critic gate         : correctness >= {min_corr} and "
           f"profitability >= {min_prof}  ->  {accepted}\n"
           f"static confirmation : {conf.passed}"
           f"{'' if conf.passed else f'  (score multiplied by {weak})'}\n"
           f"final score         : {score:.4f}\n"
           f"DETECTED            : {detected}\n"
           f"mitigation if true  : {target.mitigation} — "
           f"{(kb.mitigation_for(target.id).title if kb.mitigation_for(target.id) else '')}",
           lines)

    result.update({"detected": detected, "score": round(score, 4)})
    return "\n".join(lines), result
