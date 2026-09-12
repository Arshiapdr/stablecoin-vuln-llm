"""Few-shot exemplars for the auditor, selected leave-one-protocol-out.

In-context learning is the only kind of "training" this project can honestly
do: 16 hand-verified labels is orders of magnitude short of what fine-tuning
needs, and fine-tuning on them would also consume the very examples the
evaluation depends on.

The leakage rule is the whole point of this module. If Terra's
`handleSwapRequest` is shown to the model as a worked example and the run is
then scored on Terra's `handleSwapRequest`, the model is being handed the
answer and credited for repeating it. Every exemplar is therefore drawn from a
DIFFERENT protocol than the one under analysis — `select()` filters on protocol
before anything else, and `tests/test_fewshot.py` asserts it.

Two kinds of exemplar are supplied so the model sees both decisions:

  positive - a ground-truth vulnerable function, with the JSON the auditor
             should have produced
  negative - a function from a control protocol that does NOT satisfy the
             class property, with a correct rejection

Selection is deterministic (sorted, no RNG) so a run is reproducible.
"""
from __future__ import annotations

import json
from dataclasses import dataclass

from .config import Config, file_matches
from .kb import KnowledgeBase, confirm
from .slicing import Slice

# Exemplar bodies are truncated: they are there to demonstrate the shape of a
# decision, not to be audited themselves, and a full 4000-token function would
# crowd out the actual target.
MAX_EXEMPLAR_CHARS = 900


@dataclass
class Exemplar:
    protocol: str
    vuln_id: str
    signature: str
    code: str
    verdict: dict
    kind: str            # "positive" | "negative"

    def render(self) -> str:
        return (f"### Example ({self.kind}) — class {self.vuln_id}, "
                f"from {self.protocol}\n"
                f"function: {self.signature}\n"
                "```\n" + self.code + "\n```\n"
                "correct answer:\n" + json.dumps(self.verdict, indent=None))


def _truncate(code: str) -> str:
    if len(code) <= MAX_EXEMPLAR_CHARS:
        return code
    return code[:MAX_EXEMPLAR_CHARS] + "\n// ...[truncated for the example]"


def build_pool(cfg: Config, slices: list[Slice], kb: KnowledgeBase) -> list[Exemplar]:
    """Assemble the exemplar pool once, from ground truth plus controls."""
    from .evaluation import load_labels

    by_key: dict[tuple[str, str], list[Slice]] = {}
    for s in slices:
        by_key.setdefault((s.protocol, s.function), []).append(s)

    pool: list[Exemplar] = []

    # --- positives: hand-verified vulnerable functions -----------------------
    for lb in sorted(load_labels(cfg), key=lambda l: (l.vuln_id, l.protocol, l.function)):
        cand = [s for s in by_key.get((lb.protocol, lb.function), [])
                if file_matches(lb.file_contains, s.file)]
        if not cand:
            continue
        s = cand[0]
        pool.append(Exemplar(
            protocol=s.protocol, vuln_id=lb.vuln_id, signature=s.signature,
            code=_truncate(s.code), kind="positive",
            verdict={
                "vuln_id": lb.vuln_id, "scenario_match": True,
                "property_match": True, "confidence": 0.85,
                "severity": kb.classes[lb.vuln_id].severity
                if lb.vuln_id in kb.classes else "high",
            }))

    # --- negatives: control-protocol functions that fail the property --------
    controls = {p["name"] for p in cfg.protocol_list("control")}
    labelled = {(lb.protocol, lb.function) for lb in load_labels(cfg)}
    seen: set[str] = set()
    for s in sorted(slices, key=lambda x: (x.protocol, x.file, x.start_line)):
        if s.protocol not in controls or (s.protocol, s.function) in labelled:
            continue
        for vc, _ in kb.retrieve(s.code, top_k=1):
            if vc.id in seen or confirm(vc, s.code, []).passed:
                continue
            if len(s.code) < 120:            # too small to be instructive
                continue
            seen.add(vc.id)
            pool.append(Exemplar(
                protocol=s.protocol, vuln_id=vc.id, signature=s.signature,
                code=_truncate(s.code), kind="negative",
                verdict={"vuln_id": vc.id, "scenario_match": True,
                         "property_match": False, "confidence": 0.1,
                         "severity": "low"}))
    return pool


def select(pool: list[Exemplar], vuln_id: str, exclude_protocol: str,
           n_positive: int = 1, n_negative: int = 1) -> list[Exemplar]:
    """Pick exemplars for one (class, target protocol) pair.

    Leave-one-protocol-out is applied FIRST and unconditionally: nothing from
    `exclude_protocol` can be selected, whatever else matches. Exemplars of the
    same class are preferred; otherwise any class is used, since the shape of a
    correct answer transfers.
    """
    usable = [e for e in pool if e.protocol != exclude_protocol]

    def pick(kind: str, n: int) -> list[Exemplar]:
        same = [e for e in usable if e.kind == kind and e.vuln_id == vuln_id]
        other = [e for e in usable if e.kind == kind and e.vuln_id != vuln_id]
        ordered = sorted(same, key=lambda e: (e.protocol, e.signature)) + \
                  sorted(other, key=lambda e: (e.vuln_id, e.protocol, e.signature))
        return ordered[:n]

    return pick("positive", n_positive) + pick("negative", n_negative)


def render_block(exemplars: list[Exemplar]) -> str:
    if not exemplars:
        return ""
    body = "\n\n".join(e.render() for e in exemplars)
    return ("## WORKED EXAMPLES (different protocols; for calibration only)\n"
            + body + "\n\n")
