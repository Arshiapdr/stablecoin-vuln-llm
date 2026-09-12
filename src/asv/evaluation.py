"""Stage 5 — evaluation.

Metrics: per-class precision/recall/F1, confusion matrix, ranked metrics
(Top-k, MRR) and effective F1, which penalises abstentions and unparseable
output (PromptAudit, 2026). Bootstrap confidence intervals are included so
the numbers in the thesis carry uncertainty.
"""
from __future__ import annotations

import json
import random
from dataclasses import dataclass
from pathlib import Path

import yaml

from .config import Config, file_matches
from .detect import Finding, load_findings


# --- ground truth -----------------------------------------------------------
@dataclass
class Label:
    protocol: str
    file_contains: str
    function: str
    vuln_id: str
    source: str = ""
    note: str = ""

    def matches(self, f: Finding) -> bool:
        return (f.protocol == self.protocol
                and file_matches(self.file_contains, f.file)
                and f.function == self.function)


def load_labels(cfg: Config, name: str = "ground_truth.yaml") -> list[Label]:
    """Load one label file.

    Defaults to the hand-verified stablecoin ground truth. The SmartBugs
    benchmark labels live in a SEPARATE file and are loaded only when asked
    for by name, so the external benchmark can never silently contaminate the
    headline stablecoin metrics.
    """
    p = cfg.root / "labels" / name
    if not p.exists():
        return []
    raw = yaml.safe_load(p.read_text("utf-8")) or {}
    return [Label(**item) for item in raw.get("labels", [])]


# --- metrics ----------------------------------------------------------------
def prf(tp: int, fp: int, fn: int) -> dict:
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return {"tp": tp, "fp": fp, "fn": fn,
            "precision": round(prec, 4), "recall": round(rec, 4), "f1": round(f1, 4)}


def _key(f: Finding) -> tuple:
    return (f.protocol, f.file, f.function, f.vuln_id)


def evaluate(findings: list[Finding], labels: list[Label]) -> dict:
    """Score findings against labels.

    A label can fail to appear in `findings` for two reasons: its function was
    never selected for analysis, or retrieval never proposed its class for that
    function. Either way the detector did NOT find it, so it must count as a
    miss. Deriving the truth set only from findings that exist would silently
    drop those labels from the denominator and inflate recall — a run that
    retrieved one label out of two and detected it would report recall 1.0
    instead of 0.5.
    """
    truth: set[tuple] = set()
    unretrieved: list[Label] = []
    for lb in labels:
        hit = next((f for f in findings
                    if lb.matches(f) and f.vuln_id == lb.vuln_id), None)
        if hit is not None:
            truth.add(_key(hit))
        else:
            # Synthetic key: never present in `predicted`, so it lands in fn.
            truth.add((lb.protocol, lb.file_contains, lb.function, lb.vuln_id))
            unretrieved.append(lb)

    predicted = {_key(f) for f in findings if f.detected}
    considered = {_key(f) for f in findings}
    tp = len(predicted & truth)
    fp = len(predicted - truth)
    fn = len(truth - predicted)
    # `truth & considered` holds every label key the run scored -- INCLUDING
    # the ones it detected, which are already counted in `tp`. Subtracting the
    # whole intersection therefore removed the true positives a second time,
    # and the four cells summed to (pairs - tp) instead of pairs: 3 + 13 + 11 +
    # 393 = 420 against 423 scored pairs. Only the UNDETECTED label keys (the
    # false negatives among the considered pairs) belong in this subtraction.
    fn_considered = len(truth & considered) - tp
    tn = max(0, len(considered) - tp - fp - fn_considered)
    overall = prf(tp, fp, fn)
    overall["tn"] = tn
    # Accuracy over analysed (slice, class) pairs. Reported for completeness
    # only: negatives outnumber positives by orders of magnitude here, so this
    # number is dominated by TN and must not be read as detector quality.
    denom = len(considered) + len(unretrieved)
    overall["accuracy"] = round((tp + tn) / denom, 4) if denom else 0.0
    overall["accuracy_note"] = "TN-dominated; not a quality measure"

    per_class: dict[str, dict] = {}
    for vid in sorted({f.vuln_id for f in findings} | {lb.vuln_id for lb in labels}):
        sub = [f for f in findings if f.vuln_id == vid]
        pr = {_key(f) for f in sub if f.detected}
        tr = {k for k in truth if k[3] == vid}
        per_class[vid] = prf(len(pr & tr), len(pr - tr), len(tr - pr))

    # ranked metrics: per contract, is a true finding in the top-k by score?
    by_contract: dict[tuple, list[Finding]] = {}
    for f in findings:
        by_contract.setdefault((f.protocol, f.file, f.contract), []).append(f)
    topk = {1: 0, 3: 0, 5: 0}
    mrr_sum, ranked_units = 0.0, 0
    for _, group in by_contract.items():
        tr = [f for f in group if _key(f) in truth]
        if not tr:
            continue
        ranked_units += 1
        ordered = sorted(group, key=lambda f: -f.score)
        pos = next((i + 1 for i, f in enumerate(ordered) if _key(f) in truth), None)
        if pos:
            mrr_sum += 1 / pos
            for k in topk:
                if pos <= k:
                    topk[k] += 1
    ranked = {f"top_{k}": round(v / ranked_units, 4) if ranked_units else 0.0
              for k, v in topk.items()}
    ranked["mrr"] = round(mrr_sum / ranked_units, 4) if ranked_units else 0.0
    ranked["units"] = ranked_units

    # effective F1: abstentions count against the model. An abstention is
    # unparseable output OR a critic reply that contradicts itself -- a reply
    # scoring 10/10 while writing "rejected" is not a judgement the pipeline
    # can act on, and counting it as a clean rejection would hide the failure
    # inside the recall figure instead of reporting it.
    parse_fail = sum(1 for f in findings if f.parse_failed)
    contradictions = sum(1 for f in findings if (f.critic or {}).get("inconsistent"))
    coverage = 1 - (parse_fail + contradictions) / len(findings) if findings else 0.0
    overall["parse_failures"] = parse_fail
    overall["critic_self_contradictions"] = contradictions
    overall["coverage"] = round(coverage, 4)
    overall["effective_f1"] = round(overall["f1"] * coverage, 4)

    return {"overall": overall, "per_class": per_class, "ranked": ranked,
            # len(labels), not len(truth): `truth` is a SET, so labels that
            # share a (protocol, file, function, class) key collapse into one
            # entry. Subtracting a list length from a set size reported
            # `labels_matched: -33` on the 196-label SmartBugs file.
            "labels_matched": len(labels) - len(unretrieved),
            "labels_duplicated": len(labels) - len({
                (lb.protocol, lb.file_contains, lb.function, lb.vuln_id)
                for lb in labels}),
            "labels_unretrieved": len(unretrieved),
            "unretrieved": [f"{lb.protocol}:{lb.function}:{lb.vuln_id}"
                            for lb in unretrieved],
            "labels_total": len(labels),
            "findings": len(findings)}


def bootstrap_f1(findings: list[Finding], labels: list[Label],
                 iterations: int = 2000, level: float = 0.95, seed: int = 0) -> dict:
    if not findings:
        return {}
    # Resampling whole Finding objects and re-running `evaluate` does NOT work:
    # `evaluate` keys findings into sets, so a finding drawn twice collapses to
    # one entry. That silently turns the "bootstrap" into ~63% subsampling and
    # produces an interval that is too narrow. Instead, reduce each evaluation
    # unit to its (detected, is_true) outcome ONCE, then resample those units
    # with replacement so multiplicity is genuinely honoured.
    truth_keys: set[tuple] = set()
    unretrieved = 0
    for lb in labels:
        hit = next((f for f in findings
                    if lb.matches(f) and f.vuln_id == lb.vuln_id), None)
        if hit is not None:
            truth_keys.add(_key(hit))
        else:
            unretrieved += 1

    # (detected, is_true) per analysed finding, plus one certain miss per label
    # that was never retrieved at all.
    units: list[tuple[bool, bool]] = [
        (f.detected, _key(f) in truth_keys) for f in findings]
    units += [(False, True)] * unretrieved

    rnd = random.Random(seed)
    scores: list[float] = []
    n = len(units)
    for _ in range(iterations):
        tp = fp = fn = 0
        for _ in range(n):
            detected, is_true = units[rnd.randrange(n)]
            if detected and is_true:
                tp += 1
            elif detected:
                fp += 1
            elif is_true:
                fn += 1
        scores.append(prf(tp, fp, fn)["f1"])
    scores.sort()
    lo = scores[int((1 - level) / 2 * len(scores))]
    hi = scores[min(len(scores) - 1, int((1 + level) / 2 * len(scores)))]
    return {"f1_mean": round(sum(scores) / len(scores), 4),
            "ci_low": round(lo, 4), "ci_high": round(hi, 4),
            "iterations": iterations, "level": level}


# --- report -----------------------------------------------------------------
def run(cfg: Config, findings_name: str = "findings.json",
        out_name: str = "evaluation.json", bootstrap: bool = True,
        labels_name: str = "ground_truth.yaml") -> dict:
    findings = load_findings(cfg, findings_name)
    labels = load_labels(cfg, labels_name)
    res = evaluate(findings, labels)
    res["labels_file"] = labels_name
    if bootstrap and labels:
        res["bootstrap"] = bootstrap_f1(
            findings, labels,
            iterations=int(cfg.get("evaluation.bootstrap_iterations", 2000)),
            level=float(cfg.get("evaluation.confidence_level", 0.95)),
            seed=int(cfg.get("seed", 0)))
    res["source"] = findings_name
    out = cfg.path("results") / out_name
    out.write_text(json.dumps(res, indent=1), "utf-8")
    res["output"] = str(out)
    return res


def by_layer(cfg: Config, findings_name: str = "findings.json",
             out_name: str = "evaluation_layers.json") -> dict:
    """Score the run separately on each layer of the corpus.

    A single blended number over `study + control` is not answerable to the
    question the thesis asks. The three layers are:

      pure    - uncollateralised designs: the report's actual scope
      partial - partially collateralised, algorithmic controller (Frax,
                Iron Finance, Angle). Reported beside `pure`, never merged
                into it.
      control - collateral-backed, plus the patched half of the Beanstalk
                pair. These carry no positive labels, so precision/recall are
                undefined; what matters is the false-positive count.
    """
    findings = load_findings(cfg, findings_name)
    labels = load_labels(cfg)
    meta = cfg.protocol_meta()

    def algo_of(name: str) -> str:
        m = meta.get(name, {})
        return "control" if m.get("tier") == "control" else m.get("algorithmic", "none")

    out: dict[str, dict] = {}
    for layer in ("pure", "partial", "control"):
        names = {n for n in meta if algo_of(n) == layer}
        sub_f = [f for f in findings if f.protocol in names]
        sub_l = [lb for lb in labels if lb.protocol in names]
        res = evaluate(sub_f, sub_l)
        out[layer] = {
            "protocols": sorted(names),
            "findings": len(sub_f), "labels": len(sub_l),
            **{k: res["overall"][k] for k in
               ("tp", "fp", "fn", "precision", "recall", "f1")},
        }
    # "pure + partial" is the extended study set
    study = {n for n in meta if meta[n].get("tier") == "study"}
    res = evaluate([f for f in findings if f.protocol in study],
                   [lb for lb in labels if lb.protocol in study])
    out["study_combined"] = {
        "protocols": sorted(study),
        "findings": sum(1 for f in findings if f.protocol in study),
        "labels": sum(1 for lb in labels if lb.protocol in study),
        **{k: res["overall"][k] for k in
           ("tp", "fp", "fn", "precision", "recall", "f1")},
    }
    path = cfg.path("results") / out_name
    path.write_text(json.dumps(out, indent=1), "utf-8")
    return {"layers": out, "output": str(path)}


def compare(cfg: Config, runs: dict[str, str], out_name: str = "ablations.json") -> dict:
    """Compare several findings files (main run vs ablations/baselines)."""
    labels = load_labels(cfg)
    table = {}
    for name, fname in runs.items():
        try:
            table[name] = evaluate(load_findings(cfg, fname), labels)["overall"]
        except FileNotFoundError:
            table[name] = {"error": "not run"}
    out = cfg.path("results") / out_name
    out.write_text(json.dumps(table, indent=1), "utf-8")
    return {"table": table, "output": str(out)}
