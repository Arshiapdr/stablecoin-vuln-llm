"""Baselines for the evaluation chapter.

  * slither  : run Slither over the corpus (if installed) and map its detector
               hits onto our classes, producing a findings file in the same
               format so the numbers are directly comparable.
  * static   : the knowledge base's mechanical rules with no model at all.
  * naive    : whole-contract, unstructured prompt (the David et al. setup).
"""
from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import asdict
from pathlib import Path

from .config import Config
from .detect import Finding
from .kb import KnowledgeBase, confirm
from .slicing import Slice, load as load_slices

# Slither detector -> our class
SLITHER_MAP = {
    "reentrancy-eth": "V9", "reentrancy-no-eth": "V9", "reentrancy-benign": "V9",
    "unchecked-lowlevel": "V9", "unchecked-transfer": "V9", "unchecked-send": "V9",
    "controlled-delegatecall": "V9", "uninitialized-state": "V9",
    "arbitrary-send-eth": "V4", "arbitrary-send": "V4", "suicidal": "V4",
    "unprotected-upgrade": "V4", "missing-zero-check": "V4",
    "divide-before-multiply": "V10", "incorrect-equality": "V10",
    "unused-return": "V6", "timestamp": "V7", "weak-prng": "V10",
}


def slither_available() -> bool:
    return shutil.which("slither") is not None


def run_slither(cfg: Config, timeout: int = 600) -> dict:
    """Run Slither per corpus file and cache detector hits per slice id."""
    if not slither_available():
        return {"ok": False, "reason": "slither not installed (pip install slither-analyzer)"}
    slices = load_slices(cfg)
    by_file: dict[tuple[str, str], list[Slice]] = {}
    for s in slices:
        if s.file.endswith(".sol"):
            by_file.setdefault((s.protocol, s.file), []).append(s)

    hits_per_slice: dict[str, list[str]] = {}
    analysed = failed = 0
    for (proto, rel), group in by_file.items():
        path = cfg.path("raw") / proto / rel
        if not path.exists():
            continue
        try:
            p = subprocess.run(["slither", str(path), "--json", "-"],
                               capture_output=True, text=True, timeout=timeout)
            payload = json.loads(p.stdout or "{}")
        except Exception:
            failed += 1
            continue
        analysed += 1
        for det in (payload.get("results", {}) or {}).get("detectors", []) or []:
            check = det.get("check", "")
            for el in det.get("elements", []) or []:
                fname = el.get("name", "")
                for s in group:
                    if s.function == fname:
                        hits_per_slice.setdefault(s.id, []).append(check)
    out = cfg.path("processed") / "slither.json"
    out.write_text(json.dumps(hits_per_slice, indent=1), "utf-8")
    return {"ok": True, "files_analysed": analysed, "files_failed": failed,
            "slices_with_hits": len(hits_per_slice), "output": str(out)}


def slither_findings(cfg: Config, out_name: str = "findings_slither.json") -> dict:
    """Turn cached Slither hits into a comparable findings file."""
    p = cfg.path("processed") / "slither.json"
    hits: dict[str, list[str]] = json.loads(p.read_text("utf-8")) if p.exists() else {}
    kb = KnowledgeBase.load(cfg.knowledge_dir)
    out: list[Finding] = []
    # Emit one finding per (slice, retrieved class), exactly as the LLM run
    # does. Previously this enumerated ALL ten classes for every slice while
    # the LLM run only ever sees `retrieval.top_k`, so the baseline was scored
    # on full class coverage and the LLM on a subset — the two columns of the
    # ablation table were not measuring the same thing.
    top_k = int(cfg.get("retrieval.top_k", 3))
    for s in load_slices(cfg):
        mapped = {SLITHER_MAP[h] for h in hits.get(s.id, []) if h in SLITHER_MAP}
        for vc, _ in kb.retrieve(s.code, top_k=top_k):
            vid = vc.id
            detected = vid in mapped
            out.append(Finding(
                slice_id=s.id, protocol=s.protocol, tier=s.tier, file=s.file,
                contract=s.contract, function=s.function, start_line=s.start_line,
                vuln_id=vid, report_category=vc.report_category, title=vc.title,
                detected=detected, confidence=1.0 if detected else 0.0,
                severity=vc.severity, score=1.0 if detected else 0.0,
                provider="slither", model="slither", mitigation=vc.mitigation))
    path = cfg.path("results") / out_name
    path.write_text(json.dumps([asdict(f) for f in out], indent=1), "utf-8")
    return {"findings": len(out), "detected": sum(1 for f in out if f.detected),
            "output": str(path)}


def static_only_findings(cfg: Config, out_name: str = "findings_static.json") -> dict:
    """Knowledge base rules with no LLM — isolates the model's contribution."""
    kb = KnowledgeBase.load(cfg.knowledge_dir)
    sl_hits: dict[str, list[str]] = {}
    p = cfg.path("processed") / "slither.json"
    if p.exists():
        sl_hits = json.loads(p.read_text("utf-8"))
    out: list[Finding] = []
    for s in load_slices(cfg):
        for vc, _ in kb.retrieve(s.code, top_k=int(cfg.get("retrieval.top_k", 3))):
            c = confirm(vc, s.code, sl_hits.get(s.id, []))
            out.append(Finding(
                slice_id=s.id, protocol=s.protocol, tier=s.tier, file=s.file,
                contract=s.contract, function=s.function, start_line=s.start_line,
                vuln_id=vc.id, report_category=vc.report_category, title=vc.title,
                detected=c.passed, confidence=1.0 if c.passed else 0.0,
                severity=vc.severity, static_confirmation=c.as_dict(),
                score=1.0 if c.passed else 0.0, provider="static", model="rules",
                mitigation=vc.mitigation))
    path = cfg.path("results") / out_name
    path.write_text(json.dumps([asdict(f) for f in out], indent=1), "utf-8")
    return {"findings": len(out), "detected": sum(1 for f in out if f.detected),
            "output": str(path)}
