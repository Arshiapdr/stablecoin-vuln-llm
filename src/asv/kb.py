"""Vulnerability knowledge base: loading, retrieval and static confirmation.

The knowledge base is the project's main reusable artifact. Each class is a
scenario/property pair plus mechanical checks, so an LLM answer can always be
confirmed or contradicted without trusting the model.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

import yaml


@dataclass
class VulnClass:
    id: str
    title: str
    report_category: str
    layer: str
    severity: str
    scenario: str
    property: str
    evidence: str = ""
    key_variables: list[str] = field(default_factory=list)
    static_checks: dict = field(default_factory=dict)
    invariants: list[str] = field(default_factory=list)
    retrieval_hints: list[str] = field(default_factory=list)
    applies_to: list[str] = field(default_factory=lambda: ["all"])
    mitigation: str = ""

    # tokens used for retrieval scoring
    @property
    def retrieval_terms(self) -> list[str]:
        terms = list(self.static_checks.get("must_call", []))
        terms += list(self.static_checks.get("must_have", []))
        terms += list(self.key_variables)
        terms += list(self.retrieval_hints)
        return [t.strip("(").strip() for t in terms if t]


@dataclass
class Mitigation:
    id: str
    for_: str
    title: str
    actions: list[str]
    patch: str


class KnowledgeBase:
    def __init__(self, classes: dict[str, VulnClass], mitigations: dict[str, Mitigation]):
        self.classes = classes
        self.mitigations = mitigations

    # ---- loading -----------------------------------------------------------
    @classmethod
    def load(cls, knowledge_dir: Path) -> "KnowledgeBase":
        vraw = yaml.safe_load((knowledge_dir / "vulnerabilities.yaml").read_text("utf-8"))
        mraw = yaml.safe_load((knowledge_dir / "mitigations.yaml").read_text("utf-8"))
        classes = {
            k: VulnClass(
                id=k,
                title=v["title"],
                report_category=v.get("report_category", ""),
                layer=v.get("layer", ""),
                severity=v.get("severity", "medium"),
                scenario=v["scenario"].strip(),
                property=v["property"].strip(),
                evidence=(v.get("evidence") or "").strip(),
                key_variables=v.get("key_variables", []),
                static_checks=v.get("static_checks", {}) or {},
                invariants=v.get("invariants", []) or [],
                retrieval_hints=v.get("retrieval_hints", []) or [],
                applies_to=v.get("applies_to", ["all"]) or ["all"],
                mitigation=v.get("mitigation", ""),
            )
            for k, v in vraw.items()
        }
        mits = {
            k: Mitigation(
                id=k, for_=m["for"], title=m["title"],
                actions=m.get("actions", []), patch=(m.get("patch") or "").strip(),
            )
            for k, m in mraw.items()
        }
        # consistency: every class points at an existing mitigation
        missing = {c.mitigation for c in classes.values()} - set(mits)
        if missing:
            raise ValueError(f"knowledge base references unknown mitigations: {missing}")
        return cls(classes, mits)

    def __len__(self) -> int:
        return len(self.classes)

    def __iter__(self) -> Iterable[VulnClass]:
        return iter(self.classes.values())

    def mitigation_for(self, vuln_id: str) -> Mitigation | None:
        vc = self.classes.get(vuln_id)
        return self.mitigations.get(vc.mitigation) if vc else None

    # ---- retrieval ---------------------------------------------------------
    def retrieve(self, code: str, top_k: int = 4, always: list[str] | None = None,
                 min_score: float = 0.0) -> list[tuple[VulnClass, float]]:
        """Rank classes by how many of their trigger terms occur in the code.

        Deliberately simple and deterministic: no embedding model, no network,
        and fully explainable in the thesis. Score is a length-normalised term
        hit rate so classes with long term lists are not favoured.
        """
        low = code.lower()
        scored: list[tuple[VulnClass, float]] = []
        for vc in self.classes.values():
            terms = vc.retrieval_terms
            if not terms:
                scored.append((vc, 0.0))
                continue
            hits = sum(1 for t in terms if t.lower() in low)
            score = hits / math.sqrt(len(terms))
            scored.append((vc, score))
        scored.sort(key=lambda x: (-x[1], x[0].id))
        out = [(vc, s) for vc, s in scored if s > min_score][:top_k]
        forced = [c for c in (always or []) if c in self.classes]
        for fid in forced:
            if all(vc.id != fid for vc, _ in out):
                out.append((self.classes[fid], 0.0))
        return out


# ---------------------------------------------------------------------------
# Static confirmation: the mechanical half of the detector.
# ---------------------------------------------------------------------------

@dataclass
class Confirmation:
    passed: bool
    checks: dict[str, bool]
    captured: dict[str, list[str]]
    reason: str

    def as_dict(self) -> dict:
        return {"passed": self.passed, "checks": self.checks,
                "captured": self.captured, "reason": self.reason}


def _regex_hits(patterns: list[str] | None, code: str) -> list[str]:
    """Regex arm of a static check.

    Literal substrings cannot express "any privileged setter" or "a Cosmos
    keeper method", so each class may also carry `*_patterns`. Measured before
    this existed, static confirmation fired on 15.6% of Solidity (slice, class)
    pairs but only 7.6% of Go and 2.1% of Ride ones -- Neutrino was seven times
    less likely to confirm than a Solidity protocol, which is a property of the
    keyword lists, not of the protocols. A malformed pattern is skipped rather
    than raised: a typo in the knowledge base must not abort a run.
    """
    out: list[str] = []
    for pat in patterns or []:
        try:
            if re.search(pat, code, re.IGNORECASE):
                out.append(f"re:{pat}")
        except re.error:
            continue
    return out


def confirm(vc: VulnClass, code: str, slither_hits: list[str] | None = None) -> Confirmation:
    """Check a class's static conditions against a code slice.

    - must_call : at least one pattern must appear   (the scenario is present)
    - must_lack : none of these guards may appear    (the guard is missing)
    - must_have : at least one must appear           (the friction is present)
    - slither   : at least one detector must have fired, if signals are supplied
    """
    checks: dict[str, bool] = {}
    captured: dict[str, list[str]] = {}
    sc = vc.static_checks
    low = code.lower()
    reasons: list[str] = []

    if sc.get("must_call") or sc.get("must_call_patterns"):
        hit = [p for p in sc.get("must_call", []) if p.lower() in low]
        hit += _regex_hits(sc.get("must_call_patterns"), code)
        checks["must_call"] = bool(hit)
        captured["must_call_hits"] = hit
        if not hit:
            reasons.append("no scenario call pattern found")

    if sc.get("must_lack") or sc.get("must_lack_patterns"):
        present = [p for p in sc.get("must_lack", []) if p.lower() in low]
        present += _regex_hits(sc.get("must_lack_patterns"), code)
        checks["must_lack"] = not present
        captured["guards_present"] = present
        if present:
            reasons.append(f"guard present: {', '.join(present[:4])}")

    if sc.get("must_have") or sc.get("must_have_patterns"):
        hit = [p for p in sc.get("must_have", []) if p.lower() in low]
        hit += _regex_hits(sc.get("must_have_patterns"), code)
        checks["must_have"] = bool(hit)
        captured["must_have_hits"] = hit
        if not hit:
            reasons.append("required feature not found")

    if sc.get("slither") and slither_hits is not None:
        hit = [d for d in sc["slither"] if d in slither_hits]
        checks["slither"] = bool(hit)
        captured["slither_hits"] = hit
        # a missing Slither signal weakens but does not by itself refute

    for pat in sc.get("capture_numbers", []) or []:
        try:
            captured.setdefault("numbers", []).extend(re.findall(pat, code))
        except re.error:
            pass

    hard = [v for k, v in checks.items() if k in ("must_call", "must_lack", "must_have")]
    passed = all(hard) if hard else True
    return Confirmation(
        passed=passed,
        checks=checks,
        captured=captured,
        reason="; ".join(reasons) if reasons else "all static conditions satisfied",
    )
