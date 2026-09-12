"""Regressions for the two ways this project could silently corrupt its own
evaluation: a pinned protocol quietly resolving to the wrong tree, and the
external benchmark leaking into the headline stablecoin metrics.

Both failures are invisible in the output — the pipeline still produces
plausible numbers — so they are guarded by tests rather than by inspection.
"""
from __future__ import annotations

from dataclasses import replace

from asv.corpus import _is_commit_sha
from asv.config import Config
from asv.evaluation import load_labels


# --- commit pinning ---------------------------------------------------------

def test_commit_sha_is_distinguished_from_a_branch_name():
    assert _is_commit_sha("e9f49910e287e7a7afaa6db8f536b7194728b0af")
    assert _is_commit_sha("e9f4991")
    # branch names must NOT be treated as commits, or they lose their fallback
    assert not _is_commit_sha("main")
    assert not _is_commit_sha("master")
    assert not _is_commit_sha("develop")
    assert not _is_commit_sha("")
    # 'deadbeef' is hex, but so is a plausible branch; length keeps short
    # non-hex names out and we accept the hex-looking ones deliberately.
    assert not _is_commit_sha("release/v2")


def test_beanstalk_is_pinned_to_a_commit_and_paired_with_its_patched_tree():
    """The V5 label only exists in the pre-attack tree.

    If someone changes `beanstalk` back to a branch, the ground-truth label
    for emergencyCommit would point at code that no longer exists and V5 would
    silently become unmeasurable.
    """
    cfg = Config.load()
    protos = {p["name"]: p for p in cfg.protocol_list()}
    assert "beanstalk" in protos, "the pre-attack Beanstalk tree is required for V5"
    assert _is_commit_sha(protos["beanstalk"]["ref"]), (
        "beanstalk must stay pinned to a pre-2022-04-17 commit, not a branch")
    assert protos["beanstalk"]["tier"] == "study"

    assert "beanstalk-patched" in protos, "the patched half of the A/B pair is required"
    assert protos["beanstalk-patched"]["ref"] == "master"
    assert protos["beanstalk-patched"]["tier"] == "control"
    # same repository, two states — that is what makes it a controlled pair
    assert protos["beanstalk"]["repo"] == protos["beanstalk-patched"]["repo"]


def test_v5_label_targets_the_pinned_tree_not_the_patched_one():
    cfg = Config.load()
    v5 = [lb for lb in load_labels(cfg) if lb.vuln_id == "V5"]
    assert v5, "V5 must carry at least one label now that Beanstalk is pinned"
    for lb in v5:
        assert lb.protocol == "beanstalk", (
            "a V5 label on beanstalk-patched would be a false positive by "
            "construction — the governance facet was removed after the attack")


# --- track separation -------------------------------------------------------

def test_headline_labels_never_include_benchmark_entries():
    """`load_labels` must default to the stablecoin ground truth only."""
    cfg = Config.load()
    for lb in load_labels(cfg):
        assert lb.protocol != "smartbugs-curated", (
            "SmartBugs labels belong in labels/smartbugs.yaml, scored as a "
            "separate track; mixing them changes the headline recall")


def test_benchmark_slices_are_excluded_from_an_unfiltered_detect_run():
    from asv.detect import select_slices
    from asv.slicing import Slice

    def mk(pid: str, protocol: str, tier: str) -> Slice:
        return Slice(
            id=pid, protocol=protocol, tier=tier, language="solidity",
            file=f"{protocol}/C.sol", contract="C", function=f"f{pid}",
            signature=f"function f{pid}()", start_line=1, end_line=5,
            code="function f() public { }", state_vars=[], modifiers=[],
            callees=[], solc_version="0.8.0", n_chars=24, approx_tokens=6,
            normalized_code="function f() public { }")

    rows = [mk("a", "terra-classic", "primary"),
            mk("b", "smartbugs-curated", "benchmark"),
            mk("c", "liquity", "control")]

    class FakeCfg:
        pass

    import asv.detect as detect_mod
    original = detect_mod.load_slices
    detect_mod.load_slices = lambda cfg: rows
    try:
        # unfiltered: benchmark must be dropped
        got = select_slices(FakeCfg(), limit=None, protocols=None)
        assert {s.protocol for s in got} == {"terra-classic", "liquity"}

        # explicitly requested: benchmark must be reachable
        got = select_slices(FakeCfg(), limit=None, protocols=["smartbugs-curated"])
        assert [s.protocol for s in got] == ["smartbugs-curated"]
    finally:
        detect_mod.load_slices = original


def test_source_text_root_override_keeps_benchmarks_readable():
    """Benchmarks live under _benchmarks/<name> but carry a clean protocol name."""
    from asv.corpus import SourceFile
    f = SourceFile(protocol="smartbugs-curated", tier="benchmark",
                   language="solidity", repo="r", rel_path="dataset/x.sol",
                   sha256="0" * 64, n_lines=1, n_bytes=1,
                   root="_benchmarks/smartbugs-curated")
    assert (f.root or f.protocol) == "_benchmarks/smartbugs-curated"
    plain = replace(f, root="")
    assert (plain.root or plain.protocol) == "smartbugs-curated"


# --- the critic decision must not depend on two channels agreeing -----------
def test_a_self_contradicting_critic_reply_is_an_abstention():
    """A reply scoring 10/10 while saying "rejected" is a contradiction, and
    18 of 83 replies did exactly that in a real 7B run. Gating on both
    channels turned the model's inability to restate its own scores into a
    silent miss; the thresholds in pipeline.yaml are the definition."""
    import asv.detect as detect
    from asv.config import Config
    from asv.kb import KnowledgeBase
    from asv.llm import Router
    from asv.slicing import Slice

    cfg = Config.load()
    kb = KnowledgeBase.load(cfg.knowledge_dir)
    vc = kb.classes["V4"]
    sl = Slice(id="x", protocol="p", tier="study", language="solidity",
               file="a/B.sol", contract="B", function="setOracle",
               signature="setOracle(address)", start_line=1, end_line=3,
               code="function setOracle(address o) public onlyOwner { oracle = o; }")

    def fake(system, user, temperature=0.0, max_tokens=None):
        from asv.llm import LLMResponse
        import json as _j
        if "reviewer" in system.lower():
            # scores say yes, the word says no
            return LLMResponse(_j.dumps({"correctness": 10, "severity": 8,
                                         "profitability": 9, "verdict": "rejected",
                                         "rebuttal": ""}), "mock", "m")
        return LLMResponse(_j.dumps({"vuln_id": "V4", "scenario_match": True,
                                     "property_match": True, "confidence": 0.9,
                                     "key_variables": [], "vulnerable_statements": [],
                                     "attack_path": "p", "severity": "high"}), "mock", "m")

    router = Router(cfg, order=["mock"], cache=False)
    router.complete = fake                                  # type: ignore[assignment]
    out = detect.analyse_slice(sl, kb, router, cfg, {}, False, True, False, False)
    hit = [f for f in out if f.vuln_id == "V4"]
    assert hit, "a finding must still be recorded"
    assert hit[0].critic["inconsistent"] is True, "the contradiction must be flagged"
    assert hit[0].critic["verdict"] == "rejected", "the model's own word is preserved"
    assert not hit[0].detected, (
        "a reply scoring 10/10 while writing 'rejected' is not a judgement: it must "
        "abstain, not be resolved in either direction by the pipeline")
