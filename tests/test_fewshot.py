"""Few-shot exemplars must never leak the answer for the protocol under audit.

Showing the model Terra's `handleSwapRequest` as a worked example and then
scoring the run on Terra's `handleSwapRequest` would hand it the answer and
credit it for repeating it — the same shape as the mock-scaffolding leak found
earlier. `select()` applies leave-one-protocol-out before anything else; these
tests hold it to that.
"""
from __future__ import annotations

import pytest

from asv.config import Config
from asv.fewshot import Exemplar, build_pool, render_block, select
from asv.kb import KnowledgeBase


def _ex(protocol: str, vuln_id: str, kind: str = "positive") -> Exemplar:
    return Exemplar(protocol=protocol, vuln_id=vuln_id,
                    signature=f"f_{protocol}()", code="function f() { }",
                    verdict={"vuln_id": vuln_id, "property_match": kind == "positive"},
                    kind=kind)


POOL = [
    _ex("terra-classic", "V1"), _ex("basis-cash", "V1"),
    _ex("iron-finance", "V2"), _ex("beanstalk", "V5"),
    _ex("liquity", "V1", "negative"), _ex("mento", "V6", "negative"),
]


def test_no_exemplar_ever_comes_from_the_protocol_under_audit():
    for target in {e.protocol for e in POOL}:
        for vid in {e.vuln_id for e in POOL}:
            for e in select(POOL, vid, target):
                assert e.protocol != target, (
                    f"leak: auditing {target} would show it its own {e.vuln_id} example")


def test_same_class_exemplars_are_preferred_when_available():
    got = select(POOL, "V1", "terra-classic", n_positive=1, n_negative=0)
    assert [e.protocol for e in got] == ["basis-cash"]
    assert got[0].vuln_id == "V1"


def test_falls_back_to_another_class_rather_than_returning_nothing():
    """Only terra-classic has a V1 positive here, and it is excluded."""
    pool = [_ex("terra-classic", "V1"), _ex("iron-finance", "V2")]
    got = select(pool, "V1", "terra-classic", n_positive=1, n_negative=0)
    assert len(got) == 1 and got[0].vuln_id == "V2"


def test_selection_is_deterministic():
    a = select(POOL, "V1", "beanstalk")
    b = select(POOL, "V1", "beanstalk")
    assert [(e.protocol, e.vuln_id, e.kind) for e in a] == \
           [(e.protocol, e.vuln_id, e.kind) for e in b]


def test_both_a_positive_and_a_negative_are_shown():
    got = select(POOL, "V1", "terra-classic")
    kinds = {e.kind for e in got}
    assert kinds == {"positive", "negative"}, (
        "the model must see a correct rejection as well as a correct detection")


def test_render_block_is_empty_when_few_shot_is_off():
    assert render_block([]) == ""


def test_prompt_carries_examples_only_when_exemplars_are_passed():
    from asv.detect import _auditor_prompt
    from asv.slicing import Slice
    cfg = Config.load()
    kb = KnowledgeBase.load(cfg.knowledge_dir)
    sl = Slice(id="x", protocol="terra-classic", tier="study", language="solidity",
               file="a/B.sol", contract="B", function="f", signature="f()",
               start_line=1, end_line=3, code="function f() public { _mint(); }")
    vc = kb.classes["V1"]

    plain = _auditor_prompt(sl, vc, True, [], False)
    assert "WORKED EXAMPLES" not in plain

    shots = select(POOL, "V1", sl.protocol)
    withex = _auditor_prompt(sl, vc, True, [], False, exemplars=shots)
    assert "WORKED EXAMPLES" in withex
    assert "terra-classic" not in withex.split("## TASK")[0].split(
        "WORKED EXAMPLES")[1], "the exemplar block must not mention the audited protocol"


@pytest.mark.skipif(not (Config.load().path("processed") / "slices.json").exists(),
                    reason="needs a built corpus")
def test_real_pool_is_non_trivial_and_leak_free():
    from asv.slicing import load as load_slices
    cfg = Config.load()
    kb = KnowledgeBase.load(cfg.knowledge_dir)
    pool = build_pool(cfg, load_slices(cfg), kb)
    assert any(e.kind == "positive" for e in pool)
    assert any(e.kind == "negative" for e in pool)
    for target in {e.protocol for e in pool}:
        for e in select(pool, "V1", target):
            assert e.protocol != target
