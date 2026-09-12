"""The two classification axes must stay independent.

`tier` (the protocol's role in the evaluation) and `algorithmic` (a property of
its mechanism) were once collapsed into one field, which put Fei — fully
collateral-backed — in the algorithmic study set because it had a famous
incident, while Reflexer RAI — a PID controller that genuinely adjusts the peg
algorithmically — sat in the controls because its peg held.
"""
from __future__ import annotations

import pytest

from asv.config import Config

TIERS = {"study", "control"}
ALGO = {"pure", "partial", "none"}


@pytest.fixture(scope="module")
def protos():
    return {p["name"]: p for p in Config.load().protocol_list()}


def test_every_protocol_declares_both_axes(protos):
    for name, p in protos.items():
        assert p.get("tier") in TIERS, f"{name}: bad tier {p.get('tier')!r}"
        assert p.get("algorithmic") in ALGO, f"{name}: bad algorithmic"


def test_the_axes_are_independent_not_a_relabelled_tier(protos):
    """If they were the same field, these two rows could not exist."""
    assert protos["beanstalk-patched"]["algorithmic"] == "pure"
    assert protos["beanstalk-patched"]["tier"] == "control"
    assert protos["reflexer-rai"]["algorithmic"] == "partial"
    assert protos["reflexer-rai"]["tier"] == "control"


def test_fei_is_a_control_not_an_algorithmic_study_protocol(protos):
    """FEI is backed by exogenous collateral; its incident is a code defect in
    a different repository, not evidence about an algorithmic mechanism."""
    assert protos["fei-protocol"]["tier"] == "control"
    assert protos["fei-protocol"]["algorithmic"] == "none"


def test_mento_is_partial_because_its_code_mints_and_burns(protos):
    """Mento was classified `none` by reputation — "reserve-backed, therefore
    collateral-backed" — until the code was actually read.

    contracts/swap/Broker.sol transferOut() calls `IERC20(token).safeMint(...)`
    for a stable asset and safeBurn() on the way in, so supply expands and
    contracts with swap flow. contracts/swap/BiPoolManager.sol
    getUpdatedBuckets() re-anchors virtual buckets to an oracle rate, which are
    then traded along ConstantProduct/ConstantSumPricingModule. That is an
    algorithmic controller on top of a real collateral reserve — `partial`.

    Figure 2 and Table 2 render the `algorithmic` field directly, so a
    regression here would print "collateral-backed" under a bar for a protocol
    whose own Broker mints its stablecoin on demand.
    """
    assert protos["mento"]["algorithmic"] == "partial"
    assert protos["mento"]["tier"] == "control"


def test_two_independent_partial_controls_exist(protos):
    """RAI and Mento are both algorithmic in mechanism and both held their peg.

    One such row could be an outlier; two make the corpus-level claim — that
    what breaks these designs is the absorbing token, not the algorithm —
    rest on more than a single data point.
    """
    partial_controls = {n for n, p in protos.items()
                        if p["algorithmic"] == "partial" and p["tier"] == "control"}
    assert {"reflexer-rai", "mento"} <= partial_controls, partial_controls


def test_no_control_protocol_carries_a_positive_label():
    """Controls exist to measure false positives; a label here would be a bug."""
    from asv.evaluation import load_labels
    cfg = Config.load()
    controls = {p["name"] for p in cfg.protocol_list("control")}
    for lb in load_labels(cfg):
        assert lb.protocol not in controls, (
            f"{lb.protocol} is a control but carries a {lb.vuln_id} label")


def test_family_no_longer_encodes_the_tier(protos):
    """`control_cdp` / `control_basket` re-encoded role inside the mechanism
    descriptor, which is the same conflation one level down."""
    for name, p in protos.items():
        assert not p["family"].startswith("control_"), (
            f"{name}: family {p['family']!r} encodes role, not mechanism")


def test_pure_and_partial_split_matches_the_intended_sets(protos):
    pure = {n for n, p in protos.items() if p["algorithmic"] == "pure"}
    partial = {n for n, p in protos.items() if p["algorithmic"] == "partial"}
    assert {"frax", "iron-finance", "angle-protocol"} <= partial
    assert {"terra-classic", "neutrino", "basis-cash", "empty-set-dollar",
            "ampleforth", "yam-finance", "beanstalk"} <= pure


def test_protocol_list_filters_on_either_axis():
    cfg = Config.load()
    assert len(cfg.protocol_list("study")) == 10
    assert len(cfg.protocol_list("control")) == 6
    assert len(cfg.protocol_list(algorithmic="pure")) == 8      # incl. patched
    assert len(cfg.protocol_list("study", algorithmic="pure")) == 7
    # "primary" stays accepted as a deprecated alias
    assert cfg.protocol_list("primary") == cfg.protocol_list("study")


def test_applicability_matrix_counts_only_the_study_set():
    from asv.report import table_applicability
    t = table_applicability(Config.load())
    hdr = " ".join(t.header)
    assert "pcv_backed" not in hdr, (
        "pcv_backed has no study-set protocol left; it must not appear as a column")
    assert "dual_token" in hdr and "rebase" in hdr


# --- the critic's standard must match how the class is defined --------------
def test_design_classes_are_not_judged_by_the_exploitability_rubric():
    """A governance class cannot be reviewed by a rule that rejects privilege.

    V4 is defined as "authority is a single EOA rather than multisig+timelock".
    The implementation rubric zeroes any finding where "the attacker cannot
    obtain the required privilege", so applying it to V4 rejects the class by
    construction -- observed as 16/16 ground-truth rejections with
    correctness=0 in a real run.
    """
    from asv.config import Config
    from asv.detect import CRITIC_SYSTEM, CRITIC_SYSTEM_DESIGN, critic_system
    from asv.kb import KnowledgeBase

    kb = KnowledgeBase.load(Config.load().knowledge_dir)
    for vc in kb:
        chosen = critic_system(vc)
        if vc.layer == "implementation":
            assert chosen is CRITIC_SYSTEM, vc.id
        else:
            assert chosen is CRITIC_SYSTEM_DESIGN, vc.id
            assert "cannot obtain the required privilege" not in chosen, vc.id

    assert critic_system(kb.classes["V4"]) is CRITIC_SYSTEM_DESIGN
    assert critic_system(kb.classes["V9"]) is CRITIC_SYSTEM
    # both rubrics stay adversarial and evidence-bound
    for r in (CRITIC_SYSTEM, CRITIC_SYSTEM_DESIGN):
        assert "default position is" in r and "WRONG" in r
        assert "was not supplied" in r


def test_every_knowledge_base_class_gets_a_rubric():
    from asv.config import Config
    from asv.detect import critic_system
    from asv.kb import KnowledgeBase
    kb = KnowledgeBase.load(Config.load().knowledge_dir)
    assert {vc.layer for vc in kb} <= {"implementation", "economic", "governance", "oracle"}
    assert all(critic_system(vc).strip() for vc in kb)


def test_both_rubrics_forbid_a_confirmed_verdict_with_zero_correctness():
    """Observed in a real run: 7 of 16 ground-truth findings came back
    verdict='confirmed' with correctness=0 and profitability 7-9. The gate
    needs both, so a self-contradicting reply silently becomes a miss."""
    from asv.detect import CRITIC_SYSTEM, CRITIC_SYSTEM_DESIGN
    for r in (CRITIC_SYSTEM, CRITIC_SYSTEM_DESIGN):
        assert "verdict and the scores must agree" in r
        assert 'Never output "confirmed" together with correctness 0' in r
