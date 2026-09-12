import pytest

from asv.config import Config
from asv.kb import KnowledgeBase, confirm

cfg = Config.load()
kb = KnowledgeBase.load(cfg.knowledge_dir)


def test_knowledge_base_is_consistent():
    assert len(kb) == 10
    for vc in kb:
        assert vc.scenario and vc.property
        assert vc.report_category in {"A1", "A2", "A3", "A4", "A5", "A6", "A7"}
        assert kb.mitigation_for(vc.id) is not None


def test_every_report_category_is_covered():
    covered = {vc.report_category for vc in kb}
    assert {"A1", "A2", "A3", "A4", "A5", "A6", "A7"} <= covered


def test_the_added_categories_are_named_not_placeholders():
    """A6/A7 were carried as the placeholder `NEW` while the report still had
    only five categories. The report now names them (Execution-Path Defects,
    Accounting-Invariant Defects), so `NEW` must not survive anywhere: it would
    print into findings.json, prevention.json and table t1 as a category the
    thesis does not contain."""
    assert {vc.report_category for vc in kb}.isdisjoint({"NEW"})
    assert kb.classes["V9"].report_category == "A6"
    assert kb.classes["V10"].report_category == "A7"
    # both added classes are implementation-layer by definition
    assert kb.classes["V9"].layer == kb.classes["V10"].layer == "implementation"


def test_confirm_flags_missing_guard():
    vc = kb.classes["V6"]
    vulnerable = "function p() public view returns (uint) { return IOracle(o).consult(); }"
    safe = ("function p() public view returns (uint) {"
            " (,int a,,uint updatedAt,) = feed.latestRoundData();"
            " require(block.timestamp - updatedAt < 3600); return twap(); }")
    assert confirm(vc, vulnerable).passed is True
    assert confirm(vc, safe).passed is False


def test_confirm_requires_the_scenario():
    vc = kb.classes["V5"]
    assert confirm(vc, "function noop() public {}").passed is False


def test_retrieval_is_deterministic_and_ranked():
    code = "function redeem(uint a) external { collectRedemption(); redemption_fee; }"
    a = [v.id for v, _ in kb.retrieve(code, top_k=4)]
    b = [v.id for v, _ in kb.retrieve(code, top_k=4)]
    assert a == b
    assert "V3" in a


# --- static checks must not be Solidity-only --------------------------------
def test_static_confirmation_is_not_biased_against_non_solidity_protocols():
    """Measured before the cross-language vocabulary existed: static
    confirmation fired on 15.6% of Solidity (slice, class) pairs, 7.6% of Go
    and 2.1% of Ride. Neutrino was 7x less likely to confirm than a Solidity
    protocol for reasons of keyword vocabulary, and because confirmation is an
    AND gate on detection, that capped recall on the two non-Solidity study
    protocols no matter how good the model was.
    """
    import collections

    from asv.config import Config
    from asv.kb import KnowledgeBase, confirm
    from asv.slicing import load as load_slices

    cfg = Config.load()
    if not (cfg.path("processed") / "slices.json").exists():
        pytest.skip("needs a built corpus")
    kb = KnowledgeBase.load(cfg.knowledge_dir)
    meta = cfg.protocol_meta()
    rate = collections.defaultdict(lambda: [0, 0])
    for s in (x for x in load_slices(cfg) if x.tier != "benchmark"):
        lang = meta.get(s.protocol, {}).get("language", "solidity")
        for vc, _ in kb.retrieve(s.code, top_k=4):
            rate[lang][0] += confirm(vc, s.code, []).passed
            rate[lang][1] += 1
    pct = {k: a / b for k, (a, b) in rate.items() if b}
    assert {"solidity", "go", "ride"} <= set(pct)
    # No language may confirm at less than half the Solidity rate.
    for lang, p in pct.items():
        assert p >= 0.5 * pct["solidity"], f"{lang} {p:.1%} vs solidity {pct['solidity']:.1%}"


def test_a_privileged_setter_is_recognised_by_the_function_it_declares():
    """`function setBondOracle(address) onlyOperator` calls nothing on V4's
    list -- the setter IS the declaration. A literal-only check called this
    'no scenario call pattern found'."""
    from asv.config import Config
    from asv.kb import KnowledgeBase, confirm
    kb = KnowledgeBase.load(Config.load().knowledge_dir)
    code = "function setBondOracle(address _newOracle) public onlyOperator { bOracle = _newOracle; }"
    assert confirm(kb.classes["V4"], code, []).passed


def test_redemption_friction_is_recognised_under_a_synonym():
    """Iron Finance spells its cooldown `redemption_delay`."""
    from asv.config import Config
    from asv.kb import KnowledgeBase, confirm
    kb = KnowledgeBase.load(Config.load().knowledge_dir)
    code = ("function collectRedemption() external { "
            "require((last_redeemed[msg.sender] + redemption_delay) <= block.number); }")
    assert confirm(kb.classes["V3"], code, []).passed


def test_block_number_alone_is_not_redemption_friction():
    """Guard against the loose form of the fix: `\\w*lock\\w*` matches
    'block.number', which would find friction in every function that reads
    the clock."""
    from asv.config import Config
    from asv.kb import KnowledgeBase, confirm
    kb = KnowledgeBase.load(Config.load().knowledge_dir)
    code = "function redeem(uint256 amount) external { last = block.number; _burn(msg.sender, amount); }"
    assert not confirm(kb.classes["V3"], code, []).passed


def test_a_malformed_pattern_is_skipped_not_raised():
    from asv.kb import _regex_hits
    assert _regex_hits(["([unclosed"], "anything") == []
