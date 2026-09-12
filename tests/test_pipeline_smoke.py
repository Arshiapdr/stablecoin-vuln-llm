"""End-to-end smoke test: knowledge base -> slice -> detect (mock) -> evaluate.

Runs entirely offline on a synthetic mini-corpus, so CI needs no network.
"""
import json

from asv.config import Config
from asv.corpus import SourceFile
from asv.detect import analyse_slice
from asv.kb import KnowledgeBase
from asv.llm import Router
from asv.slicing import slice_file

cfg = Config.load()
kb = KnowledgeBase.load(cfg.knowledge_dir)

VULNERABLE = """
pragma solidity ^0.8.0;
contract AlgoStable {
    address public oracle;
    function swapToShare(uint256 amount) external {
        uint256 price = IOracle(oracle).consult();
        _burn(msg.sender, amount);
        _mint(msg.sender, amount * 1e18 / price);
    }
}
"""

SAFE = """
pragma solidity ^0.8.0;
contract SafeStable {
    uint256 public constant MAX_MINT_PER_EPOCH = 1e21;
    function swapToShare(uint256 amount) external nonReentrant whenNotPaused {
        (, int256 a,, uint256 updatedAt,) = feed.latestRoundData();
        require(block.timestamp - updatedAt <= 3600, "stale");
        uint256 twap = twapOracle.consult(1800);
        require(amount <= MAX_MINT_PER_EPOCH, "mint cap");
        _burn(msg.sender, amount);
        _mint(msg.sender, FullMath.mulDiv(amount, 1e18, twap));
        assert(totalSupply() <= MAX_MINT_PER_EPOCH * epochs);
    }
}
"""


def _slices(text, name):
    sf = SourceFile("demo", "primary", "solidity", "repo", f"contracts/{name}.sol",
                    "0" * 64, text.count("\n"), len(text))
    return slice_file(sf, text, cfg)


def test_vulnerable_contract_is_flagged_and_safe_one_is_not():
    router = Router(cfg, order=["mock"], cache=False)
    vuln = _slices(VULNERABLE, "AlgoStable")[0]
    safe = _slices(SAFE, "SafeStable")[0]

    vf = analyse_slice(vuln, kb, router, cfg)
    sf_ = analyse_slice(safe, kb, router, cfg)

    assert any(f.detected for f in vf), "vulnerable swap should raise at least one class"
    assert not any(f.detected for f in sf_), "guarded swap should raise nothing"


def test_every_finding_carries_a_mitigation_and_is_serialisable():
    router = Router(cfg, order=["mock"], cache=False)
    for f in analyse_slice(_slices(VULNERABLE, "AlgoStable")[0], kb, router, cfg):
        assert f.mitigation and kb.mitigations[f.mitigation]
        json.dumps(f.__dict__)


# --- a dead provider must abort, not produce a full run of empty findings ---
def test_detect_aborts_when_no_call_ever_succeeds(monkeypatch, tmp_path):
    """The failure mode this guards against produced 415 empty findings, an
    evaluation of 0.0 on every metric, and no stated cause."""
    import pytest

    import asv.detect as detect
    import asv.llm as llm
    from asv.config import Config

    cfg = Config.load()
    monkeypatch.setattr(
        llm.Router, "complete",
        lambda self, *a, **k: (setattr(self, "errors", self.errors + 1),
                               setattr(self, "last_error", "HTTP 401: bad key"),
                               llm.LLMResponse("", "none", "none", error="HTTP 401: bad key"))[-1])
    with pytest.raises(RuntimeError, match="consecutive provider failures"):
        detect.run(cfg, provider="mock", limit=20, out_name="__pytest_should_not_exist.json")
    assert not (cfg.path("results") / "__pytest_should_not_exist.json").exists(), \
        "a failed run must not leave a results file behind"
