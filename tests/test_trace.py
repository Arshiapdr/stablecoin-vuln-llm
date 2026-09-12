"""The trace tool must never leak the mock scaffolding into a real prompt."""
from asv.config import Config
from asv.detect import _auditor_prompt
from asv.kb import KnowledgeBase
from asv.corpus import SourceFile
from asv.slicing import slice_file

cfg = Config.load()
kb = KnowledgeBase.load(cfg.knowledge_dir)

SRC = """
pragma solidity ^0.8.0;
contract S {
    function swap(uint256 a) external {
        uint256 p = IOracle(o).consult();
        _burn(msg.sender, a);
        _mint(msg.sender, a / p);
    }
}
"""


def _slice():
    sf = SourceFile("d", "primary", "solidity", "r", "contracts/S.sol", "0" * 64, 1, 1)
    return slice_file(sf, SRC, cfg)[0]


def test_real_prompt_has_no_precheck_or_hint():
    p = _auditor_prompt(_slice(), kb.classes["V1"], True, [], False, mock_mode=False)
    assert "static_precheck" not in p
    assert "must_call_hint" not in p
    assert "## TASK" in p and "OUTPUT SCHEMA" in p


def test_mock_prompt_carries_the_scaffolding():
    p = _auditor_prompt(_slice(), kb.classes["V1"], True, [], False, mock_mode=True)
    assert "static_precheck: true" in p
    assert "must_call_hint" in p


def test_prompt_contains_the_code_and_the_class_definition():
    vc = kb.classes["V6"]
    p = _auditor_prompt(_slice(), vc, False, [], False)
    assert "consult()" in p
    assert vc.scenario.split()[0] in p
