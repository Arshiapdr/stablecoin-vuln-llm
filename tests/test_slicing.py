from asv.config import Config
from asv.corpus import SourceFile
from asv.slicing import normalize_identifiers, slice_file

cfg = Config.load()

SOL = """
pragma solidity ^0.8.0;
contract Pool {
    uint256 public redemption_fee;
    address public oracle;
    modifier onlyOwner() { require(msg.sender == owner); _; }

    function getPrice() public view returns (uint256) {
        return IOracle(oracle).consult();
    }

    function setOracle(address o) external onlyOwner {
        oracle = o;
    }
}
"""


def _sf():
    return SourceFile("demo", "primary", "solidity", "repo", "contracts/Pool.sol",
                      "0" * 64, SOL.count("\n"), len(SOL))


def test_slices_solidity_functions():
    slices = slice_file(_sf(), SOL, cfg)
    names = {s.function for s in slices}
    assert {"getPrice", "setOracle"} <= names
    s = next(s for s in slices if s.function == "setOracle")
    assert s.contract == "Pool"
    assert "onlyOwner" in s.modifiers or "onlyOwner" in s.code


def test_slice_carries_line_numbers_and_budget():
    for s in slice_file(_sf(), SOL, cfg):
        assert s.start_line >= 1 and s.end_line >= s.start_line
        assert s.approx_tokens <= int(cfg.get("preprocess.max_slice_tokens", 4000))


def test_identifier_normalisation_keeps_keywords():
    out = normalize_identifiers("function transferTokens(uint256 amount) public { require(amount > 0); }")
    assert "require" in out and "public" in out
    assert "transferTokens" not in out


# --- regressions from the slicing audit -------------------------------------

def test_declared_name_returns_the_variable_not_the_initialiser():
    """`split()[-1].split("=")[0]` returned the VALUE for initialised decls."""
    from asv.slicing import declared_name
    assert declared_name("uint256 public constant MAX = 100;") == "MAX"
    assert declared_name("uint256 public rewardRate = 0;") == "rewardRate"
    assert declared_name("address public oracle;") == "oracle"
    # "=>" is not an assignment
    assert declared_name("mapping(address => uint256) public balances;") == "balances"
    assert declared_name(
        "mapping(address => mapping(address => uint)) internal allowed;") == "allowed"
    assert declared_name("IOracle public oracle = IOracle(address(0));") == "oracle"


def test_slice_ids_are_unique_per_definition_site():
    """Go methods on different receivers shared a name+signature and collided."""
    from asv.config import Config
    from asv.corpus import SourceFile
    from asv.slicing import slice_file
    src = (
        "package p\n"
        "func (k Keeper) GetSigners() []byte {\n\treturn kA\n}\n"
        "func (s Server) GetSigners() []byte {\n\treturn sB\n}\n"
    )
    f = SourceFile(protocol="x", tier="primary", language="go", repo="r",
                   rel_path="a/msgs.go", sha256="0" * 64, n_lines=6, n_bytes=len(src))
    got = slice_file(f, src, Config.load())
    assert len(got) == 2
    assert got[0].id != got[1].id, "same name in one file must not share an id"
