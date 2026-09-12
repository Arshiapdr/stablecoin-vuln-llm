"""Stage 1 — function-level slicing.

Whole-contract prompting performs badly (David et al. report 4.1% precision /
7.6% F1); function-level slicing with context is what GPTScan used to reach
57% precision / 67.8% F1. This module produces those slices without needing a
compiler, so it runs anywhere.

A slice carries: the function body, the state variables it touches, the
modifiers applied to it, and the signatures of the functions it calls.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .config import Config
from .corpus import SourceFile, load as load_corpus, source_text

# --- language patterns ------------------------------------------------------
SOL_FUNC = re.compile(
    r"^[ \t]*function\s+(?P<name>[A-Za-z_]\w*)\s*\((?P<args>[^)]*)\)"
    r"(?P<mods>[^{;]*)(?P<open>\{|;)", re.M)
SOL_STATE = re.compile(
    r"^[ \t]{0,8}(?P<decl>(?:mapping\s*\([^;]*?\)|address|uint\d*|int\d*|bool|bytes\d*|"
    r"string|[A-Z]\w*)(?:\s*\[\s*\])?\s+(?:public|private|internal|constant|immutable|"
    r"override|\s)*[A-Za-z_]\w*\s*(?:=[^;]*)?;)", re.M)
SOL_MODIFIER = re.compile(r"^[ \t]*modifier\s+(?P<name>\w+)\s*\([^)]*\)\s*\{", re.M)
SOL_PRAGMA = re.compile(r"pragma\s+solidity\s+([^;]+);")

GO_FUNC = re.compile(r"^func\s+(?:\([^)]*\)\s*)?(?P<name>[A-Za-z_]\w*)\s*\((?P<args>[^)]*)\)", re.M)
RIDE_FUNC = re.compile(r"^\s*(?:@Callable\([^)]*\)\s*)?func\s+(?P<name>\w+)\s*\((?P<args>[^)]*)\)", re.M)

CALL = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
IDENT = re.compile(r"\b[A-Za-z_]\w{2,}\b")

RESERVED = {
    "require", "assert", "revert", "if", "for", "while", "return", "emit",
    "function", "returns", "memory", "storage", "calldata", "public", "private",
    "internal", "external", "view", "pure", "payable", "uint", "uint256", "int",
    "address", "bool", "bytes", "string", "mapping", "struct", "enum", "new",
    "this", "super", "msg", "block", "tx", "abi", "keccak256", "type",
    "func", "var", "const", "package", "import", "range", "make", "len", "err",
    "nil", "true", "false", "let", "case", "match", "then", "else",
}


@dataclass
class Slice:
    id: str
    protocol: str
    tier: str
    language: str
    file: str
    contract: str
    function: str
    signature: str
    start_line: int
    end_line: int
    code: str
    state_vars: str = ""
    modifiers: str = ""
    callees: list[str] = field(default_factory=list)
    solc_version: str = ""
    n_chars: int = 0
    approx_tokens: int = 0
    normalized_code: str = ""

    def prompt_context(self) -> str:
        parts = []
        if self.state_vars:
            parts.append("// state variables\n" + self.state_vars)
        if self.modifiers:
            parts.append("// modifiers\n" + self.modifiers)
        if self.callees:
            parts.append("// callees: " + ", ".join(sorted(set(self.callees))[:25]))
        return "\n\n".join(parts) if parts else "(none extracted)"


# --- helpers ----------------------------------------------------------------
def _match_block(text: str, open_idx: int) -> int:
    """Return the index just past the closing brace of the block at open_idx."""
    depth, i, n = 0, open_idx, len(text)
    in_line, in_block, in_str, quote = False, False, False, ""
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if in_line:
            if c == "\n":
                in_line = False
        elif in_block:
            if c == "*" and nxt == "/":
                in_block = False; i += 1
        elif in_str:
            if c == "\\":
                i += 1
            elif c == quote:
                in_str = False
        elif c == "/" and nxt == "/":
            in_line = True; i += 1
        elif c == "/" and nxt == "*":
            in_block = True; i += 1
        elif c in "\"'":
            in_str, quote = True, c
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return n


def _contract_of(text: str, pos: int) -> str:
    best = ""
    for m in re.finditer(r"^\s*(?:abstract\s+)?(?:contract|library|interface)\s+(\w+)",
                         text[:pos], re.M):
        best = m.group(1)
    return best or Path("unknown").stem


def normalize_identifiers(code: str) -> str:
    """Contamination control: rename user identifiers to opaque names so the
    model cannot rely on lexical cues (COMPSAC 2026 measures 4.1-8.5pp of
    accuracy coming from names alone)."""
    mapping: dict[str, str] = {}

    def repl(m: re.Match) -> str:
        w = m.group(0)
        if w in RESERVED or w.startswith("_") and len(w) <= 2:
            return w
        if w not in mapping:
            mapping[w] = f"id{len(mapping):03d}"
        return mapping[w]

    return IDENT.sub(repl, code)


def strip_comments(code: str) -> str:
    """Remove // and /* */ comments, respecting string literals.

    Line count is preserved: a removed comment leaves its newlines behind, so
    `start_line`/`end_line` and any line-based reasoning stay valid. String
    literals are not touched — a URL inside a string ("https://x") must survive,
    which is exactly what a naive regex gets wrong.
    """
    out: list[str] = []
    i, n = 0, len(code)
    quote: str | None = None
    while i < n:
        ch = code[i]
        if quote:
            out.append(ch)
            if ch == "\\" and i + 1 < n:      # escaped char inside a string
                out.append(code[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in ('"', "'"):
            quote = ch
            out.append(ch)
            i += 1
            continue
        if ch == "/" and i + 1 < n:
            if code[i + 1] == "/":
                j = code.find("\n", i)
                if j == -1:
                    break                      # trailing line comment, drop it
                i = j                          # newline is emitted next loop
                continue
            if code[i + 1] == "*":
                j = code.find("*/", i + 2)
                seg = code[i:] if j == -1 else code[i:j + 2]
                out.append("\n" * seg.count("\n"))
                i = n if j == -1 else j + 2
                continue
        out.append(ch)
        i += 1
    return "\n".join(line.rstrip() for line in "".join(out).split("\n"))


def approx_tokens(text: str) -> int:
    """Rough token estimate (~4 chars/token) — good enough for budgeting."""
    return max(1, len(text) // 4)


def declared_name(decl: str) -> str:
    """The variable name declared by a state-variable declaration.

    Naive `decl.split()[-1].split("=")[0]` returns the INITIALISER, not the
    name: `uint256 public rewardRate = 0;` yielded "0", so the declaration was
    then matched against any function body containing a literal 0 and attached
    itself to almost every slice as prompt noise. Splitting on "=" also breaks
    on `mapping(address => uint256)`, whose "=>" is not an assignment.

    Take everything before the first top-level `=` that is not part of `=>`,
    then the last identifier in it.
    """
    s = decl.strip().rstrip(";")
    depth, cut = 0, len(s)
    for i, ch in enumerate(s):
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        elif ch == "=" and depth == 0:
            if i + 1 < len(s) and s[i + 1] == ">":   # mapping arrow, not assign
                continue
            if i and s[i - 1] in "=!<>":             # comparison operator
                continue
            cut = i
            break
    idents = re.findall(r"[A-Za-z_]\w*", s[:cut])
    return idents[-1] if idents else ""


# --- per-language extraction ------------------------------------------------
def _solidity_slices(text: str, f: SourceFile, cfg: Config) -> list[Slice]:
    pragma = SOL_PRAGMA.search(text)
    solc = pragma.group(1).strip() if pragma else ""
    state_decls = [m.group("decl").strip() for m in SOL_STATE.finditer(text)][:40]
    mod_bodies: dict[str, str] = {}
    for m in SOL_MODIFIER.finditer(text):
        end = _match_block(text, text.index("{", m.end() - 1))
        mod_bodies[m.group("name")] = text[m.start():end].strip()

    out: list[Slice] = []
    for m in SOL_FUNC.finditer(text):
        if m.group("open") == ";":       # interface declaration
            continue
        start = m.start()
        end = _match_block(text, text.index("{", m.end() - 1))
        code = text[start:end]
        mods = [w for w in re.findall(r"\b(\w+)", m.group("mods") or "")
                if w in mod_bodies or w in {"onlyOwner", "nonReentrant", "onlyRole",
                                            "whenNotPaused", "onlyGovernance"}]
        callees = [c for c in CALL.findall(code) if c not in RESERVED][:40]
        used_state = "\n".join(
            d for d in state_decls
            if (nm := declared_name(d)) and re.search(r"\b" + re.escape(nm) + r"\b", code))
        out.append(_mk_slice(f, cfg, _contract_of(text, start), m.group("name"),
                             f'{m.group("name")}({m.group("args").strip()})',
                             text, start, end, code, used_state,
                             "\n".join(mod_bodies[x] for x in mods if x in mod_bodies),
                             callees, solc))
    return out


def _generic_slices(text: str, f: SourceFile, cfg: Config, pattern: re.Pattern) -> list[Slice]:
    out: list[Slice] = []
    for m in pattern.finditer(text):
        brace = text.find("{", m.end())
        if brace == -1 or brace - m.end() > 200:
            nxt = pattern.search(text, m.end())
            end = nxt.start() if nxt else min(len(text), m.start() + 6000)
        else:
            end = _match_block(text, brace)
        code = text[m.start():end]
        callees = [c for c in CALL.findall(code) if c not in RESERVED][:40]
        out.append(_mk_slice(f, cfg, Path(f.rel_path).stem, m.group("name"),
                             f'{m.group("name")}({m.group("args").strip()[:120]})',
                             text, m.start(), end, code, "", "", callees, ""))
    return out


def _mk_slice(f: SourceFile, cfg: Config, contract: str, name: str, sig: str,
              text: str, start: int, end: int, code: str, state: str,
              mods: str, callees: list[str], solc: str) -> Slice:
    # LABEL LEAK GUARD — benchmark only.
    #
    # SmartBugs-Curated annotates its ground truth INSIDE the source: the
    # vulnerable line carries `// <yes> <report> ACCESS_CONTROL` and the file
    # header carries `@vulnerable_at_lines: 31,38`. Measured on the built
    # corpus before this guard existed: 153 of 826 benchmark slices still
    # carried an annotation, and 181 of the 196 external labels sat on an
    # annotated slice (V9 111/113, V10 50/52, V7 12/12, V4 8/19). A model
    # reading such a slice can lift the answer out of a comment instead of
    # analysing the code, which would make every benchmark metric meaningless.
    #
    # Comments are therefore removed from benchmark slices before anything
    # else — before the token budget, so the budget reflects real code, and
    # before normalisation, so the normalised copy is clean too. Stablecoin
    # slices keep their comments: their code carries no ground truth, and a
    # real protocol's comments are legitimate context an auditor would read.
    # This is deliberately not configurable — a leak guard with an off switch
    # is a leak guard that eventually gets switched off.
    if f.tier == "benchmark":
        code = strip_comments(code)
        state = strip_comments(state)
        mods = strip_comments(mods)
    max_tokens = int(cfg.get("preprocess.max_slice_tokens", 4000))
    if approx_tokens(code) > max_tokens:
        code = code[: max_tokens * 4] + "\n// ...[truncated]"
    # The start offset is part of the identity. Without it, two functions with
    # the same name and argument string in one file collapse to a single id —
    # Go methods on different receivers (`func (k Keeper) GetSigners()` vs
    # `func (s Server) GetSigners()`) are the common case, and 169 ids covering
    # 1096 slices (13% of the corpus) collided. Colliding ids silently merge
    # Slither hits across unrelated functions and make `--slice-id` ambiguous.
    sid = hashlib.sha256(
        f"{f.protocol}:{f.rel_path}:{contract}:{sig}:{start}".encode()).hexdigest()[:16]
    s = Slice(
        id=sid, protocol=f.protocol, tier=f.tier, language=f.language,
        file=f.rel_path, contract=contract, function=name, signature=sig,
        start_line=text.count("\n", 0, start) + 1,
        end_line=text.count("\n", 0, end) + 1,
        code=code, state_vars=state[:4000], modifiers=mods[:2000],
        callees=callees, solc_version=solc,
        n_chars=len(code), approx_tokens=approx_tokens(code),
    )
    if cfg.get("preprocess.normalize_identifiers", True):
        s.normalized_code = normalize_identifiers(code)
    return s


# --- public API -------------------------------------------------------------
def slice_file(f: SourceFile, text: str, cfg: Config) -> list[Slice]:
    if f.language == "solidity" or f.rel_path.endswith(".sol"):
        return _solidity_slices(text, f, cfg)
    if f.rel_path.endswith(".go"):
        return _generic_slices(text, f, cfg, GO_FUNC)
    if f.rel_path.endswith(".ride"):
        return _generic_slices(text, f, cfg, RIDE_FUNC)
    return []


def build(cfg: Config, limit: int | None = None) -> dict:
    files = load_corpus(cfg)
    min_chars = int(cfg.get("preprocess.min_slice_chars", 60))
    slices: list[Slice] = []
    for f in files:
        text = source_text(cfg, f)
        if not text:
            continue
        for s in slice_file(f, text, cfg):
            if s.n_chars >= min_chars:
                slices.append(s)
    slices.sort(key=lambda s: (s.protocol, s.file, s.start_line))
    if limit:
        slices = slices[:limit]
    out = cfg.path("processed") / "slices.json"
    out.write_text(json.dumps([asdict(s) for s in slices], indent=1), "utf-8")
    by_proto: dict[str, int] = {}
    for s in slices:
        by_proto[s.protocol] = by_proto.get(s.protocol, 0) + 1
    return {"slices": len(slices), "by_protocol": by_proto,
            "total_tokens": sum(s.approx_tokens for s in slices), "output": str(out)}


def load(cfg: Config) -> list[Slice]:
    p = cfg.path("processed") / "slices.json"
    if not p.exists():
        raise FileNotFoundError("slices.json missing — run `asv slice` first")
    return [Slice(**d) for d in json.loads(p.read_text("utf-8"))]
