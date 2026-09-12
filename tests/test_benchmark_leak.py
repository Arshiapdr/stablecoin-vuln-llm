"""The benchmark must not hand the model its own answer key.

SmartBugs-Curated writes its ground truth into the source it distributes: the
vulnerable line carries `// <yes> <report> ACCESS_CONTROL`, and the file header
carries `@vulnerable_at_lines: 31,38`. Those comments survived slicing, so a
slice sent to the model contained the answer in plain English. Measured on the
built corpus before the guard: 153 of 826 benchmark slices carried an
annotation, and 181 of the 196 external labels sat on one.

`_mk_slice` now strips comments from benchmark-tier slices. These tests hold it
to that, and hold the stripper to not damaging the code around the comments.
"""
from __future__ import annotations

import json

import pytest

from asv.config import Config
from asv.slicing import strip_comments

# Every annotation form present in SmartBugs-Curated, verified by scanning the
# dataset: the per-line markers and the file-header line-number list.
MARKERS = ("<yes>", "<report>", "@vulnerable_at_lines")


# --- the stripper itself ----------------------------------------------------

def test_line_comment_is_removed():
    assert "ACCESS_CONTROL" not in strip_comments(
        "function f() {\n    // <yes> <report> ACCESS_CONTROL\n    g();\n}")


def test_block_comment_is_removed():
    src = "/*\n * @vulnerable_at_lines: 31,38\n */\ncontract C {}"
    out = strip_comments(src)
    assert "@vulnerable_at_lines" not in out
    assert "contract C {}" in out


def test_line_count_is_preserved():
    """start_line/end_line and the label line->function resolution depend on it."""
    src = "a();\n// gone\n/* also\n   gone */\nb();"
    assert strip_comments(src).count("\n") == src.count("\n")


def test_string_literals_are_not_touched():
    """A naive regex eats the // in a URL and corrupts the code."""
    src = 'string public s = "https://example.com/x"; // note'
    out = strip_comments(src)
    assert '"https://example.com/x"' in out
    assert "note" not in out


def test_escaped_quote_inside_a_string_does_not_end_it():
    src = r'string a = "he said \" // not a comment"; // real comment'
    out = strip_comments(src)
    assert "// not a comment" in out
    assert "real comment" not in out


def test_code_outside_comments_is_untouched():
    src = "function withdraw() {\n    require(x.delegatecall(sig)); // <yes> <report> X\n}"
    out = strip_comments(src)
    assert "require(x.delegatecall(sig));" in out
    assert "<yes>" not in out


def test_division_is_not_mistaken_for_a_comment():
    src = "uint x = a / b; uint y = c / d;"
    assert strip_comments(src) == src


# --- the built corpus, when one is present ----------------------------------

def _slices():
    p = Config.load().path("processed") / "slices.json"
    if not p.exists():
        pytest.skip("needs a built corpus")
    return json.loads(p.read_text("utf-8"))


def test_no_benchmark_slice_carries_an_annotation():
    bench = [s for s in _slices() if s.get("tier") == "benchmark"]
    if not bench:
        pytest.skip("no benchmark slices in this corpus")
    for s in bench:
        for field in ("code", "normalized_code", "state_vars", "modifiers"):
            blob = s.get(field) or ""
            for marker in MARKERS:
                assert marker not in blob, (
                    f"{s['file']}::{s['function']} leaks {marker!r} in {field}")


def test_stablecoin_slices_keep_their_comments():
    """The guard is scoped to the benchmark; real protocol comments are context."""
    sl = [s for s in _slices() if s.get("tier") != "benchmark"]
    if not sl:
        pytest.skip("no stablecoin slices in this corpus")
    assert any("//" in (s.get("code") or "") for s in sl), (
        "comments were stripped from the stablecoin track too — the guard is "
        "meant to apply only to the benchmark")
