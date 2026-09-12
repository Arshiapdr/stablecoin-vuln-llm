"""Report generation must run offline and produce every artifact it promises."""
import json

import pytest

from asv.config import Config
from asv.report import Table, table_classes

cfg = Config.load()


def test_class_table_covers_all_ten_classes_and_all_categories():
    t = table_classes(cfg)
    assert len(t.rows) == 10
    cats = {r[1] for r in t.rows}
    assert any("A1" in c for c in cats) and any("A4" in c for c in cats)
    # A6/A7 used to print as "missing from report" while the report had only
    # five categories; it now names them, so every row must carry a real one
    assert any("A6" in c for c in cats) and any("A7" in c for c in cats)
    assert not any("missing" in c for c in cats)
    assert all(c[:2] in {"A1", "A2", "A3", "A4", "A5", "A6", "A7"} for c in cats)


def test_table_renders_markdown_csv_and_latex(tmp_path):
    t = Table("t_demo", "Demo", ["A", "B"], [[1, "x_y"], [2, "z"]])
    t.write(tmp_path)
    md = (tmp_path / "t_demo.md").read_text()
    assert "| A | B |" in md and "| 1 | x_y |" in md
    tex = (tmp_path / "t_demo.tex").read_text()
    assert r"\begin{tabular}{ll}" in tex
    assert r"x\_y" in tex           # LaTeX-escaped
    csv_text = (tmp_path / "t_demo.csv").read_text()
    assert csv_text.splitlines()[0] == "A,B"


def test_corpus_table_reads_the_tier_from_the_config_not_the_slices(tmp_path):
    """A slice's `tier` is frozen into corpus.json when `asv corpus` runs.

    Reading the Role column from the slices meant that any later change in
    protocols.yaml left Table 2 printing a stale role while `asv layers` used
    the new one. A corpus collected before the tier split still carries the
    deprecated alias "primary", so the table showed `fei-protocol` as
    "primary" — putting a collateral-backed protocol back in the study set in
    the very figure that exists to show the two axes are independent.
    """
    pytest.importorskip("matplotlib")
    from asv.report import fig_corpus

    slices_path = cfg.path("processed") / "slices.json"
    if not slices_path.exists():
        pytest.skip("needs a built corpus")
    result = fig_corpus(cfg, tmp_path)
    if result is None:
        pytest.skip("no stablecoin slices in this corpus")
    _, table = result

    meta = {p["name"]: p for p in cfg.protocol_list()}
    display_to_name = {p.get("display", n): n for n, p in meta.items()}
    role_col = table.header.index("Role")
    seen = 0
    for row in table.rows:
        name = display_to_name.get(row[0])
        if name is None:
            continue
        seen += 1
        assert row[role_col] == meta[name]["tier"], (
            f"{name}: table says {row[role_col]!r}, config says "
            f"{meta[name]['tier']!r} — the Role column is stale")
        assert row[role_col] != "primary", (
            f"{name}: 'primary' is the pre-split alias and must never be "
            "printed as a role")
    assert seen > 0, "no protocol rows matched the config by display name"


def test_figures_render_without_a_display(tmp_path):
    pytest.importorskip("matplotlib")
    from asv.report import fig_confusion, fig_pipeline
    # fig_pipeline now READS its counts from the config instead of carrying
    # them as literals ("12 protocol repos" while protocols.yaml declared 16).
    from asv.config import Config
    assert fig_pipeline(Config.load(), tmp_path).endswith(".png")
    ev = {"overall": {"tp": 3, "fp": 4, "fn": 1, "tn": 9}}
    assert fig_confusion(ev, tmp_path).endswith(".png")
    assert (tmp_path / "fig1_pipeline.pdf").exists()


# --- the early-warning table must survive the per-protocol monitor shape ----
def test_leadtime_table_reads_the_per_protocol_monitor(tmp_path, monkeypatch):
    """`asv data monitor` (all protocols) writes {"per_protocol": ...} with
    alerts and lead time nested; `--series` mode writes them flat. The report
    read only the flat shape, so Table 8 rendered as all zeros in the
    documented pipeline while the monitor had raised alerts on 12 protocols.
    """
    import json

    from asv.config import Config
    from asv.report import table_leadtime

    cfg = Config.load()
    results = cfg.path("results")
    saved = (results / "monitor.json").read_text("utf-8") if (results / "monitor.json").exists() else None
    try:
        (results / "monitor.json").write_text(json.dumps({"per_protocol": {
            "a": {"alerts": 3, "lead_time": {"total": 2, "detected": 1,
                                             "max_lookback_minutes": 2880,
                                             "events": [{"lead_minutes": 30},
                                                        {"lead_minutes": None}]}},
            "b": {"alerts": 1, "lead_time": {"total": 1, "detected": 1,
                                             "max_lookback_minutes": 2880,
                                             "events": [{"lead_minutes": 50}]}},
        }}), "utf-8")
        t = table_leadtime(cfg)
        flat = {r[0]: r[1] for r in t.rows}
        assert flat["Alerts raised"] == 4
        assert flat["Depeg episodes"] == 3
        assert flat["Episodes preceded by an alert"] == 2
        assert flat["Episodes warned (%)"] == "66.7%"
        assert flat["Median lead time (minutes)"] == 50
    finally:
        if saved is not None:
            (results / "monitor.json").write_text(saved, "utf-8")


def test_prevention_report_does_not_assert_confirmed_vulnerabilities():
    """The document names real protocols, files and lines. At this detector's
    measured precision most listed sites are not vulnerabilities, and some are
    in control protocols included as negatives."""
    from asv.config import Config
    p = Config.load().path("results") / "prevention.md"
    if not p.exists():
        pytest.skip("run `asv prevent` first")
    text = p.read_text("utf-8")
    assert "Confirmed findings" not in text
    assert "UNVERIFIED detector outputs" in text
    assert "manually reviewed" in text
