"""Stage 7 — presentation: figures and tables for the written report.

Turns the JSON in results/ into publication-ready artifacts:

  figures/  PNG (200 dpi) + PDF, one per exhibit
  tables/   the same numbers as Markdown, CSV and LaTeX
  REPORT.md a single page that embeds everything

Colour follows a validated categorical palette (CVD-safe on the light surface);
only the first three slots are used together in any all-pairs chart.
"""
from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .config import Config

# --- palette (validated; light surface) -------------------------------------
SURFACE = "#fcfcfb"
INK = "#0b0b0b"
INK_2 = "#52514e"
INK_MUTED = "#8a8880"
GRID = "#e3e2dd"
S1 = "#2a78d6"   # blue     - precision / primary series
S2 = "#eb6834"   # orange   - recall
S3 = "#1baf7a"   # aqua     - F1
S8 = "#e34948"   # red      - reserved: depeg / alert marks
SEQ = ["#eef3fa", "#cfe0f4", "#9dc0e9", "#6a9fdd", "#3d81d2", "#2a78d6"]


def _mpl():
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    plt.rcParams.update({
        "figure.facecolor": SURFACE, "axes.facecolor": SURFACE,
        "savefig.facecolor": SURFACE,
        "font.size": 9, "font.family": "DejaVu Sans",
        "axes.edgecolor": GRID, "axes.labelcolor": INK_2,
        "axes.titlesize": 11, "axes.titleweight": "bold", "axes.titlecolor": INK,
        "xtick.color": INK_2, "ytick.color": INK_2,
        "xtick.labelsize": 8, "ytick.labelsize": 8,
        "axes.spines.top": False, "axes.spines.right": False,
        "grid.color": GRID, "grid.linewidth": 0.6,
        "legend.frameon": False, "legend.fontsize": 8,
        "figure.dpi": 110,
    })
    return plt


def _fmt_score(v: float) -> str:
    """Two decimals lie about small non-zero scores.

    The rule baseline's F1 is 0.0074; `f"{v:.2f}"` printed it as "0.01",
    overstating it by a third and making a detector that fires on thousands of
    sites look like it scored a round hundredth. Anything below 0.01 is shown
    as "<0.01", and anything below 0.1 gets a third decimal.
    """
    if v == 0:
        return "0.00"
    if v < 0.01:
        return "<0.01"
    if v < 0.1:
        return f"{v:.3f}"
    return f"{v:.2f}"


def _save(fig, out_dir: Path, name: str) -> str:
    out_dir.mkdir(parents=True, exist_ok=True)
    png = out_dir / f"{name}.png"
    fig.savefig(png, dpi=200, bbox_inches="tight")
    fig.savefig(out_dir / f"{name}.pdf", bbox_inches="tight")
    import matplotlib.pyplot as plt
    plt.close(fig)
    return str(png)


# --- tables -----------------------------------------------------------------
@dataclass
class Table:
    name: str
    caption: str
    header: list[str]
    rows: list[list]

    def markdown(self) -> str:
        head = "| " + " | ".join(self.header) + " |"
        sep = "|" + "|".join("---" for _ in self.header) + "|"
        body = ["| " + " | ".join(str(c) for c in r) + " |" for r in self.rows]
        return "\n".join([head, sep, *body])

    def latex(self) -> str:
        cols = "l" * len(self.header)
        lines = [r"\begin{table}[htbp]", r"\centering",
                 rf"\caption{{{self.caption}}}",
                 rf"\begin{{tabular}}{{{cols}}}", r"\hline",
                 " & ".join(self.header) + r" \\", r"\hline"]
        for r in self.rows:
            lines.append(" & ".join(str(c).replace("_", r"\_").replace("%", r"\%")
                                    for c in r) + r" \\")
        lines += [r"\hline", r"\end{tabular}", r"\end{table}"]
        return "\n".join(lines)

    def write(self, out_dir: Path) -> None:
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / f"{self.name}.md").write_text(
            f"**{self.caption}**\n\n{self.markdown()}\n", "utf-8")
        (out_dir / f"{self.name}.tex").write_text(self.latex(), "utf-8")
        with (out_dir / f"{self.name}.csv").open("w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(self.header)
            w.writerows(self.rows)


def _load(path: Path):
    return json.loads(path.read_text("utf-8")) if path.exists() else None


# --- exhibits ---------------------------------------------------------------
def fig_pipeline(cfg: Config, out_dir: Path) -> str:
    # Counts are READ, never typed. The subtitle here used to say "12 protocol
    # repos" as a literal while protocols.yaml declared 16 plus a benchmark, so
    # the first figure of the report contradicted its own Table 2.
    from .kb import KnowledgeBase
    n_proto = len(cfg.protocol_list())
    try:
        n_classes = len(list(KnowledgeBase.load(cfg.knowledge_dir)))
    except Exception:                                        # noqa: BLE001
        n_classes = 0
    slices = _load(cfg.path("processed") / "slices.json") or []
    n_slices = sum(1 for s in slices if s.get("tier") != "benchmark")
    # Benchmarks that were actually COLLECTED, not merely declared:
    # protocols.yaml lists three benchmark repos but only SmartBugs-Curated
    # ships machine-readable labels and is collected as source.
    n_bench = len({s["protocol"] for s in slices if s.get("tier") == "benchmark"})
    plt = _mpl()
    stages = [("0\nCorpus", f"{n_proto} protocols" +
               (f"\n+{n_bench} benchmark" if n_bench else "")),
              ("1\nSlicing", f"{n_slices:,} slices" if n_slices else "function slices"),
              ("2\nKnowledge", f"{n_classes} classes"),
              ("3\nDetection", "auditor + critic"),
              ("4\nBehaviour", "depeg + alerts"), ("5\nEvaluation", "metrics"),
              ("6\nPrevention", "patches + monitor")]
    fig, ax = plt.subplots(figsize=(11, 2.1))
    ax.set_xlim(0, len(stages)); ax.set_ylim(0, 1); ax.axis("off")
    for i, (title, sub) in enumerate(stages):
        ax.add_patch(plt.Rectangle((i + 0.06, 0.30), 0.88, 0.48,
                                   facecolor="#eef3fa", edgecolor=S1, linewidth=1.2))
        ax.text(i + 0.5, 0.62, title, ha="center", va="center",
                fontsize=9, fontweight="bold", color=INK)
        ax.text(i + 0.5, 0.40, sub, ha="center", va="center",
                fontsize=7.5, color=INK_2)
        if i < len(stages) - 1:
            ax.annotate("", xy=(i + 1.05, 0.54), xytext=(i + 0.95, 0.54),
                        arrowprops=dict(arrowstyle="->", color=INK_MUTED, lw=1.1))
    ax.set_title("Figure 1 — Pipeline stages", loc="left", pad=10)
    return _save(fig, out_dir, "fig1_pipeline")


def fig_corpus(cfg: Config, out_dir: Path) -> tuple[str, Table] | None:
    slices = _load(cfg.path("processed") / "slices.json")
    if not slices:
        return None
    counts: dict[str, int] = {}
    tiers: dict[str, str] = {}
    for s in slices:
        # The SmartBugs benchmark is a separate external-comparability track,
        # not part of the stablecoin corpus this figure describes.
        if s["tier"] == "benchmark":
            continue
        counts[s["protocol"]] = counts.get(s["protocol"], 0) + 1
        tiers[s["protocol"]] = s["tier"]
    if not counts:
        return None
    # `tier` must be read from the CONFIG, not from the slices. A slice's tier
    # is frozen into data/interim/corpus.json when `asv corpus` runs, so any
    # later taxonomy change in protocols.yaml leaves this table printing a
    # stale role while `asv layers` uses the new one — the table and the
    # metrics would then disagree. Observed: a corpus collected before the
    # tier split still carries the deprecated alias "primary" for ten
    # protocols, including fei-protocol, which protocols.yaml declares
    # `tier: control`. Table 2 printed "primary" for it — reinstating, in the
    # figure, exactly the misclassification the split was made to remove.
    # `algorithmic` below is already read from the config; `tier` now matches.
    _meta_tier = cfg.protocol_meta()
    for _p in counts:
        tiers[_p] = _meta_tier.get(_p, {}).get("tier", tiers.get(_p, "—"))
    order = sorted(counts, key=lambda k: counts[k])
    plt = _mpl()
    fig, ax = plt.subplots(figsize=(7.2, 4.0))
    meta_algo = {k: v.get("algorithmic", "none") for k, v in cfg.protocol_meta().items()}
    _c = {"pure": S1, "partial": S3, "none": INK_MUTED}
    colors = [_c.get(meta_algo.get(p, "none"), INK_MUTED) for p in order]
    bars = ax.barh(range(len(order)), [counts[p] for p in order],
                   color=colors, height=0.62)
    total_slices = sum(counts.values())
    for i, p in enumerate(order):
        # Absolute count AND share: 1,951 slices means little until the reader
        # sees it is a quarter of the corpus, which is what makes the sampling
        # in `select_slices` proportional rather than arbitrary.
        ax.text(counts[p] + max(counts.values()) * 0.012, i,
                f"{counts[p]:,}  ({100 * counts[p] / total_slices:.1f}%)",
                va="center", fontsize=8, color=INK_2)
    ax.set_yticks(range(len(order)))
    ax.set_yticklabels(order, fontsize=8)
    ax.set_xlabel(f"function-level slices  (n = {sum(counts.values()):,} across "
                  f"{len(counts)} protocols)")
    ax.set_xlim(0, max(counts.values()) * 1.30)   # room for the share label
    ax.grid(axis="x", alpha=0.7); ax.set_axisbelow(True)
    ax.set_title("Figure 2 — Corpus composition", loc="left", pad=8)
    import matplotlib.patches as mp
    ax.legend(handles=[mp.Patch(color=S1, label="purely algorithmic"),
                       mp.Patch(color=S3, label="partially algorithmic"),
                       mp.Patch(color=INK_MUTED, label="collateral-backed")],
              loc="lower right")
    path = _save(fig, out_dir, "fig2_corpus")
    meta = {x["name"]: x for x in cfg.protocol_list()}
    tbl = Table("t2_corpus",
                "Corpus composition. `Algorithmic` is a property of the mechanism; "
                "`Role` is the protocol's part in the evaluation. The two are "
                "independent — Beanstalk (patched) is purely algorithmic but a "
                "control, and Reflexer RAI is partially algorithmic but a control.",
                ["Protocol", "Algorithmic", "Role", "Mechanism family", "Incident", "Slices"],
                [[meta.get(p, {}).get("display", p),
                  meta.get(p, {}).get("algorithmic", "—"),
                  tiers[p],
                  meta.get(p, {}).get("family", "—"),
                  (meta.get(p, {}).get("incident") or {}).get("date", "—")
                  if meta.get(p, {}).get("incident") else "—",
                  counts[p]]
                 for p in sorted(counts, key=lambda k: -counts[k])])
    return path, tbl


def fig_per_class(evaluation: dict, out_dir: Path) -> tuple[str, Table]:
    per = evaluation["per_class"]
    ids = sorted(per, key=lambda k: int(k[1:]))
    plt = _mpl()
    fig, ax = plt.subplots(figsize=(9.6, 4.2))
    w = 0.22                       # narrower bars => a visible gap between classes
    xs = [x * 1.35 for x in range(len(ids))]   # and more space between groups
    # Value labels are STAGGERED in height, one row per series. Three bars of
    # equal value put three labels at the same y and the same x-ish, which
    # rendered as "1.01.01.00" and "0.00.00.00" - unreadable exactly where the
    # scores agree, which is most of this chart.
    for off, key, colour, label, lift in ((-w, "precision", S1, "Precision", 0.030),
                                          (0.0, "recall", S2, "Recall", 0.082),
                                          (w, "f1", S3, "F1", 0.134)):
        vals = [per[i][key] for i in ids]
        ax.bar([x + off for x in xs], vals, width=w * 0.92, color=colour, label=label)
        for x, v in zip(xs, vals):
            # Zeros are labelled too. Printing only non-zero bars left V1, V2,
            # V5-V9 with no annotation at all, which reads as "not measured"
            # rather than "measured and scored zero".
            ax.text(x + off, v + lift, f"{v:.2f}", ha="center",
                    fontsize=6.2, color=colour if v > 0 else INK_MUTED)
    # Support under every class: a precision of 1.000 resting on ONE label is
    # not the same claim as one resting on twenty, and the bar height alone
    # cannot show the difference.
    ax.set_xticks(list(xs))
    ax.set_xticklabels([f"{i}\nn={per[i]['tp'] + per[i]['fn']}" for i in ids],
                       fontsize=8)
    ax.set_ylim(0, 1.22); ax.set_ylabel("score")
    ax.set_xlabel("vulnerability class (n = ground-truth labels for that class)")
    ax.grid(axis="y", alpha=0.7); ax.set_axisbelow(True)
    ax.legend(ncol=3, loc="upper right")
    ax.set_title("Figure 3 — Detection performance by vulnerability class",
                 loc="left", pad=8)
    ax.margins(x=0.02)
    path = _save(fig, out_dir, "fig3_per_class")
    tbl = Table("t4_per_class", "Per-class detection performance",
                ["Class", "TP", "FP", "FN", "Precision", "Recall", "F1"],
                [[i, per[i]["tp"], per[i]["fp"], per[i]["fn"],
                  f'{per[i]["precision"]:.3f}', f'{per[i]["recall"]:.3f}',
                  f'{per[i]["f1"]:.3f}'] for i in ids])
    return path, tbl


def fig_confusion(evaluation: dict, out_dir: Path) -> str:
    o = evaluation["overall"]
    m = [[o["tp"], o["fn"]], [o["fp"], o.get("tn", 0)]]
    plt = _mpl()
    from matplotlib.colors import LinearSegmentedColormap
    cmap = LinearSegmentedColormap.from_list("seq", SEQ)
    fig, ax = plt.subplots(figsize=(4.0, 3.4))
    top = max(max(r) for r in m) or 1
    ax.imshow(m, cmap=cmap, vmin=0, vmax=top)
    for i in range(2):
        for j in range(2):
            ax.text(j, i, f"{m[i][j]:,}", ha="center", va="center",
                    fontsize=13, fontweight="bold",
                    color="#ffffff" if m[i][j] > top * 0.55 else INK)
    ax.set_xticks([0, 1]); ax.set_xticklabels(["predicted +", "predicted −"])
    ax.set_yticks([0, 1]); ax.set_yticklabels(["actual +", "actual −"])
    for s in ax.spines.values():
        s.set_visible(False)
    ax.set_title("Figure 4 — Confusion matrix", loc="left", pad=8)
    return _save(fig, out_dir, "fig4_confusion")


def fig_ablation(cfg: Config, out_dir: Path) -> tuple[str, Table] | None:
    data = _load(cfg.path("results") / "ablations.json")
    if not data:
        return None
    rows = [(k, v) for k, v in data.items() if "error" not in v]
    if not rows:
        return None
    labels = [k.replace("_", " ") for k, _ in rows]
    plt = _mpl()
    fig, ax = plt.subplots(figsize=(8.4, 3.8))
    w = 0.26
    xs = range(len(rows))
    for off, key, colour, label, lift in ((-w, "precision", S1, "Precision", 0.020),
                                          (0.0, "recall", S2, "Recall", 0.058),
                                          (w, "f1", S3, "F1", 0.096)):
        vals = [v.get(key, 0) for _, v in rows]
        ax.bar([x + off for x in xs], vals, width=w * 0.92, color=colour, label=label)
        for x, v in zip(xs, vals):
            ax.text(x + off, v + lift, _fmt_score(v), ha="center", fontsize=6.4,
                    color=colour if v > 0 else INK_MUTED)
    ax.set_xticks(list(xs))
    ax.set_xticklabels(labels, rotation=18, ha="right", fontsize=7.5)
    ax.set_ylabel("score"); ax.set_ylim(0, max(
        [v.get("recall", 0) for _, v in rows] + [0.2]) * 1.42)
    ax.grid(axis="y", alpha=0.7); ax.set_axisbelow(True)
    ax.legend(ncol=3, loc="upper right")
    ax.set_title("Figure 5 — Baselines and ablations", loc="left", pad=8)
    path = _save(fig, out_dir, "fig5_ablation")
    tbl = Table("t5_ablation", "Baselines and ablations",
                ["Run", "TP", "FP", "FN", "Precision", "Recall", "F1", "Effective F1"],
                [[k.replace("_", " "), v.get("tp"), v.get("fp"), v.get("fn"),
                  f'{v.get("precision", 0):.3f}', f'{v.get("recall", 0):.3f}',
                  f'{v.get("f1", 0):.3f}', f'{v.get("effective_f1", 0):.3f}']
                 for k, v in rows])
    return path, tbl



def _depeg_view(cfg: Config, protocol: str | None = None) -> dict | None:
    """One protocol's depeg record, from either shape of results/depeg.json.

    `asv data depeg` used to write a single flat record because the behavioural
    track covered Terra alone. It now writes {"per_protocol": {name: record}}.
    Both shapes are accepted so an older results directory still renders, and
    so the figures keep describing exactly one series rather than silently
    pooling protocols with different resolutions and different peg targets.
    """
    d = _load(cfg.path("results") / "depeg.json")
    if not d:
        return None
    per = d.get("per_protocol")
    if per is None:
        return d                                   # legacy flat record
    if protocol and protocol in per:
        return {**per[protocol], "protocol": protocol}
    # No protocol asked for: pick ONE — never a merge across protocols, whose
    # series differ in resolution and peg target. Order: highest resolution
    # first (a minute series is stronger evidence than an hourly one), then the
    # most labelled episodes, then the most samples. Ranking by samples alone
    # chose `liquity` — a control with zero events — as the headline depeg
    # exhibit, over a protocol that actually collapsed.
    best = min(per.items(),
               key=lambda kv: (kv[1].get("median_step_seconds") or 10**9,
                               -len(kv[1].get("events") or []),
                               -kv[1].get("samples", 0)))
    return {**best[1], "protocol": best[0]}


def fig_depeg(cfg: Config, out_dir: Path, series_path: Path | None = None,
              protocol: str | None = None, name: str = "fig6_depeg"
              ) -> tuple[str, Table] | None:
    depeg = _depeg_view(cfg, protocol)
    if not depeg or not series_path or not Path(series_path).exists():
        return None
    from .market import load_series
    series = load_series(Path(series_path))
    if not series:
        return None
    monitor = _load(cfg.path("results") / "monitor.json") or {}
    # Alerts, like the lead-time block, are nested per protocol unless the
    # monitor was run with `--series`. Reading only the flat key drew the panel
    # with no warning lines at all while the monitor had raised them.
    _who = depeg.get("protocol")
    alert_events = monitor.get("alert_events")
    if alert_events is None and monitor.get("per_protocol"):
        alert_events = (monitor["per_protocol"].get(_who) or {}).get("alert_events")

    plt = _mpl()
    import matplotlib.dates as mdates
    xs = [datetime.fromtimestamp(t, timezone.utc) for t, _ in series]
    ys = [p for _, p in series]
    fig, ax = plt.subplots(figsize=(9.6, 3.9))
    for ev in depeg["events"]:
        if ev["kind"] != "depeg":
            continue
        ax.axvspan(datetime.fromtimestamp(ev["start_ts"], timezone.utc),
                   datetime.fromtimestamp(ev["end_ts"], timezone.utc),
                   color=S8, alpha=0.10, lw=0)
    ax.plot(xs, ys, color=S1, lw=1.6)
    ax.axhline(1.0, color=INK_MUTED, lw=0.9, ls=(0, (4, 3)))
    ax.axhline(cfg.get("behavior.depeg_threshold", 0.99), color=S8, lw=0.9,
               ls=(0, (2, 2)))
    first = True
    for a in (alert_events or [])[:40]:
        ax.axvline(datetime.fromtimestamp(a["ts"], timezone.utc), color=S2,
                   lw=0.9, alpha=0.85,
                   label="early-warning alert" if first else None)
        first = False
    ax.set_ylabel("price (USD)"); ax.set_ylim(0, 1.08)
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%d %b"))
    ax.grid(axis="y", alpha=0.7); ax.set_axisbelow(True)
    import matplotlib.patches as mp
    handles = [plt.Line2D([], [], color=S1, lw=1.6, label="price"),
               mp.Patch(color=S8, alpha=0.10, label="labelled depeg"),
               plt.Line2D([], [], color=S8, lw=0.9, ls=(0, (2, 2)),
                          label=f'threshold {cfg.get("behavior.depeg_threshold", 0.99)}')]
    if not first:
        handles.append(plt.Line2D([], [], color=S2, lw=0.9, label="early-warning alert"))
    ax.legend(handles=handles, ncol=4, loc="lower left")
    # An unlabelled price chart is unciteable: the reader cannot tell which
    # protocol, which year, or at what resolution. All three go in the title.
    who = depeg.get("protocol", "—")
    step = depeg.get("median_step_seconds")
    res = "1-minute" if step and step <= 120 else "1-hour" if step else "unknown"
    span = (f"{xs[0]:%d %b %Y} – {xs[-1]:%d %b %Y}" if xs else "")
    ax.set_title(f"Figure 6 — {who}: peg deviation, labelled events and early "
                 f"warnings\n{span} · {res} series · {len(series):,} samples · "
                 f"peg target USD 1.00",
                 loc="left", pad=8, fontsize=10)
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%d %b %Y"))
    fig.autofmt_xdate(rotation=0, ha="center")
    path = _save(fig, out_dir, name)

    ev_rows = [[e["kind"], e["start_iso"][:16].replace("T", " "),
                e["duration_min"], f'{e["min_price"]:.4f}']
               for e in depeg["events"] if e["kind"] != "depeg"][:20]
    if not ev_rows:
        ev_rows = [[e["kind"], e["start_iso"][:16].replace("T", " "),
                    e["duration_min"], f'{e["min_price"]:.4f}']
                   for e in depeg["events"][:20]]
    who = depeg.get("protocol")
    tbl = Table("t6_depeg_events",
                "Labelled severe (<$0.95) and failure (<$0.80) episodes; the "
                "milder $0.99 tier is omitted for space and is in "
                "results/depeg.json" + (f" — {who}" if who else ""),
                ["Kind", "Start (UTC)", "Duration (min)", "Min price"], ev_rows)
    return path, tbl


def table_sensitivity(cfg: Config) -> Table | None:
    """Table 7 without the figure: seven numbers do not need a bar chart."""
    depeg = _depeg_view(cfg)
    if not depeg or "sensitivity" not in depeg:
        return None
    sens = depeg["sensitivity"]
    who = depeg.get("protocol")
    return Table("t7_sensitivity",
                 "Depeg-threshold sensitivity" + (f" — {who}" if who else ""),
                 ["Threshold", "Episodes", "Minutes below", "Min price"],
                 [[f"${t}", sens[t]["events"], sens[t]["total_minutes"],
                   f'{sens[t]["min_price"]:.4f}' if sens[t]["min_price"] else "—"]
                  for t in sorted(sens, key=lambda k: -float(k))])


def fig_sensitivity(cfg: Config, out_dir: Path) -> tuple[str, Table] | None:
    depeg = _depeg_view(cfg)
    if not depeg or "sensitivity" not in depeg:
        return None
    sens = depeg["sensitivity"]
    ths = sorted(sens, key=lambda k: -float(k))
    plt = _mpl()
    # two measures of different scale -> two stacked panels, never a dual axis
    fig, (a1, a2) = plt.subplots(2, 1, figsize=(7.4, 4.6), sharex=True)
    a1.bar(range(len(ths)), [sens[t]["events"] for t in ths], color=S1, width=0.6)
    for i, t in enumerate(ths):
        a1.text(i, sens[t]["events"], str(sens[t]["events"]), ha="center",
                va="bottom", fontsize=7, color=INK_2)
    a1.set_ylabel("episodes")
    a1.grid(axis="y", alpha=0.7); a1.set_axisbelow(True)
    a1.set_title("Figure 7 — Sensitivity of the depeg definition to the threshold",
                 loc="left", pad=8)
    a2.bar(range(len(ths)), [sens[t]["total_minutes"] for t in ths],
           color=S3, width=0.6)
    a2.set_ylabel("minutes below")
    a2.set_xticks(range(len(ths))); a2.set_xticklabels([f"${t}" for t in ths])
    a2.set_xlabel("threshold")
    a2.grid(axis="y", alpha=0.7); a2.set_axisbelow(True)
    path = _save(fig, out_dir, "fig7_sensitivity")
    tbl = Table("t7_sensitivity",
                "Depeg-threshold sensitivity" + (f" — {depeg.get('protocol')}"
                                                 if depeg.get("protocol") else ""),
                ["Threshold", "Episodes", "Minutes below", "Min price"],
                [[f"${t}", sens[t]["events"], sens[t]["total_minutes"],
                  "—" if sens[t]["min_price"] is None else f'{sens[t]["min_price"]:.4f}']
                 for t in ths])
    return path, tbl


def table_classes(cfg: Config) -> Table:
    from .kb import KnowledgeBase
    kb = KnowledgeBase.load(cfg.knowledge_dir)
    cat = {"A1": "A1 death spiral", "A2": "A2 arbitrage manipulation",
           "A3": "A3 governance & parameter", "A4": "A4 oracle & price feed",
           "A5": "A5 yield integration",
           "A6": "A6 execution-path defects",
           "A7": "A7 accounting-invariant defects"}
    rows = [[v.id, cat.get(v.report_category, v.report_category), v.layer,
             v.severity, v.mitigation, v.title]
            for v in sorted(kb, key=lambda x: int(x.id[1:]))]
    return Table("t1_classes",
                 "Vulnerability classes and their mapping to the report categories",
                 ["Class", "Report category", "Layer", "Severity", "Mitigation", "Title"],
                 rows)


def table_applicability(cfg: Config) -> Table:
    """The bridge between the two taxonomies.

    Rows are vulnerability classes (what the detector looks for); columns are
    stablecoin mechanism families (what the corpus is made of). The two are
    orthogonal, and the interesting content is that V1-V3 are mechanism-specific
    while V4-V10 are mechanism-independent.
    """
    from .kb import KnowledgeBase
    kb = KnowledgeBase.load(cfg.knowledge_dir)
    # Families present in the STUDY set, in a stable order.
    order = ["dual_token", "seigniorage_shares", "rebase", "fractional_hybrid",
             "pcv_backed"]
    study = cfg.protocol_list("study")
    present = {p.get("family") for p in study}
    fams = [f for f in order if f in present] + sorted(present - set(order))
    counts = {f: sum(1 for p in study if p.get("family") == f) for f in fams}
    header = ["Class", "Report cat."] + [f'{f}\n(n={counts[f]})'.replace("\n", " ")
                                         for f in fams]
    rows = []
    for v in sorted(kb, key=lambda x: int(x.id[1:])):
        applies = set(v.applies_to)
        marks = ["yes" if ("all" in applies or f in applies) else "—" for f in fams]
        rows.append([v.id, v.report_category] + marks)
    return Table("t9_applicability",
                 "Which vulnerability class can occur in which mechanism family",
                 header, rows)


def fig_applicability(cfg: Config, out_dir: Path) -> str:
    from .kb import KnowledgeBase
    kb = KnowledgeBase.load(cfg.knowledge_dir)
    fams = ["dual_token", "seigniorage_shares", "rebase",
            "fractional_hybrid", "pcv_backed"]
    classes = sorted(kb, key=lambda x: int(x.id[1:]))
    grid = [[1 if ("all" in v.applies_to or f in v.applies_to) else 0
             for f in fams] for v in classes]
    plt = _mpl()
    from matplotlib.colors import ListedColormap
    fig, ax = plt.subplots(figsize=(7.6, 4.8))
    ax.imshow(grid, cmap=ListedColormap(["#f4f3ef", "#9dc0e9"]), vmin=0, vmax=1)
    for i, row in enumerate(grid):
        for j, cell in enumerate(row):
            ax.text(j, i, "●" if cell else "·", ha="center", va="center",
                    fontsize=13 if cell else 10,
                    color=S1 if cell else INK_MUTED)
    ax.set_xticks(range(len(fams)))
    ax.set_xticklabels([f.replace("_", " ") for f in fams], fontsize=8,
                       rotation=28, ha="right")
    ax.set_yticks(range(len(classes)))
    ax.set_yticklabels([f"{v.id}  {v.report_category}" for v in classes], fontsize=8)
    ax.set_xticks([x - 0.5 for x in range(1, len(fams))], minor=True)
    ax.set_yticks([y - 0.5 for y in range(1, len(classes))], minor=True)
    ax.grid(which="minor", color=SURFACE, linewidth=2)
    ax.tick_params(which="minor", length=0)
    for sp in ax.spines.values():
        sp.set_visible(False)
    ax.set_title("Figure 8 — Vulnerability classes x mechanism families",
                 loc="left", pad=10)
    ax.set_xlabel("V1-V3 are mechanism-specific; V4-V10 are mechanism-independent.",
                  fontsize=8, labelpad=14)
    return _save(fig, out_dir, "fig8_applicability")


def table_overall(evaluation: dict) -> Table:
    o = evaluation["overall"]
    b = evaluation.get("bootstrap", {})
    rows = [["True positives", o["tp"]], ["False positives", o["fp"]],
            ["False negatives", o["fn"]], ["True negatives", o.get("tn", "—")],
            ["Precision", f'{o["precision"]:.3f}'],
            ["Recall", f'{o["recall"]:.3f}'],
            ["F1", f'{o["f1"]:.3f}'],
            ["Effective F1 (coverage-aware)", f'{o["effective_f1"]:.3f}'],
            ["Accuracy (TN-dominated — not a quality measure)",
             f'{o.get("accuracy", 0):.3f}'],
            ["Output coverage", f'{o.get("coverage", 1):.3f}'],
            ["Unparseable outputs", o.get("parse_failures", 0)],
            ["Ground-truth labels retrieved", f'{evaluation["labels_matched"]}'
                                              f'/{evaluation["labels_total"]}'],
            ["Labels never retrieved (counted as misses)",
             evaluation.get("labels_unretrieved", 0)],
            ["Findings scored", evaluation["findings"]]]
    if b:
        rows.append([f'F1 {int(b["level"] * 100)}% CI (bootstrap, '
                     f'{b["iterations"]} iters)',
                     f'[{b["ci_low"]:.3f}, {b["ci_high"]:.3f}]'])
    r = evaluation.get("ranked", {})
    for k in ("top_1", "top_3", "top_5", "mrr"):
        if k in r:
            rows.append([k.replace("_", "-").upper(), f"{r[k]:.3f}"])
    return Table("t3_overall", "Overall detection metrics", ["Metric", "Value"], rows)


def table_layers(cfg: Config) -> Table | None:
    """The headline result, split by how algorithmic each protocol actually is."""
    d = _load(cfg.path("results") / "evaluation_layers.json")
    if not d:
        return None
    label = {
        "pure": "Purely algorithmic (report scope)",
        "partial": "Partially algorithmic",
        "study_combined": "Study set (pure + partial)",
        "control": "Controls (collateral-backed / patched)",
    }
    rows = []
    for k in ("pure", "partial", "study_combined", "control"):
        r = d.get(k)
        if not r:
            continue
        n = len(r["protocols"])
        if k == "control":
            # no positive labels here: precision/recall are undefined, and the
            # only meaningful number is how often the detector fired at all
            rows.append([label[k], n, r["labels"], "—", "—", "—", r["fp"]])
        else:
            rows.append([label[k], n, r["labels"], f'{r["precision"]:.3f}',
                         f'{r["recall"]:.3f}', f'{r["f1"]:.3f}', r["fp"]])
    return Table("t10_layers",
                 "Results by layer. The purely algorithmic row is the report's "
                 "actual scope; the partial row is reported beside it, never "
                 "merged into it. Controls carry no positive labels, so only "
                 "their false-positive count is meaningful.",
                 ["Layer", "Protocols", "Labels", "Precision", "Recall", "F1",
                  "False positives"], rows)


def table_leadtime(cfg: Config) -> Table | None:
    m = _load(cfg.path("results") / "monitor.json")
    if not m:
        return None
    lt = m.get("lead_time", {})
    alerts = m.get("alerts", 0)
    if not lt and m.get("per_protocol"):
        # Older monitor.json: per-protocol only, no top-level aggregate.
        per = m["per_protocol"].values()
        pooled = sorted(e["lead_minutes"] for v in per
                        for e in v["lead_time"]["events"]
                        if e.get("lead_minutes") is not None)
        lt = {"total": sum(v["lead_time"]["total"] for v in per),
              "detected": sum(v["lead_time"]["detected"] for v in per),
              "median_lead_minutes": pooled[len(pooled) // 2] if pooled else "—",
              "max_lookback_minutes": next(
                  (v["lead_time"]["max_lookback_minutes"] for v in per), "—")}
        alerts = sum(v["alerts"] for v in per)
    total = lt.get("total", 0)
    det = lt.get("detected", 0)
    rows = [["Alerts raised", alerts],
            ["Depeg episodes", total],
            ["Episodes preceded by an alert", det],
            ["Episodes warned (%)", f"{100 * det / total:.1f}%" if total else "—"],
            ["Median lead time (minutes)", lt.get("median_lead_minutes", "—")],
            ["Look-back bound (minutes)", lt.get("max_lookback_minutes", "—")]]
    return Table("t8_leadtime",
                 "Early-warning monitor performance (alerts are only credited "
                 "within the look-back bound and never across a previous episode)",
                 ["Metric", "Value"], rows)


# --- driver -----------------------------------------------------------------
def build(cfg: Config, series_path: str | None = None) -> dict:
    figs_dir = cfg.path("results") / "figures"
    tabs_dir = cfg.path("results") / "tables"
    evaluation = _load(cfg.path("results") / "evaluation.json")

    figures: list[tuple[str, str]] = []
    tables: list[Table] = [table_classes(cfg)]

    figures.append(("Figure 1 — Pipeline stages", fig_pipeline(cfg, figs_dir)))

    got = fig_corpus(cfg, figs_dir)
    if got:
        figures.append(("Figure 2 — Corpus composition", got[0]))
        tables.append(got[1])

    tables.append(table_applicability(cfg))

    if evaluation:
        tables.append(table_overall(evaluation))
        lay = table_layers(cfg)
        if lay:
            tables.append(lay)
        p, t = fig_per_class(evaluation, figs_dir)
        figures.append(("Figure 3 — Performance by class", p))
        tables.append(t)
        figures.append(("Figure 4 — Confusion matrix", fig_confusion(evaluation, figs_dir)))

    got = fig_ablation(cfg, figs_dir)
    if got:
        figures.append(("Figure 5 — Baselines and ablations", got[0]))
        tables.append(got[1])

    sp = Path(series_path) if series_path else None
    if sp is None:
        # Resolve the series that belongs to the protocol _depeg_view picks, so
        # the price line, the shaded episodes and the caption all describe the
        # same protocol.
        from .market import series_path as _sp
        view = _depeg_view(cfg)
        if view and view.get("protocol"):
            mdir = cfg.path("raw") / "market"
            sp = next((c for c in (_sp(mdir, view["protocol"], "1m"),
                                   _sp(mdir, view["protocol"], "1h"))
                       if c.exists()), None)
    got = fig_depeg(cfg, figs_dir, sp)
    if got:
        figures.append(("Figure 6 — Peg deviation and early warnings", got[0]))
        tables.append(got[1])

    # One panel per USD-pegged protocol, written beside the headline figure as
    # fig6_depeg_<protocol>. Protocols whose peg is not $1.00 (AMPL's
    # CPI-adjusted target, agEUR's euro, RAI's floating redemption price) are
    # NOT plotted against a $1 line: doing so would draw a "depeg" that is
    # simply a different unit of account. They are listed instead.
    from .market import market_protocols, series_path as _series_path
    subfigures: list[tuple[str, str]] = []
    mdir = cfg.path("raw") / "market"
    usd = {n for n, _ in market_protocols(cfg, depeggable_only=True)}
    extra: list[str] = []
    for pname, spec in market_protocols(cfg):
        if pname not in usd:
            extra.append(f"{pname} (peg target {spec.get('peg_target')})")
            continue
        cand = next((c for c in (_series_path(mdir, pname, "1m"),
                                 _series_path(mdir, pname, "1h")) if c.exists()), None)
        if cand is None or (view and pname == view.get("protocol")):
            continue
        sub = fig_depeg(cfg, figs_dir, cand, protocol=pname,
                        name=f"fig6_depeg_{pname}")
        if sub:
            subfigures.append((pname, sub[0]))

    # Figures 7 and 8 are deliberately NOT emitted. The threshold sweep and the
    # class x family matrix are both exactly reproduced by Tables 7 and 9, and
    # a bar chart of seven numbers and a matrix that is almost entirely "yes"
    # add no information a reader cannot get from the tables. The TABLES stay.
    # Table only: `fig_sensitivity` would also write fig7_*.png/pdf, and an
    # orphan file nothing references invites someone to paste it into the
    # report later without the reasoning for why it was dropped.
    sens = table_sensitivity(cfg)
    if sens:
        tables.append(sens)

    lt = table_leadtime(cfg)
    if lt:
        tables.append(lt)

    for t in tables:
        t.write(tabs_dir)

    # single embeddable page
    findings = _load(cfg.path("results") / "findings.json") or []
    providers = sorted({f.get("provider", "") for f in findings if f.get("provider")})
    lines = ["# Results", "",
             f"Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}.",
             "Every figure is also written as PDF, and every table as CSV and LaTeX.",
             f"Detection backend(s): {', '.join(providers) or 'n/a'}.", ""]
    if providers == ["mock"]:
        lines += ["> **These numbers come from the offline `mock` backend**, which is a "
                  "deterministic rule engine, not a language model. It is the "
                  "\"structure without an LLM\" reference point. The ablation figure is "
                  "expected to be flat here, because the mock ignores the critic, the "
                  "static weighting, identifier normalisation **and the few-shot "
                  "exemplars** — it reads only the two scaffolding lines it is given, "
                  "so `llm_few_shot` is identical to `llm_full` by construction and "
                  "says nothing about whether worked examples help. Re-run with "
                  "`--provider gemini` for the headline result.", ""]
    fig_by_num = {int(t.split("—")[0].strip().split()[1]): (t, p)
                  for t, p in figures if t.startswith("Figure ")}
    tab_by_num = {int(t.name.split("_")[0][1:]): t for t in tables}
    for i in range(1, 11):
        if i in tab_by_num:
            t = tab_by_num[i]
            lines += [f"## Table {i} — {t.caption}", "", t.markdown(), ""]
        if i in fig_by_num:
            title, path = fig_by_num[i]
            rel = Path(path).relative_to(cfg.path("results"))
            lines += [f"## {title}", "", f"![{title}]({rel.as_posix()})", ""]

    # Appendix: the same peg-deviation panel for every other USD-pegged
    # protocol, and an explicit list of the ones deliberately not plotted.
    if subfigures:
        lines += ["## Figure 6 (appendix) — peg deviation, remaining "
                  "USD-pegged protocols", ""]
        for pname, path in sorted(subfigures):
            rel = Path(path).relative_to(cfg.path("results"))
            lines += [f"**{pname}**", "", f"![{pname}]({rel.as_posix()})", ""]
    if extra:
        lines += ["> Not plotted against a $1.00 line, because their peg target "
                  "is not the dollar and a $1 reference would draw a "
                  "\"depeg\" that is only a different unit of account: "
                  + "; ".join(sorted(extra)) +
                  ". Protocols with no free market series at all (YAM v1) are "
                  "absent from the behavioural track entirely.", ""]
    out = cfg.path("results") / "REPORT.md"
    out.write_text("\n".join(lines), "utf-8")

    return {"figures": len(figures), "tables": len(tables),
            "figures_dir": str(figs_dir), "tables_dir": str(tabs_dir),
            "report": str(out)}
