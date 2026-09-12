#!/usr/bin/env python3
"""Draw the implementation architecture: fig7_architecture.png / .pdf

Deliberately carries NO numbers -- no slice counts, no metrics, no protocol
counts. Those live in Figures 1-6 and in the tables, and they change with every
run; this diagram must stay true whatever the run produced. It shows what
component exists, what it reads and what it writes.

    python scripts/draw_architecture.py
    python scripts/draw_architecture.py --out-dir some/where
"""
import argparse
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import matplotlib                                        # noqa: E402
matplotlib.use("Agg")
import matplotlib.pyplot as plt                          # noqa: E402
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch  # noqa: E402

# Palette shared with report.py so the figure sits in the same visual system.
INK, INK_2, MUTED = "#11161c", "#3d4753", "#8a94a2"
BLUE, GREEN, AMBER, GREY = "#2f6fd0", "#12946b", "#c07800", "#69737f"
SURFACE, BAND = "#fbfbfa", "#f2f5f9"

PROCESS, SOURCE, ARTIFACT, MODEL = "process", "source", "artifact", "model"
STYLE = {
    PROCESS:  dict(fc="#e9f0fb", ec=BLUE,  lw=1.4, tc=INK),
    SOURCE:   dict(fc="#f0f1f3", ec=GREY,  lw=1.2, tc=INK_2),
    ARTIFACT: dict(fc="#eaf6f1", ec=GREEN, lw=1.2, tc=INK_2),
    MODEL:    dict(fc="#fdf3e3", ec=AMBER, lw=1.4, tc=INK),
}


def box(ax, x, y, w, h, title, sub=None, kind=PROCESS, fs=9.5):
    """A labelled box. Title and subtitle are spaced by the SUBTITLE's line
    count, otherwise a three-line caption prints on top of its own heading."""
    s = STYLE[kind]
    ax.add_patch(FancyBboxPatch((x, y), w, h,
                                boxstyle="round,pad=0.012,rounding_size=0.06",
                                fc=s["fc"], ec=s["ec"], lw=s["lw"], zorder=3))
    cy = y + h / 2
    if not sub:
        ax.text(x + w / 2, cy, title, ha="center", va="center", fontsize=fs,
                fontweight="bold", color=s["tc"], zorder=4)
        return (x, y, w, h)
    nl = sub.count("\n") + 1
    gap = 0.10 + 0.075 * (nl - 1)
    ax.text(x + w / 2, cy + gap, title, ha="center", va="bottom", fontsize=fs,
            fontweight="bold", color=s["tc"], zorder=4)
    ax.text(x + w / 2, cy + gap - 0.10, sub, ha="center", va="top",
            fontsize=7.6, color=MUTED, zorder=4, linespacing=1.45)
    return (x, y, w, h)


def arrow(ax, a, b, side="right", text=None, style="-|>", colour=INK_2, rad=0.0):
    """Connect box a to box b. `side` picks the anchor pair."""
    ax_, ay, aw, ah = a
    bx, by, bw, bh = b
    pts = {
        "right": ((ax_ + aw, ay + ah / 2), (bx, by + bh / 2)),
        "down":  ((ax_ + aw / 2, ay), (bx + bw / 2, by + bh)),
        "up":    ((ax_ + aw / 2, ay + ah), (bx + bw / 2, by)),
    }[side]
    ax.add_patch(FancyArrowPatch(pts[0], pts[1], arrowstyle=style, mutation_scale=11,
                                 lw=1.15, color=colour, zorder=2,
                                 connectionstyle=f"arc3,rad={rad}",
                                 shrinkA=1.5, shrinkB=2.5))
    if text:
        mx, my = (pts[0][0] + pts[1][0]) / 2, (pts[0][1] + pts[1][1]) / 2
        ax.text(mx, my + 0.10, text, ha="center", va="bottom", fontsize=7,
                color=MUTED, zorder=4)


def band(ax, y, h, label):
    ax.add_patch(plt.Rectangle((0.05, y), 15.9, h, fc=BAND, ec="none", zorder=0))
    ax.text(0.18, y + h - 0.06, label, ha="left", va="top", fontsize=8,
            fontweight="bold", color=MUTED, zorder=1)


def draw():
    fig, ax = plt.subplots(figsize=(16, 10.9))
    fig.patch.set_facecolor(SURFACE)
    ax.set_xlim(0, 16); ax.set_ylim(0, 10.9); ax.axis("off")

    ax.text(0.05, 10.80, "Implementation architecture", fontsize=16,
            fontweight="bold", color=INK, va="top")
    ax.text(0.05, 10.36,
            "Two independent tracks. The static track produces findings, which "
            "are scored against the ground truth to give the detection metrics.\n"
            "The behavioural track is never mixed into those metrics — its "
            "episodes and alerts are plotted and tabulated in the report.",
            fontsize=9.6, color=INK_2, va="top", linespacing=1.45)

    band(ax, 7.15, 2.30, "STATIC TRACK — contract code")
    band(ax, 4.95, 2.05, "BEHAVIOURAL TRACK — market series")
    band(ax, 0.30, 4.10, "SCORING, ABLATION AND REPORTING")

    # ---- static track ---------------------------------------------------
    src_repo = box(ax, 0.35, 8.25, 2.05, 0.95, "Protocol\nrepositories")
    corpus = box(ax, 2.85, 8.25, 2.05, 0.95, "Corpus builder",
                 "asv corpus\n→ corpus.json", PROCESS)
    slicer = box(ax, 5.35, 8.25, 2.05, 0.95, "Function slicer",
                 "asv slice\n→ slices.json", PROCESS)
    detect = box(ax, 8.35, 8.02, 3.75, 1.33, "", None, PROCESS, 11)
    ax.text(10.22, 9.02, "Detection engine", ha="center", va="center",
            fontsize=11, fontweight="bold", color=INK, zorder=4)
    ax.text(10.22, 8.66, "asv detect  →  findings.json", ha="center",
            va="center", fontsize=8.4, color=INK_2, zorder=4)
    ax.text(10.22, 8.28,
            "retrieve classes → auditor ×2 → adversarial critic\n"
            "→ static confirmation → accept / reject",
            ha="center", va="center", fontsize=7.9, color=MUTED, zorder=4,
            linespacing=1.5)
    kb = box(ax, 5.35, 7.32, 2.05, 0.80, "Knowledge base",
             "scenario + property per class", ARTIFACT, 9)
    llm = box(ax, 13.25, 8.25, 2.30, 0.95, "Local LLM",
              "llama.cpp server\nOpenAI-compatible", MODEL)

    arrow(ax, src_repo, corpus); arrow(ax, corpus, slicer); arrow(ax, slicer, detect)
    ax.add_patch(FancyArrowPatch((7.40, 7.72), (8.90, 8.05), arrowstyle="-|>",
                                 mutation_scale=11, lw=1.15, color=INK_2,
                                 connectionstyle="arc3,rad=-0.18", zorder=2))
    ax.add_patch(FancyArrowPatch((12.10, 8.70), (13.25, 8.70), arrowstyle="<|-|>",
                                 mutation_scale=11, lw=1.3, color=AMBER, zorder=2))
    ax.text(12.67, 8.82, "prompt /\nJSON verdict", ha="center", va="bottom",
            fontsize=7.2, color=MUTED)
    ax.text(14.40, 8.16, "responses cached — re-runs are free", ha="center",
            va="top", fontsize=7.2, color=MUTED, style="italic")

    # ---- behavioural track ----------------------------------------------
    src_mkt = box(ax, 0.35, 5.30, 2.05, 1.05, "Market data",
                  "prices · supply\nincidents", SOURCE)
    fetch = box(ax, 2.85, 5.30, 2.05, 1.05, "Series fetcher",
                "asv data fetch", PROCESS)
    depeg = box(ax, 5.35, 5.30, 2.05, 1.05, "Depeg labeller",
                "asv data depeg\n→ depeg.json", PROCESS)
    monitor = box(ax, 8.35, 5.30, 2.40, 1.05, "Indicator monitor",
                  "asv data monitor\n→ monitor.json", PROCESS)
    arrow(ax, src_mkt, fetch); arrow(ax, fetch, depeg); arrow(ax, depeg, monitor)

    # ---- scoring ---------------------------------------------------------
    truth = box(ax, 0.35, 2.95, 2.05, 1.00, "Ground truth",
                "hand-verified\nlabels + sources", ARTIFACT)
    baselines = box(ax, 0.35, 1.30, 2.05, 1.00, "Baselines",
                    "rule engine", PROCESS)
    ablate = box(ax, 2.85, 1.30, 2.30, 1.00, "Ablations",
                 "no critic · no static\nnormalised · few-shot", PROCESS)
    evaluate = box(ax, 5.65, 1.60, 2.85, 1.75, "", None, PROCESS, 11)
    ax.text(7.07, 2.93, "Evaluation", ha="center", va="center", fontsize=11,
            fontweight="bold", color=INK, zorder=4)
    ax.text(7.07, 2.59, "asv evaluate · layers · compare", ha="center",
            va="center", fontsize=8.4, color=INK_2, zorder=4)
    ax.text(7.07, 2.13, "precision · recall · F1",
            ha="center", va="center", fontsize=7.9, color=MUTED, linespacing=1.5)
    prevent = box(ax, 9.45, 2.45, 2.30, 1.00, "Prevention",
                  "asv prevent → prevention.md\nsites + measured precision", PROCESS)
    report = box(ax, 9.45, 0.85, 2.30, 1.00, "Report builder",
                 "asv report\n→ figures · tables", PROCESS)
    out = box(ax, 12.85, 1.55, 2.55, 1.55, "Deliverables",
              "REPORT.md\nfigures/ · tables/\nprevention.md", ARTIFACT, 10.5)

    arrow(ax, truth, evaluate, rad=-0.05)
    arrow(ax, ablate, evaluate, rad=-0.05)
    arrow(ax, baselines, ablate)
    arrow(ax, evaluate, prevent, rad=0.06)
    arrow(ax, evaluate, report, rad=-0.06)
    arrow(ax, prevent, out, rad=0.06)
    arrow(ax, report, out, rad=-0.06)

    def elbow(ax, pts, colour, label=None, lx=None, ly=None):
        """Orthogonal connector. A long diagonal arc sweeping across a band
        reads as if it ENTERED the boxes it passes; right-angled routing does
        not."""
        for (x0, y0), (x1, y1) in zip(pts, pts[1:-1]):
            ax.plot([x0, x1], [y0, y1], color=colour, lw=1.3, zorder=2,
                    solid_capstyle="round")
        ax.add_patch(FancyArrowPatch(pts[-2], pts[-1], arrowstyle="-|>",
                                     mutation_scale=12, lw=1.3, color=colour,
                                     zorder=2, shrinkA=0, shrinkB=2))
        if label:
            ax.text(lx, ly, label, fontsize=8, color=colour, style="italic",
                    ha="left", va="bottom", zorder=4)

    # findings -> Evaluation, down the right margin and back along the top of
    # the scoring band. This is the ONLY thing the detection metrics are
    # computed from, together with the ground truth.
    elbow(ax, [(11.90, 8.02), (12.35, 8.02), (12.35, 3.78), (7.07, 3.78),
               (7.07, 3.35)], INK_2, "findings.json", 12.48, 5.60)

    # behavioural results -> Report builder ONLY. They are plotted and
    # tabulated; they never enter precision, recall or F1.
    elbow(ax, [(10.00, 5.30), (10.00, 4.15), (8.85, 4.15), (8.85, 1.35),
               (9.45, 1.35)], INK_2, "episodes · alerts", 8.30, 4.28)

    import matplotlib.patches as mp
    ax.legend(handles=[mp.Patch(fc=STYLE[SOURCE]["fc"], ec=GREY, label="external source"),
                       mp.Patch(fc=STYLE[PROCESS]["fc"], ec=BLUE, label="pipeline stage"),
                       mp.Patch(fc=STYLE[ARTIFACT]["fc"], ec=GREEN, label="data / deliverable"),
                       mp.Patch(fc=STYLE[MODEL]["fc"], ec=AMBER, label="language model")],
              loc="lower left", bbox_to_anchor=(0.30, -0.005), ncol=4,
              frameon=False, fontsize=9)
    return fig


def save(fig, out_dir: Path, name: str = "fig7_architecture") -> list[str]:
    """Write PNG and PDF atomically.

    Rendering straight onto the destination fails with EINVAL/EACCES when the
    file is open in a viewer, and can leave a half-written figure if the
    process dies. Write to a temporary file in the same directory, then
    os.replace() it into place.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for ext, kw in (("png", dict(dpi=200)), ("pdf", {})):
        target = out_dir / f"{name}.{ext}"
        fd, tmp = tempfile.mkstemp(dir=out_dir, suffix=f".{ext}")
        os.close(fd)
        try:
            fig.savefig(tmp, bbox_inches="tight", **kw)
            os.replace(tmp, target)
            written.append(str(target))
        except OSError as e:
            Path(tmp).unlink(missing_ok=True)
            raise SystemExit(
                f"could not write {target}: {e}\n"
                f"Close any viewer showing {target.name} and re-run.") from e
    plt.close(fig)
    return written


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", default=None)
    a = ap.parse_args()
    if a.out_dir:
        d = Path(a.out_dir)
    else:
        from asv.config import Config
        d = Config.load().path("results") / "figures"
    for p in save(draw(), d):
        print("wrote", p)
