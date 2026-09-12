"""Command-line interface.  `asv --help` lists everything."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from . import (baselines, corpus, detect, evaluation, market, prevent, report,
               slicing, trace)
from .config import Config
from .kb import KnowledgeBase


def _echo(title: str, payload: dict) -> None:
    click.secho(f"\n{title}", fg="cyan", bold=True)
    click.echo(json.dumps(payload, indent=1, ensure_ascii=False))


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--root", type=click.Path(file_okay=False), default=None,
              help="Repository root (defaults to the installed package's repo).")
@click.pass_context
def cli(ctx, root):
    """Algorithmic-stablecoin vulnerability detection with free LLMs."""
    ctx.obj = Config.load(root)


# --- stage 0 ----------------------------------------------------------------
@cli.command()
@click.option("--only", multiple=True, help="Limit to these protocol names.")
@click.option("--force", is_flag=True, help="Re-clone even if present.")
@click.option("--benchmarks", is_flag=True, help="Also clone the comparison corpora.")
@click.pass_obj
def corpus_cmd(cfg, only, force, benchmarks):
    """Clone protocol repos and collect stabilisation-logic source files."""
    _echo("corpus", corpus.build(cfg, list(only) or None, force, benchmarks))


cli.add_command(corpus_cmd, name="corpus")


# --- stage 1 ----------------------------------------------------------------
@cli.command("slice")
@click.option("--limit", type=int, default=None)
@click.pass_obj
def slice_cmd(cfg, limit):
    """Cut the corpus into function-level slices with context."""
    _echo("slices", slicing.build(cfg, limit))


# --- stage 2 ----------------------------------------------------------------
@cli.command("kb")
@click.pass_obj
def kb_cmd(cfg):
    """Validate and summarise the vulnerability knowledge base."""
    kb = KnowledgeBase.load(cfg.knowledge_dir)
    rows = [{"id": v.id, "report_category": v.report_category, "layer": v.layer,
             "severity": v.severity, "mitigation": v.mitigation, "title": v.title}
            for v in kb]
    _echo(f"knowledge base ({len(kb)} classes)", {"classes": rows})


# --- stage 3 ----------------------------------------------------------------
@cli.command()
@click.option("--provider", default=None,
              help="gemini | mistral | nvidia | openrouter | groq | local | mock")
@click.option("--limit", type=int, default=None, help="Analyse only N slices.")
@click.option("--protocol", "protocols", multiple=True)
@click.option("--normalized", is_flag=True, help="Use identifier-normalised code.")
@click.option("--no-critic", is_flag=True)
@click.option("--no-static", is_flag=True)
@click.option("--no-slither", is_flag=True)
@click.option("--out", "out_name", default="findings.json")
@click.option("--no-include-labeled", is_flag=True,
              help="Do not force ground-truth functions into a limited run.")
@click.option("--few-shot", is_flag=True,
              help="Add worked examples to the auditor prompt, selected "
                   "leave-one-protocol-out so no target sees its own answer.")
@click.pass_obj
def detect_cmd(cfg, provider, limit, protocols, normalized, no_critic, no_static,
               no_slither, out_name, no_include_labeled, few_shot):
    """Run the LLM detector over the slices."""
    total = {"n": 0}

    def progress(i, n):
        total["n"] = n
        if i % 10 == 0 or i == n:
            click.echo(f"  {i}/{n} slices", err=True)

    res = detect.run(cfg, provider, limit, list(protocols) or None, normalized,
                     not no_critic, not no_static, not no_slither, out_name, progress,
                     include_labeled=not no_include_labeled, few_shot=few_shot)
    _echo("detect", res)


cli.add_command(detect_cmd, name="detect")


# --- stage 4 ----------------------------------------------------------------
@cli.group()
def data():
    """Fetch market data and label depeg events."""


@data.command("fetch")
@click.option("--protocol", "protocols", multiple=True,
              help="Fetch only these protocols (repeatable). Default: all with "
                   "a `market:` block in configs/protocols.yaml.")
@click.pass_obj
def data_fetch(cfg, protocols):
    """Download price, supply and incident data (all free, no key).

    Series are declared per protocol in configs/protocols.yaml under `market:`
    and written as `<protocol>_1h.csv` / `_1m.csv` / `_supply.csv`, named by the
    corpus entry rather than by ticker so every file traces back to a protocol.
    """
    out = cfg.path("raw") / "market"
    wanted = set(protocols)
    todo = [(n, m) for n, m in market.market_protocols(cfg)
            if not wanted or n in wanted]
    missing = wanted - {n for n, _ in todo}
    res: dict = {"protocols": len(todo), "results": []}
    if missing:
        res["no_market_series"] = sorted(missing)
    for name, _ in todo:
        res["results"].append(market.fetch_protocol(cfg, name, out))
    try:
        res["hacks"] = str(market.fetch_hacks(out))
    except Exception as e:                                  # noqa: BLE001
        res["hacks_error"] = f"{type(e).__name__}: {e}"
    ok = sum(1 for r in res["results"] if r.get("hourly") or r.get("minutes"))
    _echo("data fetch", {"protocols": len(todo), "with_a_price_series": ok,
                         "output_dir": str(out),
                         "no_market_series": res.get("no_market_series", []),
                         "results": res["results"]})


def _depeg_one(cfg, s, th, minutes, floor):
    events = (market.label_depegs(s, th["depeg_threshold"], minutes, "depeg",
                                  min_samples=floor)
              + market.label_depegs(s, th["severe_threshold"], minutes, "severe",
                                    min_samples=floor)
              + market.label_depegs(s, th["failure_threshold"], minutes, "failure",
                                    min_samples=floor))
    step = "unknown"
    if len(s) > 1:
        gaps = sorted(b[0] - a[0] for a, b in zip(s, s[1:]))
        step = gaps[len(gaps) // 2]
    return {"samples": len(s), "median_step_seconds": step,
            "events": market.events_to_json(events),
            "indicators": market.compute_indicators(s, cfg_thresholds=th).__dict__,
            "sensitivity": market.sensitivity(
                s, cfg.get("behavior.sensitivity_grid", [0.99]), minutes,
                min_samples=floor)}


@data.command("depeg")
@click.option("--series", type=click.Path(exists=True), default=None,
              help="Score one CSV directly. Omit to score every protocol that "
                   "has a fetched, USD-pegged series.")
@click.option("--protocol", "protocols", multiple=True,
              help="Restrict the per-protocol run to these names.")
@click.pass_obj
def data_depeg(cfg, series, protocols):
    """Label depeg events and run the threshold sensitivity analysis.

    Without --series this iterates every protocol whose `market.peg_target` is
    `usd`. Protocols targeting something else are skipped with a reason rather
    than silently thresholded: agEUR is euro-pegged, and AMPL and RAI have no
    fixed $1.00 target at all, so "deviation from $1.00" is undefined for them.
    """
    th = {k: cfg.get(f"behavior.{k}") for k in
          ("depeg_threshold", "severe_threshold", "failure_threshold",
           "min_consecutive_minutes", "supply_growth_window_hours",
           "supply_growth_alert", "backing_ratio_alert", "pool_imbalance_alert")}
    minutes = int(th["min_consecutive_minutes"] or 5)
    floor = int(cfg.get("behavior.min_consecutive_samples", 2))
    market_dir = cfg.path("raw") / "market"

    if series:
        res = _depeg_one(cfg, market.load_series(Path(series)), th, minutes, floor)
        out = cfg.path("results") / "depeg.json"
        out.write_text(json.dumps(res, indent=1), "utf-8")
        _echo("depeg", {k: v for k, v in res.items() if k != "events"} |
              {"n_events": len(res["events"]), "output": str(out)})
        return

    wanted = set(protocols)
    per: dict = {}
    skipped: dict = {}
    for name, spec in market.market_protocols(cfg):
        if wanted and name not in wanted:
            continue
        if spec.get("peg_target") not in market.DEPEGGABLE_PEG_TARGETS:
            skipped[name] = f"peg_target={spec.get('peg_target')!r}, not a $1.00 target"
            continue
        path = next((p for p in (market.series_path(market_dir, name, "1m"),
                                 market.series_path(market_dir, name, "1h"))
                     if p.exists()), None)
        if path is None:
            skipped[name] = "no fetched series — run `asv data fetch`"
            continue
        s = market.load_series(path)
        if not s:
            # A header-only CSV is what a wholly failed download leaves behind.
            # Scoring it would report "0 events", which reads exactly like a
            # protocol whose peg held. Refuse rather than publish that.
            skipped[name] = f"series file has no samples: {path.name}"
            continue
        per[name] = _depeg_one(cfg, s, th, minutes, floor)
        per[name]["series"] = str(path)
    res = {"per_protocol": per, "skipped": skipped,
           "min_consecutive_minutes": minutes, "min_consecutive_samples": floor}
    out = cfg.path("results") / "depeg.json"
    out.write_text(json.dumps(res, indent=1), "utf-8")
    _echo("depeg", {"scored": sorted(per),
                    "events": {k: len(v["events"]) for k, v in per.items()},
                    "skipped": skipped, "output": str(out)})


@data.command("monitor")
@click.option("--series", type=click.Path(exists=True), default=None,
              help="Monitor one CSV directly. Omit to monitor every protocol "
                   "with a fetched, USD-pegged series.")
@click.option("--supply", type=click.Path(exists=True), default=None)
@click.option("--protocol", "protocols", multiple=True)
@click.pass_obj
def data_monitor(cfg, series, supply, protocols):
    """Run the early-warning monitor and report lead time."""
    th = {k: cfg.get(f"behavior.{k}") for k in
          ("depeg_threshold", "severe_threshold", "failure_threshold",
           "supply_growth_window_hours", "supply_growth_alert",
           "backing_ratio_alert", "pool_imbalance_alert")}
    minutes = int(cfg.get("behavior.min_consecutive_minutes", 5))
    floor = int(cfg.get("behavior.min_consecutive_samples", 2))
    market_dir = cfg.path("raw") / "market"

    def run(s, sup):
        alerts = prevent.monitor(s, sup, th)
        events = market.label_depegs(s, th["depeg_threshold"], minutes,
                                     min_samples=floor)
        return ({"alerts": len(alerts),
                 "lead_time": prevent.lead_time(alerts, events)},
                [a.__dict__ for a in alerts])

    out = cfg.path("results") / "monitor.json"
    if series:
        res, ev = run(market.load_series(Path(series)),
                      market.load_series(Path(supply)) if supply else None)
        out.write_text(json.dumps({**res, "alert_events": ev}, indent=1), "utf-8")
        _echo("monitor", res | {"output": str(out)})
        return

    wanted = set(protocols)
    per: dict = {}
    for name, spec in market.market_protocols(cfg, depeggable_only=True):
        if wanted and name not in wanted:
            continue
        path = next((p for p in (market.series_path(market_dir, name, "1m"),
                                 market.series_path(market_dir, name, "1h"))
                     if p.exists()), None)
        if path is None:
            continue
        s = market.load_series(path)
        if not s:
            continue                       # empty file: nothing to monitor
        sup_path = market.series_path(market_dir, name, "supply")
        res, ev = run(s, market.load_series(sup_path) if sup_path.exists() else None)
        per[name] = {**res, "series": str(path),
                     "supply": str(sup_path) if sup_path.exists() else None,
                     "alert_events": ev}
    # Aggregate across protocols as well as per protocol. `--series` mode
    # writes a FLAT record and every consumer was built against that shape, so
    # the per-protocol mode used to emit a file whose alerts and lead times
    # were invisible to `asv report` -- Table 8 rendered as all zeros while the
    # monitor had in fact raised alerts on 12 protocols.
    pooled = [e for v in per.values() for e in v["lead_time"]["events"]
              if e.get("lead_minutes") is not None]
    pooled.sort(key=lambda e: e["lead_minutes"])
    agg = {
        "alerts": sum(v["alerts"] for v in per.values()),
        "lead_time": {
            "total": sum(v["lead_time"]["total"] for v in per.values()),
            "detected": sum(v["lead_time"]["detected"] for v in per.values()),
            # Median over the pooled events, not a median of per-protocol
            # medians, which would weight a one-episode protocol equally with
            # a twenty-episode one.
            "median_lead_minutes": (pooled[len(pooled) // 2]["lead_minutes"]
                                    if pooled else None),
            "max_lookback_minutes": next(
                (v["lead_time"]["max_lookback_minutes"] for v in per.values()), None),
            "protocols": len(per),
        },
    }
    out.write_text(json.dumps({**agg, "per_protocol": per}, indent=1), "utf-8")
    _echo("monitor", {"monitored": sorted(per),
                      "alerts": {k: v["alerts"] for k, v in per.items()},
                      "output": str(out)})


# --- stage 5 ----------------------------------------------------------------
@cli.command("slither")
@click.pass_obj
def slither_cmd(cfg):
    """Run Slither over the corpus (optional; used as a baseline and a signal)."""
    _echo("slither", baselines.run_slither(cfg))


@cli.command("baseline")
@click.option("--kind", type=click.Choice(["slither", "static"]), required=True)
@click.pass_obj
def baseline_cmd(cfg, kind):
    """Produce a baseline findings file comparable with the LLM run."""
    fn = baselines.slither_findings if kind == "slither" else baselines.static_only_findings
    _echo(f"baseline:{kind}", fn(cfg))


@cli.command("evaluate")
@click.option("--findings", "findings_name", default="findings.json")
@click.option("--out", "out_name", default="evaluation.json")
@click.option("--no-bootstrap", is_flag=True)
@click.option("--labels", "labels_name", default="ground_truth.yaml",
              help="Label file under labels/. Use smartbugs.yaml to score the "
                   "external benchmark track separately.")
@click.pass_obj
def evaluate_cmd(cfg, findings_name, out_name, no_bootstrap, labels_name):
    """Score a findings file against the ground truth."""
    _echo("evaluation", evaluation.run(cfg, findings_name, out_name,
                                       not no_bootstrap, labels_name))


@cli.command("layers")
@click.option("--findings", "findings_name", default="findings.json")
@click.pass_obj
def layers_cmd(cfg, findings_name):
    """Score the run separately on pure / partial / control layers."""
    _echo("layers", evaluation.by_layer(cfg, findings_name))


@cli.command("compare")
@click.pass_obj
def compare_cmd(cfg):
    """Compare the main run with the baselines and ablations."""
    runs = {"llm_full": "findings.json",
            "llm_no_critic": "findings_no_critic.json",
            "llm_no_kb_static": "findings_no_static.json",
            "llm_normalized_ids": "findings_normalized.json",
            "llm_few_shot": "findings_fewshot.json",
            "baseline_static_rules": "findings_static.json",
            "baseline_slither": "findings_slither.json"}
    _echo("comparison", evaluation.compare(cfg, runs))


# --- stage 6 ----------------------------------------------------------------
@cli.command("prevent")
@click.option("--findings", "findings_name", default="findings.json")
@click.pass_obj
def prevent_cmd(cfg, findings_name):
    """Map confirmed findings to mitigations and write the prevention report."""
    _echo("prevention", prevent.build_report(cfg, findings_name))


# --- transparency -----------------------------------------------------------
@cli.command("trace")
@click.option("--provider", default=None, help="Which backend to call.")
@click.option("--function", default=None, help="Function name to trace.")
@click.option("--protocol", default=None, help="Restrict to one protocol.")
@click.option("--slice-id", default=None, help="Exact slice id.")
@click.option("--class", "vuln_id", default=None, help="Force a class, e.g. V1.")
@click.option("--dry-run", is_flag=True,
              help="Print the prompt and stop. No model call, no quota.")
@click.option("--out", "out_path", type=click.Path(), default=None,
              help="Also write the trace to a markdown file.")
@click.pass_obj
def trace_cmd(cfg, provider, function, protocol, slice_id, vuln_id, dry_run, out_path):
    """Show the full prompt, raw model reply and every decision for ONE function."""
    text, summary = trace.run(cfg, provider, function, protocol, slice_id,
                              vuln_id, dry_run)
    click.echo(text)
    if out_path:
        Path(out_path).write_text(text, "utf-8")
        click.secho(f"\nwritten to {out_path}", fg="green")
    _echo("summary", summary)


# --- stage 7 ----------------------------------------------------------------
@cli.command("report")
@click.option("--series", type=click.Path(exists=True), default=None,
              help="Price series to plot in the depeg figure.")
@click.pass_obj
def report_cmd(cfg, series):
    """Generate figures and tables for the written report."""
    _echo("report", report.build(cfg, series))


# --- convenience ------------------------------------------------------------
@cli.command("run-all")
@click.option("--provider", default="mock", show_default=True)
@click.option("--limit", type=int, default=200, show_default=True,
              help="Slices to analyse (keep small on a free tier).")
@click.option("--skip-corpus", is_flag=True)
@click.pass_obj
def run_all(cfg, provider, limit, skip_corpus):
    """Corpus -> slice -> detect -> baseline -> evaluate -> prevent."""
    if not skip_corpus:
        _echo("corpus", corpus.build(cfg))
    _echo("slices", slicing.build(cfg))
    _echo("baseline:static", baselines.static_only_findings(cfg))
    _echo("detect", detect.run(cfg, provider, limit))
    _echo("evaluation", evaluation.run(cfg, "findings.json"))
    _echo("prevention", prevent.build_report(cfg))
    _echo("report", report.build(cfg))
    click.secho("\nDone. See results/REPORT.md, results/figures/ and results/tables/.",
                fg="green", bold=True)


@cli.command("status")
@click.pass_obj
def status_cmd(cfg):
    """Show which providers are usable and which artifacts exist."""
    art = {}
    for name, p in [("corpus.json", cfg.path("interim") / "corpus.json"),
                    ("slices.json", cfg.path("processed") / "slices.json"),
                    ("slither.json", cfg.path("processed") / "slither.json"),
                    ("findings.json", cfg.path("results") / "findings.json"),
                    ("evaluation.json", cfg.path("results") / "evaluation.json"),
                    ("prevention.md", cfg.path("results") / "prevention.md")]:
        art[name] = p.exists()
    _echo("status", {
        "providers_configured": cfg.provider_order,
        "providers_usable_now": cfg.available_providers(),
        "slither_installed": baselines.slither_available(),
        "artifacts": art,
    })


def main() -> int:
    try:
        cli()
    except Exception as exc:                    # friendly failure
        click.secho(f"error: {type(exc).__name__}: {exc}", fg="red", err=True)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
