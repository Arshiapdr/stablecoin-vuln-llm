"""Stage 6 — prevention.

Two outputs:
  1. A mitigation report: every confirmed finding mapped to its design pattern,
     patch template and recommended parameters.
  2. An early-warning monitor over the behavioural indicators, scored by lead
     time against known depeg events.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

from .config import Config
from .detect import Finding, load_findings
from .kb import KnowledgeBase
from .market import DepegEvent, Indicators, compute_indicators, label_depegs


@dataclass
class Recommendation:
    protocol: str
    file: str
    contract: str
    function: str
    line: int
    vuln_id: str
    report_category: str
    vuln_title: str
    severity: str
    score: float
    mitigation_id: str
    mitigation_title: str
    actions: list[str]
    patch: str
    attack_path: str


def build_report(cfg: Config, findings_name: str = "findings.json",
                 out_name: str = "prevention.json",
                 md_name: str = "prevention.md") -> dict:
    kb = KnowledgeBase.load(cfg.knowledge_dir)
    findings = [f for f in load_findings(cfg, findings_name) if f.detected]
    findings.sort(key=lambda f: -f.score)

    recs: list[Recommendation] = []
    for f in findings:
        m = kb.mitigation_for(f.vuln_id)
        if not m:
            continue
        recs.append(Recommendation(
            protocol=f.protocol, file=f.file, contract=f.contract,
            function=f.function, line=f.start_line, vuln_id=f.vuln_id,
            report_category=f.report_category, vuln_title=f.title,
            severity=f.severity, score=f.score,
            mitigation_id=m.id, mitigation_title=m.title,
            actions=m.actions, patch=m.patch, attack_path=f.attack_path))

    out = cfg.path("results") / out_name
    out.write_text(json.dumps([asdict(r) for r in recs], indent=1), "utf-8")

    # human-readable checklist
    #
    # The heading used to read "Confirmed findings", and the sites below name
    # real protocols, files and line numbers. At the measured precision of this
    # detector most of them are NOT vulnerabilities, and several sit in the
    # control protocols, which were selected precisely because they carry the
    # safeguard in question. Publishing that as a confirmation would be an
    # assertion about live systems that the evidence does not support, so the
    # measured precision is carried into the document itself rather than left
    # in a separate metrics file a reader may never open.
    prec = None
    try:
        ev = json.loads((cfg.path("results") / "evaluation.json").read_text("utf-8"))
        prec = ev.get("overall", {}).get("precision")
    except (OSError, ValueError, KeyError):
        pass
    caveat = (f"measured precision of this run: **{prec:.3f}** "
              if isinstance(prec, (int, float)) else "")
    lines = ["# Prevention report", "",
             f"Detector outputs requiring review: **{len(recs)}**", "",
             "> These are UNVERIFIED detector outputs, not confirmed "
             "vulnerabilities. " + caveat +
             "\n> Each site below must be manually reviewed before it is treated "
             "as a finding, and no claim is made here about the security of any "
             "named protocol. Control protocols appear in this list by "
             "construction: they were included as negatives, so a site of theirs "
             "listed here is most likely a false positive. "
             "See `docs/FP_TRIAGE.md` for the adjudication procedure.", ""]
    by_class: dict[str, list[Recommendation]] = {}
    for r in recs:
        by_class.setdefault(r.vuln_id, []).append(r)
    for vid in sorted(by_class, key=lambda v: -len(by_class[v])):
        group = by_class[vid]
        head = group[0]
        lines += [f"## {vid} — {head.vuln_title}",
                  f"*Report category:* {head.report_category} · "
                  f"*Mitigation:* {head.mitigation_id} — {head.mitigation_title}",
                  "", "**Actions**"]
        lines += [f"- {a}" for a in head.actions]
        lines += ["", "**Patch template**", "```solidity", head.patch, "```", "",
                  f"**Affected sites ({len(group)})**", ""]
        for r in group[:25]:
            lines.append(f"- `{r.protocol}` {r.file}:{r.line} → `{r.function}` "
                         f"(score {r.score:.3f})")
        if len(group) > 25:
            lines.append(f"- ...and {len(group) - 25} more")
        lines.append("")
    md = cfg.path("results") / md_name
    md.write_text("\n".join(lines), "utf-8")

    return {"recommendations": len(recs), "classes": len(by_class),
            "output": str(out), "markdown": str(md)}


# --- early warning ----------------------------------------------------------
@dataclass
class Alert:
    ts: int
    state: str
    reasons: list[str]


def monitor(prices: list[tuple[int, float]],
            absorbing_supply: list[tuple[int, float]] | None,
            thresholds: dict, step: int = 60,
            step_seconds: int | None = None) -> list[Alert]:
    """Walk the series and emit an alert whenever the state leaves 'normal'.

    The monitor sees only data up to each point in time, so lead time measured
    against a later depeg event is honest.

    `step` is MINUTES of series time between evaluations, not samples. Both it
    and the warm-up window are converted using the series' own median spacing.

    This used to be counted in samples: `window = supply_growth_window_hours *
    60` gave 1440, and the loop was `range(1440, len(prices), 60)`. On minute
    data that is the intended 24-hour warm-up evaluated hourly, but on an
    hourly series of a few hundred points the range is EMPTY — the monitor
    never ran and reported zero alerts for a protocol collapsing to $0.06.
    Same defect class as the `prices[-1440:]` indicator window fixed earlier:
    a sample count silently standing in for a duration.
    """
    alerts: list[Alert] = []
    last_state = "normal"
    if len(prices) < 2:
        return alerts
    if step_seconds is None:
        gaps = sorted(b[0] - a[0] for a, b in zip(prices, prices[1:]))
        step_seconds = max(1, gaps[len(gaps) // 2])
    window_h = int(thresholds.get("supply_growth_window_hours", 24) or 24)
    window = max(1, -(-window_h * 3600 // step_seconds))     # ceil, in samples
    stride = max(1, -(-int(step) * 60 // step_seconds))      # ceil, in samples
    for i in range(window, len(prices), stride):
        ind = compute_indicators(
            prices[:i],
            [s for s in (absorbing_supply or []) if s[0] <= prices[i - 1][0]] or None,
            cfg_thresholds=thresholds)
        if ind.state != "normal" and ind.state != last_state:
            alerts.append(Alert(prices[i - 1][0], ind.state, ind.alerts))
        last_state = ind.state
    return alerts


def lead_time(alerts: list[Alert], events: list[DepegEvent],
              max_lookback_minutes: int = 2880) -> dict:
    """Minutes between the earliest *admissible* alert and each depeg event.

    Two rules make this an honest warning measure rather than a look-back
    artefact:

    1. **Bounded look-back.** Only alerts within `max_lookback_minutes` (default
       48h) before the event count. Without a bound, an alert weeks earlier is
       credited as a "warning", which is not a warning anyone could act on.
    2. **No credit across an earlier event.** Alerts at or before the END of the
       preceding depeg event are discarded, because those were raised by that
       earlier episode. The previous implementation took `prior[0]` — the first
       alert in the entire series — so every event after the first was credited
       to the very first alert ever emitted. On a two-event series that reported
       a median lead time of 31 days from an unrelated blip.

    An alert raised *during* the event itself is not a warning and scores None.
    """
    evs = sorted(events, key=lambda e: e.start_ts)
    out = []
    for i, ev in enumerate(evs):
        floor = ev.start_ts - max_lookback_minutes * 60
        if i:                                   # never reach across a prior event
            floor = max(floor, evs[i - 1].end_ts + 1)
        cand = [a for a in alerts if floor <= a.ts < ev.start_ts]
        first = min(cand, key=lambda a: a.ts) if cand else None
        out.append({
            "event_start": ev.start_iso, "kind": ev.kind,
            "lead_minutes": int((ev.start_ts - first.ts) / 60) if first else None,
            "first_alert_state": first.state if first else None,
            "admissible_alerts": len(cand),
        })
    hit = sorted(o["lead_minutes"] for o in out if o["lead_minutes"] is not None)
    return {"events": out,
            "detected": len(hit), "total": len(out),
            "max_lookback_minutes": max_lookback_minutes,
            "median_lead_minutes": hit[len(hit) // 2] if hit else None}
