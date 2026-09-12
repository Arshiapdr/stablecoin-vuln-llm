#!/usr/bin/env python3
"""Print results/depeg.json as a readable per-threshold table.

The three event kinds are NESTED labels of one price history -- a price below
$0.80 is also below $0.95 and $0.99 -- so summing them counts the same collapse
three times. They are reported per kind here for that reason. Protocols with no
episode print "--" rather than 0.0, which would read as "the price hit zero".
"""
import collections
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from asv.config import Config          # noqa: E402
from asv.market import load_series, series_path  # noqa: E402

cfg = Config.load()
path = cfg.path("results") / "depeg.json"
if not path.exists():
    sys.exit(f"{path} missing -- run `asv data depeg` first")
doc = json.loads(path.read_text("utf-8"))

print(f"rule: price below the threshold for >= {doc.get('min_consecutive_minutes')} min "
      f"and >= {doc.get('min_consecutive_samples')} consecutive samples\n")
head = f"{'protocol':20}{'depeg':>7}{'severe':>8}{'failure':>9}{'samples':>9}{'min price':>11}  state"
print(head)
print("-" * len(head))
for name, v in doc["per_protocol"].items():
    c = collections.Counter(e["kind"] for e in v["events"])
    lo = min((e["min_price"] for e in v["events"]), default=None)
    if lo is None:                      # no episode: show the real series floor
        # Resolve the CSV from the protocol name, not from the absolute path
        # recorded in depeg.json: that path belongs to whichever machine ran
        # the stage and does not survive being read on another one.
        market_dir = cfg.path("raw") / "market"
        src = next((q for q in (series_path(market_dir, name, "1m"),
                                series_path(market_dir, name, "1h")) if q.exists()), None)
        series = [px for _, px in load_series(src)] if src else []
        lo_txt = f"--({min(series):.4f})" if series else "--"
    else:
        lo_txt = f"{lo:.4f}"
    print(f"{name:20}{c['depeg']:>7}{c['severe']:>8}{c['failure']:>9}"
          f"{v['samples']:>9}{lo_txt:>11}  {v['indicators']['state']}")

if doc.get("skipped"):
    print("\nnot $1.00-pegged, deliberately not thresholded:")
    for k, why in doc["skipped"].items():
        print(f"  {k:18} {why}")
