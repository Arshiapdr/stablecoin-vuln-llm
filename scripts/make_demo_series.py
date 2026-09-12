#!/usr/bin/env python3
"""Generate a SYNTHETIC UST-shaped minute series for demonstrating the
behavioural track without network access.

This is NOT real data and must never be used for a reported result. For real
data run:  asv data fetch
"""
import csv
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from asv.config import Config  # noqa: E402


def main() -> int:
    cfg = Config.load()
    random.seed(int(cfg.get("seed", 0)))
    t0 = 1651881600                      # 2022-05-07 00:00 UTC
    rows = []
    for i in range(8 * 1440):
        day = i / 1440
        if day < 1.0:
            p = 1.0 + random.gauss(0, 0.0004)
        elif day < 2.0:
            p = 0.995 - 0.02 * (day - 1) + random.gauss(0, 0.002)
        elif day < 3.0:
            p = 0.80 - 0.15 * (day - 2) + random.gauss(0, 0.01)
        elif day < 5.0:
            p = 0.45 - 0.15 * (day - 3) + random.gauss(0, 0.02)
        else:
            p = max(0.03, 0.15 - 0.03 * (day - 5)) + random.gauss(0, 0.01)
        rows.append((t0 + i * 60, round(max(0.01, p), 6)))

    out = cfg.path("raw") / "market"
    out.mkdir(parents=True, exist_ok=True)
    path = out / "SYNTHETIC_1m.csv"
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["ts", "price"])
        w.writerows(rows)
    print(f"wrote {len(rows)} synthetic minutes to {path}")
    print("NOTE: synthetic. Use `asv data fetch` for real data.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
