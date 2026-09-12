#!/usr/bin/env python3
"""Verify every ground-truth label anchors to a function that exists in the corpus."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from asv.config import Config, file_matches  # noqa: E402
from asv.evaluation import load_labels  # noqa: E402
from asv.slicing import load as load_slices  # noqa: E402

cfg = Config.load()
slices = load_slices(cfg)
labels = load_labels(cfg)
bad = []
for lb in labels:
    hit = [s for s in slices
           if s.protocol == lb.protocol
           and file_matches(lb.file_contains, s.file)
           and s.function == lb.function]
    print(f"{'OK ' if hit else 'MISS'} {lb.vuln_id:4} {lb.protocol:16} {lb.function}")
    if not hit:
        bad.append(lb)
print(f"\n{len(labels) - len(bad)}/{len(labels)} labels anchored")
sys.exit(1 if bad else 0)
