#!/usr/bin/env python3
"""One table for every findings file in results/, scored the same way.

`asv detect` prints how many findings a run produced, not whether they were
right; `asv evaluate` scores one file at a time and writes JSON. After an
ablation sweep what you actually want is the runs side by side, including the
two columns the ablations exist to move: precision, and how many false
positives land on CONTROL protocols -- protocols chosen because they carry the
safeguards, so a hit there is the costly kind of error.

    python scripts/show_runs.py
    python scripts/show_runs.py --labels smartbugs.yaml      # benchmark track
"""
import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from asv.config import Config, file_matches          # noqa: E402
from asv.detect import load_findings                 # noqa: E402
from asv.evaluation import evaluate, load_labels     # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--labels", default="ground_truth.yaml")
args = ap.parse_args()

cfg = Config.load()
labels = load_labels(cfg, args.labels)
controls = {p["name"] for p in cfg.protocol_list("control")}
results = cfg.path("results")

# Canonical order first, then anything else found on disk.
ORDER = ["findings.json", "findings_no_static.json", "findings_no_critic.json",
         "findings_normalized.json", "findings_fewshot.json",
         "findings_static.json", "findings_slither.json"]
found = sorted(p.name for p in results.glob("findings*.json"))
names = [n for n in ORDER if n in found] + [n for n in found if n not in ORDER]
if not names:
    sys.exit(f"no findings*.json in {results}")

def is_label(f):
    return any(lb.protocol == f.protocol and file_matches(lb.file_contains, f.file)
               and lb.function == f.function and lb.vuln_id == f.vuln_id for lb in labels)

# Wide numeric fields: the static baseline scores the WHOLE corpus, so its
# counts run to five digits and narrower columns silently ran together.
hdr = (f"{'run':30}{'pairs':>7}{'det':>6}{'TP':>5}{'FP':>6}{'ctrlFP':>8}"
       f"{'prec':>7}{'rec':>7}{'F1':>7}{'cov':>7}{'effF1':>7}")
print(f"labels: {args.labels} ({len(labels)})\n")
print(hdr)
print("-" * len(hdr))
for name in names:
    try:
        f = load_findings(cfg, name)
    except Exception as e:                                   # noqa: BLE001
        print(f"{name:30}  unreadable: {type(e).__name__}")
        continue
    if not f:
        print(f"{name:30}  empty")
        continue
    m = evaluate(f, labels)["overall"]
    det = [x for x in f if x.detected]
    cfp = sum(1 for x in det if not is_label(x) and x.protocol in controls)
    print(f"{name:30}{len(f):>7}{len(det):>6}{m['tp']:>5}{m['fp']:>6}{cfp:>8}"
          f"{m['precision']:>7.3f}{m['recall']:>7.3f}{m['f1']:>7.3f}"
          f"{m['coverage']:>7.3f}{m['effective_f1']:>7.3f}")

print("\ncov = 1 - (parse failures + self-contradicting critic replies) / findings")
print("effF1 = F1 x cov, so abstentions are charged against the run")
print("ctrlFP = false positives on control protocols (the expensive kind)")
print("\nNOTE: rows are only comparable at equal `pairs`. The rule baseline")
print("(findings_static.json) scores the WHOLE corpus, not the 216-slice sample,")
print("so compare it on precision/recall, never on raw counts.")
