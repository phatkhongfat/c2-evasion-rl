#!/usr/bin/env python3
"""In bảng evasion rate theo classtype (plan P2)."""
import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "snort_validation"))
from alert_strat import stratify


ap = argparse.ArgumentParser()
ap.add_argument("--sweep", default=str(ROOT / "snort_validation/reports/ceiling_ownership_both_v2.json"))
ap.add_argument("--rules", default=str(ROOT / "snort_validation/et_open_c2/et_open_c2.rules"))
args = ap.parse_args()
res = stratify(args.sweep, args.rules)
if not res:
    print("(no baseline_sids in this sweep — older report, or no flow alerted "
          "at baseline; rerun sweep with the P2 code for stratification)",
          file=sys.stderr)
for g, per in res.items():
    print(f"\n### classtype: {g}")
    print("| mech | flows | evaded | valid |")
    print("|---|---|---|---|")
    for m, d in sorted(per.items(), key=lambda kv: -kv[1]["valid"]):
        print(f"| {m} | {d['flows']} | {d['evaded']} | {d['valid']} |")
