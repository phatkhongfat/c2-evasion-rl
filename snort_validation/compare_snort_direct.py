#!/usr/bin/env python3
"""Task 5: compare real-Snort detection across policies on the seeded eval.

Reads the real-Snort validation reports (produced by validate_with_snort.py)
and prints detection / evasion side by side, plus the joint XGBoost picture.
"""
import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
REP = REPO / "snort_validation" / "reports"

DEFAULT = {
    "baseline (no mutation)": "baseline_snort_validation_seeded_blind.json",
    "blind agent": "agent_snort_validation_seeded_blind.json",
    "blind agent l=10": "agent_snort_validation_seeded_l10.json",
    "enhanced l=10": "agent_snort_validation_seeded_enh10.json",
    "snort-direct l=10": "agent_snort_validation_seeded_snort_direct.json",
}

XGB = {
    "baseline (no mutation)": "baseline_evaluation_seeded_blind.json",
    "blind agent": "agent_evaluation_seeded_blind.json",
    "blind agent l=10": "agent_evaluation_seeded_l10.json",
    "enhanced l=10": "agent_evaluation_seeded_enh10.json",
    "snort-direct l=10": "agent_evaluation_seeded_snort_direct.json",
}


def load(path):
    p = REP / path
    if not p.exists():
        return None
    return json.loads(p.read_text())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--gate", type=float, default=0.55,
                    help="detection-rate success threshold (<= passes)")
    args = ap.parse_args()

    print(f"{'policy':24s} {'Snort det':>10s} {'Snort eva':>10s} "
          f"{'XGB eva':>9s} {'both':>6s} {'n':>4s}")
    print("-" * 70)
    rows = []
    for name, snort_file in DEFAULT.items():
        sn = load(snort_file)
        if sn is None:
            print(f"{name:24s} {'N/A':>10s}")
            continue
        det = sn["overall_detection_rate"]
        n = sn["total_flows"]
        ev = load(XGB[name]) if name in XGB else None
        xgb_ev = ev["xgb_evasion_rate"] if ev else float("nan")

        both = float("nan")
        if ev is not None and "episode_results" in sn:
            verd = {e["episode"]: e["detected"] for e in sn["episode_results"]}
            both = sum(1 for e in ev["episodes"]
                       if e["evaded_xgboost"] and not verd[e["episode_id"]])
        rows.append((name, det, 1 - det, xgb_ev, both, n))
        print(f"{name:24s} {det*100:9.2f}% {ev*100 if ev else float('nan'):9.2f}% "
              f"{xgb_ev*100:8.2f}% {both:6.0f} {n:4d}")

    print()
    target = [r for r in rows if r[0] == "snort-direct l=10"]
    if not target:
        print("[PENDING] snort-direct validation report not found yet")
        return 2
    det = target[0][1]
    print(f"DECISION GATE: snort-direct detection {det*100:.2f}% "
          f"(threshold <= {args.gate*100:.0f}%)")
    if det <= args.gate:
        print("[PASS] evasion goal met -> proceed to Task 6 (document & commit)")
        return 0
    print("[FAIL] evasion goal NOT met -> Task 7 (hyperparameter sweep) required")
    return 1


if __name__ == "__main__":
    sys.exit(main())
