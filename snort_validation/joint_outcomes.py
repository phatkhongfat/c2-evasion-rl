#!/usr/bin/env python3
"""Joint XGBoost x Snort outcomes for every measured policy (Task 1 evidence)."""
import json
from collections import Counter

REP = "/root/.hermes/c2-evasion-rl/snort_validation/reports"
POLICIES = ["baseline", "random", "agent"]
RUNS = {"blind": "seeded_blind", "l10": "seeded_l10", "enh10": "seeded_enh10"}

for run, suffix in RUNS.items():
    for pol in POLICIES:
        try:
            ev = json.load(open(f"{REP}/{pol}_evaluation_{suffix}.json"))
            sn = json.load(open(f"{REP}/{pol}_snort_validation_{suffix}.json"))
        except FileNotFoundError:
            continue
        verd = {e["episode"]: e["detected"] for e in sn["episode_results"]}
        c = Counter()
        for e in ev["episodes"]:
            sn_ev = not verd[e["episode_id"]]
            xg_ev = bool(e["evaded_xgboost"])
            c[(xg_ev, sn_ev)] += 1
        n = len(ev["episodes"])
        print(f"{run:6s} {pol:9s} xgb_ev={ev['xgb_evasion_rate']:.3f} "
              f"snort_ev={1 - sn['overall_detection_rate']:.3f} | "
              f"both={c[(True, True)]:2d} xgb_only={c[(True, False)]:2d} "
              f"snort_only={c[(False, True)]:2d} neither={c[(False, False)]:2d} "
              f"of {n}")
