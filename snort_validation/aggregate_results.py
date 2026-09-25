#!/usr/bin/env python3
"""Aggregate cross-capture sweep/scale results into a final comparison table."""
import argparse
import glob
import json
import sys
from pathlib import Path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sweep", default="snort_validation/reports/sweep_corrupt_cost.json")
    ap.add_argument("--scale", default="snort_validation/reports/scale_flows.json")
    ap.add_argument("--cross-capture", default="snort_validation/reports/cross_capture_*.json")
    ap.add_argument("--out", default="snort_validation/reports/final_results_table.json")
    args = ap.parse_args()

    results = []

    # Sweep results (all corrupt_cost values, single capture, single flow count)
    if Path(args.sweep).exists():
        with open(args.sweep) as f:
            sweep_data = json.load(f)
        for item in sweep_data.get("sweep_results", []):
            results.append({
                "dataset": "ctu13",
                "capture": sweep_data.get("capture", "botnet-capture-20110819-bot"),
                "n_flows": sweep_data.get("flows", 24),
                "corrupt_cost": item["corrupt_cost"],
                "evasion_pct": item["evasion_pct"],
                "mean_corrupt": item["mean_corrupt"],
                "deterministic_evaded": item.get("deterministic_evaded", -1),
            })

    # Scale results (multiple flow counts, single corrupt_cost)
    if Path(args.scale).exists():
        with open(args.scale) as f:
            scale_data = json.load(f)
        for item in scale_data.get("scale_results", []):
            results.append({
                "dataset": "ctu13",
                "capture": scale_data.get("capture", "botnet-capture-20110819-bot"),
                "n_flows": item["n_flows"],
                "corrupt_cost": scale_data.get("corrupt_cost", 0.6),
                "evasion_pct": item["evasion_pct"],
                "mean_corrupt": item["mean_corrupt"],
                "deterministic_evaded": item.get("deterministic_evaded", -1),
            })

    # Cross-capture results
    for f in sorted(glob.glob(args.cross_capture)):
        if "summary" in f:
            continue
        try:
            with open(f) as fh:
                data = json.load(fh)
            results.append({
                "dataset": "stratosphere",
                "capture": data.get("capture", Path(f).stem),
                "n_flows": data.get("flows", 24),
                "corrupt_cost": data.get("corrupt_cost", 0.6),
                "evasion_pct": data.get("evasion_pct", data.get("deterministic_pct", 0)),
                "mean_corrupt": data.get("mean_corrupt", data.get("deterministic_mean_corrupt", 0)),
                "deterministic_evaded": data.get("deterministic_evaded", -1),
            })
        except Exception as e:
            print(f"[-] {f}: {e}", file=sys.stderr)

    # Write final table
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w") as f:
        json.dump({"results": results, "count": len(results)}, f, indent=2)

    print(f"[+] {len(results)} rows -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
