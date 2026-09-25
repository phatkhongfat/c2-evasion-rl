#!/usr/bin/env python3
"""Aggregate scale-up results (24 → 100 → 300 flows, plus eval on 500)."""
import json
from pathlib import Path

reports_dir = Path("snort_validation/reports")

# Load all scale runs
results = []
for scale in ["24", "100", "300"]:
    path = reports_dir / f"snort_bandit_scale_{scale}.json" if scale != "24" else reports_dir / "snort_bandit_real.json"
    if path.exists():
        with open(path) as f:
            data = json.load(f)
            det_evaded = data.get("deterministic_evaded", 0)
            n_flows = data.get("n_flows", int(scale))
            results.append({
                "scale": f"{n_flows} flows",
                "n_flows": n_flows,
                "deterministic_evaded": det_evaded,
                "evasion_pct": (det_evaded / n_flows) * 100,
                "mean_corrupt": data.get("mean_corrupt", 0),
                "rounds": data.get("rounds", 8)
            })

# Load 500-flow eval
eval_path = reports_dir / "snort_bandit_scale_eval_500.json"
if eval_path.exists():
    with open(eval_path) as f:
        data = json.load(f)
        results.append({
            "scale": "500 flows (eval)",
            "n_flows": 500,
            "deterministic_evaded": data.get("deterministic_evaded", 0),
            "evasion_pct": (data.get("deterministic_evaded", 0) / 500) * 100,
            "mean_corrupt": data.get("mean_corrupt", 0),
            "rounds": 1
        })

# Print table
print(f"{'Scale':<20} {'Evaded':>8} {'Evasion':>9} {'Corrupt':>8} {'Rounds':>6}")
print("─" * 55)
for row in results:
    evaded = f"{row['deterministic_evaded']}/{row['n_flows']}"
    evasion = f"{row['evasion_pct']:.1f}%"
    corrupt = f"{row['mean_corrupt']:.2f}"
    rounds = row['rounds']
    print(f"{row['scale']:<20} {evaded:>8} {evasion:>9} {corrupt:>8} {rounds:>6}")

print(f"\nTotal: {len(results)} runs")
with open(reports_dir / "scale_up_summary.json", "w") as f:
    json.dump({"results": results, "count": len(results)}, f, indent=2)
print(f"Saved: {reports_dir / 'scale_up_summary.json'}")
