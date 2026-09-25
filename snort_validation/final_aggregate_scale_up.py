#!/usr/bin/env python3
"""Final aggregation: all scale-up runs (24, 100, 300, 500 flows)."""
import json
from pathlib import Path

reports_dir = Path("snort_validation/reports")

scales = [
    ("24 flows (baseline)", "snort_bandit_real.json"),
    ("100 flows", "snort_bandit_scale_100.json"),
    ("300 flows", "snort_bandit_scale_300.json"),
    ("500 flows", "snort_bandit_scale_500.json"),
]

results = []
for label, fname in scales:
    path = reports_dir / fname
    if path.exists():
        with open(path) as f:
            data = json.load(f)
            n_flows = data.get("n_flows", int(label.split()[0]))
            det_evaded = data.get("deterministic_evaded", 0)
            results.append({
                "scale": label,
                "n_flows": n_flows,
                "deterministic_evaded": det_evaded,
                "evasion_pct": (det_evaded / n_flows) * 100,
                "mean_corrupt": data.get("mean_corrupt", 0),
                "rounds": data.get("rounds", 8)
            })
    else:
        print(f"[!] missing {fname}")

# Print table
print(f"\n{'Scale':<20} {'Evaded':>10} {'Evasion':>10} {'Corrupt':>10} {'Rounds':>6}")
print("─" * 60)
for row in results:
    evaded = f"{row['deterministic_evaded']}/{row['n_flows']}"
    evasion = f"{row['evasion_pct']:.1f}%"
    corrupt = f"{row['mean_corrupt']:.2f}"
    rounds = row['rounds']
    print(f"{row['scale']:<20} {evaded:>10} {evasion:>10} {corrupt:>10} {rounds:>6}")

# Save summary
with open(reports_dir / "final_scale_up_summary.json", "w") as f:
    json.dump({"results": results, "count": len(results), "timestamp": "2026-09-25"}, f, indent=2)
print(f"\n[+] Saved: {reports_dir / 'final_scale_up_summary.json'}")
