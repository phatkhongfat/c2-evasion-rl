#!/usr/bin/env python3
"""
Parse HTTP-only eval results and generate summary table.
"""

import json
import sys
from pathlib import Path
from collections import defaultdict

def parse_eval_results(report_path):
    """Load JSON report and summarize by mechanism."""
    with open(report_path) as f:
        data = json.load(f)
    
    # Group by mechanism
    by_mech = defaultdict(lambda: {"evaded": 0, "total": 0})
    results = data.get("results", [])
    
    for entry in results:
        mech = entry.get("mechanism", "unknown")
        evaded = entry.get("evaded", False)
        by_mech[mech]["total"] += 1
        if evaded:
            by_mech[mech]["evaded"] += 1
    
    return by_mech

def main():
    report_path = Path("/root/.hermes/c2-evasion-rl/snort_validation/reports/eval_http_only_real_snort.json")
    
    if not report_path.exists():
        print(f"Report not found: {report_path}")
        sys.exit(1)
    
    by_mech = parse_eval_results(report_path)
    
    # Print table
    print("\n=== HTTP-Only Evasion Summary (Real Snort) ===\n")
    print(f"{'Mechanism':<20} {'Evaded':<8} {'Total':<8} {'Rate (%)':<10}")
    print("-" * 50)
    
    total_evaded = 0
    total_pairs = 0
    
    for mech in sorted(by_mech.keys()):
        stats = by_mech[mech]
        evaded = stats["evaded"]
        total = stats["total"]
        rate = 100.0 * evaded / total if total > 0 else 0
        print(f"{mech:<20} {evaded:<8} {total:<8} {rate:>6.1f}%")
        
        total_evaded += evaded
        total_pairs += total
    
    print("-" * 50)
    overall_rate = 100.0 * total_evaded / total_pairs if total_pairs > 0 else 0
    print(f"{'TOTAL':<20} {total_evaded:<8} {total_pairs:<8} {overall_rate:>6.1f}%")
    print()

if __name__ == "__main__":
    main()
