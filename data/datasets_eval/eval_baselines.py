#!/usr/bin/env python3
"""
Baseline evaluation across multiple dataset subsets and rulesets.
Goal: Find combination with 20-40% baseline evasion for RL training.
"""
import sys
from pathlib import Path
repo = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(repo / "ai_agent"))
sys.path.insert(0, str(repo / "snort_validation"))

from pool_loader import load_malicious_pool
from snort_query_service import replica_snort_verdict
from aggressive_snort_replica import aggressive_snort_verdict
import numpy as np

pool = load_malicious_pool()
print(f"[+] Loaded {len(pool)} CTU-13 malicious flows\n")

# Define subsets
subsets = {
    "full_pool": pool,
    "tcp_only": [f for f in pool if f.get("proto", "").lower() == "tcp"],
    "udp_only": [f for f in pool if f.get("proto", "").lower() == "udp"],
    "medium_flows": [f for f in pool if 5 <= f.get("tot_pkts", 0) < 20],
    "long_flows": [f for f in pool if f.get("tot_pkts", 0) >= 20],
    "large_bytes": [f for f in pool if f.get("tot_bytes", 0) >= 5000],
}

# Define rulesets
rulesets = {
    "original_6": replica_snort_verdict,
    "aggressive_8": aggressive_snort_verdict,
}

print("=" * 80)
print("BASELINE EVALUATION")
print("=" * 80)
print()

results = []
for subset_name, subset in subsets.items():
    if len(subset) == 0:
        continue
    
    print(f"--- {subset_name} (n={len(subset)}) ---")
    
    for ruleset_name, verdict_fn in rulesets.items():
        detected = sum(1 for f in subset if verdict_fn(f))
        evasion_rate = 100 * (1 - detected / len(subset))
        
        # Compute packet stats
        pkts = [f.get("tot_pkts", 0) for f in subset]
        
        status = ""
        if 20 <= evasion_rate <= 40:
            status = " ✓ GOOD"
        elif 40 < evasion_rate <= 60:
            status = " → OK"
        
        print(f"  {ruleset_name:15s}: {evasion_rate:5.1f}% evasion (detect {detected}/{len(subset)}){status}")
        print(f"                      pkts: med={np.median(pkts):.0f} p95={np.percentile(pkts, 95):.0f}")
        
        results.append({
            "subset": subset_name,
            "ruleset": ruleset_name,
            "n": len(subset),
            "evasion": evasion_rate,
            "detected": detected,
        })
    
    print()

print("=" * 80)
print("RECOMMENDATIONS")
print("=" * 80)
print()

# Find best combinations (20-40% evasion)
good = [r for r in results if 20 <= r["evasion"] <= 40]
ok = [r for r in results if 40 < r["evasion"] <= 60]

if good:
    print("Best baseline (20-40% evasion):")
    for r in sorted(good, key=lambda x: abs(x["evasion"] - 30)):
        print(f"  {r['subset']:15s} + {r['ruleset']:15s}: {r['evasion']:.1f}% evasion (n={r['n']})")
elif ok:
    print("Acceptable baseline (40-60% evasion):")
    for r in sorted(ok, key=lambda x: x["evasion"]):
        print(f"  {r['subset']:15s} + {r['ruleset']:15s}: {r['evasion']:.1f}% evasion (n={r['n']})")
else:
    print("No good combinations found. Need:")
    print("  - More aggressive rules, OR")
    print("  - Different dataset with realistic attacks")

print()
print("Next steps:")
print("  1. If good combination exists: train agent on that subset+ruleset")
print("  2. Otherwise: add catch-all rules or fetch CICIDS2017/UNSW-NB15")
