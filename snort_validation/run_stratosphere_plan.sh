#!/usr/bin/env bash
# Execute the full Stratosphere sweep/scale/cross-capture plan.
# Tasks:
#   1. Code audit (ponytail)
#   2. Download Stratosphere captures  
#   3. Validate downloads
#   4. Cross-capture validation (24 flows, 8 rounds)
#   5. Sweep corrupt_cost (single best capture)
#   6. Scale flows (24 -> 50 -> 100 -> 200)
#   7. Aggregate results into table
#   8. Commit

set -euo pipefail
cd /root/.hermes/c2-evasion-rl

echo "[1/8] Code audit (syntax + lint)"
/tmp/jev-poc/venv/bin/python -m py_compile \
  snort_validation/sweep_corrupt_cost.py \
  snort_validation/scale_flows.py \
  snort_validation/cross_capture_validation.py \
  snort_validation/aggregate_results.py
echo "[+] syntax OK"

echo ""
echo "[2/8] Stratosphere downloads (background process should complete)"
ps aux | grep -F 'fetch_stratosphere_captures.sh' | grep -v grep || echo "    (not yet started or already done)"

echo ""
echo "[3/8] Validating downloads..."
for pcap in \
  "data/stratosphere/CTU-13-Dataset/1/botnet-capture-20110810-neris.pcap" \
  "data/stratosphere/CTU-13-Dataset/12/botnet-capture-20110819-bot.pcap"; do
  if [ -f "$pcap" ]; then
    sz=$(du -b "$pcap" | cut -f1)
    echo "    OK: $pcap ($sz bytes)"
  else
    echo "    MISSING: $pcap"
  fi
done

echo ""
echo "[4/8] Cross-capture validation (24 flows, 8 rounds, 4 CTU-13 captures)"
timeout 3600 /tmp/jev-poc/venv/bin/python snort_validation/cross_capture_validation.py \
  --flows 24 --rounds 8 --batch 96 \
  --captures \
    botnet-capture-20110810-neris \
    botnet-capture-20110815-rbot-dos \
    botnet-capture-20110816-qvod \
    botnet-capture-20110819-bot \
  --out snort_validation/reports/cross_capture.json \
  2>&1 | tee /tmp/cross_capture.log
echo "[+] cross-capture done"

echo ""
echo "[5/8] Corrupt-cost sweep (best capture)"
timeout 3600 /tmp/jev-poc/venv/bin/python snort_validation/sweep_corrupt_cost.py \
  --capture botnet-capture-20110819-bot \
  --flows 24 --rounds 8 --batch 96 \
  --costs 0.1 0.2 0.3 0.4 0.5 0.6 0.7 0.8 \
  --out snort_validation/reports/sweep_corrupt_cost.json \
  2>&1 | tee /tmp/sweep.log
echo "[+] corrupt-cost sweep done"

echo ""
echo "[6/8] Flow scale-up (24 -> 50 -> 100 -> 200)"
timeout 3600 /tmp/jev-poc/venv/bin/python snort_validation/scale_flows.py \
  --capture botnet-capture-20110819-bot \
  --corrupt-cost 0.6 --rounds 8 --batch 96 \
  --flow-counts 24 50 100 200 \
  --out snort_validation/reports/scale_flows.json \
  2>&1 | tee /tmp/scale.log
echo "[+] flow scale-up done"

echo ""
echo "[7/8] Aggregate results"
timeout 120 /tmp/jev-poc/venv/bin/python snort_validation/aggregate_results.py \
  --sweep snort_validation/reports/sweep_corrupt_cost.json \
  --scale snort_validation/reports/scale_flows.json \
  --cross-capture "snort_validation/reports/cross_capture_*.json" \
  --out snort_validation/reports/final_results_table.json
echo "[+] aggregation done"

echo ""
echo "[8/8] Final table"
if [ -f snort_validation/reports/final_results_table.json ]; then
  /tmp/jev-poc/venv/bin/python - snort_validation/reports/final_results_table.json <<'PY'
import json, sys
with open(sys.argv[1]) as f:
    data = json.load(f)
print(f"\n{data['count']} rows total:\n")
print("dataset        capture                           n_flows  corrupt_cost  evasion_%  mean_corrupt")
print("-" * 105)
for r in sorted(data['results'], key=lambda x: (x['dataset'], x['capture'], x['n_flows'], x['corrupt_cost'])):
    cap = r['capture'][:30]
    print(f"{r['dataset']:<14} {cap:<30} {r['n_flows']:>7} {r['corrupt_cost']:>12.1f}  {r['evasion_pct']:>9.1f}%  {r['mean_corrupt']:>12.2f}")
PY
fi

echo ""
echo "[+] Plan complete!"
