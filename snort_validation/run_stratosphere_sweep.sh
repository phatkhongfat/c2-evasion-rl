#!/usr/bin/env bash
# Run the full Stratosphere sweep plan end to end, in order, with checkpoints.
#
# Phases write to snort_validation/reports/ and each phase is resumable: a
# phase whose report exists is skipped (delete the report or set FORCE=1 to
# re-run).  The whole sweep is real Snort time, so losing it to a typo in the
# last phase is not acceptable.
#
# CONCURRENCY: the resident Snort service inspects interface ``lo``, so two
# resident runs at once corrupt each other's verdicts (see
# snort_resident_service.py).  Every phase here is sequential for that reason.
#
# Usage:
#   bash snort_validation/run_stratosphere_sweep.sh
#   ROUNDS=2 FORCE=1 bash snort_validation/run_stratosphere_sweep.sh
set -euo pipefail

REPO=/root/.hermes/c2-evasion-rl
PY=/tmp/jev-poc/venv/bin/python
R="$REPO/snort_validation/reports"
ROUNDS=${ROUNDS:-8}
FLOWS=${FLOWS:-24}
BATCH=${BATCH:-96}
cd "$REPO"

# ---- Phase 0: dataset registry + MCFP Snort labels -------------------------
if [ ! -f data/stratosphere_captures.json ] || [ "${FORCE:-0}" = "1" ]; then
  echo "[0a] registering Stratosphere captures (measures packets/flows)"
  $PY snort_validation/register_stratosphere_captures.py \
    --out data/stratosphere_captures.json
else
  echo "[0a] registry exists, skipping"
fi

if [ ! -f data/mcfp_snort_labeled.parquet ] || [ "${FORCE:-0}" = "1" ]; then
  echo "[0b] labelling MCFP captures with real Snort (ET Open C2)"
  # Parallel path: one process per capture, 4 at a time, then merge.  A single
  # sequential run is single-threaded scapy and takes ~15 min for the whole
  # MCFP set; the per-capture split is the same work on 4 cores.
  mkdir -p data/mcfp_parts
  printf '%s\n' $(ls -d data/stratosphere/mcfp/*/) | while read -r d; do
    cap=$(basename "$d"); pcap=$(ls "$d"/*.pcap 2>/dev/null | head -1)
    [ -z "$pcap" ] && continue
    echo "$cap"
  done | xargs -P 4 -I{} $PY snort_validation/build_mcfp_snort_dataset.py \
    --root data/stratosphere/mcfp --captures {} --min-alerted 24 \
    --cache data/stratosphere/mcfp_labels \
    --out "data/mcfp_parts/{}.parquet" >/dev/null 2>&1 || true
  $PY snort_validation/build_mcfp_snort_dataset.py --from-parts data/mcfp_parts \
    --min-alerted "$FLOWS" --out data/mcfp_snort_labeled.parquet
else
  echo "[0b] MCFP label table exists, skipping"
fi

# Pick the captures that actually have a usable pool.  This is measured from
# the labelled table, not assumed: the C2 ruleset fires on only a few MCFP
# captures, so a hand-written capture list would mostly load zero flows.
mapfile -t CAPS < <($PY - "$FLOWS" <<'PY'
import sys, pandas as pd
need = int(sys.argv[1])
df = pd.read_parquet("data/mcfp_snort_labeled.parquet")
g = (df[df.snort_alert == 1].query("tot_pkts >= 4")
       .groupby("capture").size().sort_values(ascending=False))
for cap, n in g[g >= need].items():
    print(cap)
PY
)
if [ "${#CAPS[@]}" -eq 0 ]; then
  echo "[-] no capture has $FLOWS Snort-alerted flows; lower FLOWS" >&2
  exit 1
fi
BEST="${CAPS[0]}"          # most alerted flows -> the only one scale-up can use
echo "[*] usable captures (>= $FLOWS alerted flows): ${CAPS[*]}"
echo "[*] best capture (largest pool): $BEST"

# ---- Phase 3: cross-capture validation -------------------------------------
if [ ! -f "$R/cross_capture_summary.json" ] || [ "${FORCE:-0}" = "1" ]; then
  echo "[3] cross-capture validation (${FLOWS} flows each)"
  $PY ai_agent/snort_bandit.py --flows "$FLOWS" --rounds "$ROUNDS" \
    --batch "$BATCH" --corrupt-cost 0.6 --resident --dataset stratosphere \
    --captures "$(IFS=,; echo "${CAPS[*]}")" --out-dir "$R"
  $PY snort_validation/aggregate_results.py \
    --cross-capture "$R/cross_capture_*.json" \
    --out "$R/final_results_table_cross.json" \
    --summary-out "$R/cross_capture_summary.json"
else
  echo "[3] cross-capture done, skipping"
fi

# ---- Phase 1: corrupt-cost sweep on the best capture -----------------------
if [ ! -f "$R/sweep_corrupt_cost.json" ] || [ "${FORCE:-0}" = "1" ]; then
  echo "[1] corrupt-cost sweep on $BEST"
  $PY ai_agent/snort_bandit.py --flows "$FLOWS" --rounds "$ROUNDS" \
    --batch "$BATCH" --resident --dataset stratosphere --capture "$BEST" \
    --sweep-cost 0.1,0.2,0.3,0.4,0.5,0.6,0.8,1.0 \
    --out "$R/sweep_corrupt_cost.json"
else
  echo "[1] sweep done, skipping"
fi

# ---- Phase 2: flow scale-up ------------------------------------------------
if [ ! -f "$R/scale_flows.json" ] || [ "${FORCE:-0}" = "1" ]; then
  echo "[2] flow scale-up 24 -> 50 -> 100 -> 200 on $BEST"
  $PY ai_agent/snort_bandit.py --rounds "$ROUNDS" --batch "$BATCH" \
    --resident --dataset stratosphere --capture "$BEST" --corrupt-cost 0.6 \
    --scale-flows 24,50,100,200 --out "$R/scale_flows.json"
else
  echo "[2] scale done, skipping"
fi

# ---- Phase 5: final table --------------------------------------------------
echo "[5] aggregating"
$PY snort_validation/aggregate_results.py \
  --sweep "$R/sweep_corrupt_cost.json" \
  --scale "$R/scale_flows.json" \
  --cross-capture "$R/cross_capture_*.json" \
  --out "$R/final_results_table.json" \
  --summary-out "$R/cross_capture_summary.json"

echo "[+] done: $R/final_results_table.json"
