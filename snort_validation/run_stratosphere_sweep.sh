#!/usr/bin/env bash
# Run the Stratosphere cross-capture / corrupt-cost sweep / flow scale-up plan.
#
# CONFIGURATIONS ARE CHOSEN FROM MEASURED POOL SIZES, not guessed.
# ``snort_validation/capture_pool_sizes.py`` on the labelled MCFP table gives:
#
#   botnet-capture-20110811-neris   471 usable flows   (Neris)
#   botnet-capture-20110810-neris    45 usable flows   (Neris)
#   capture-win13                    29 usable flows   (Neris)
#
# so the scale-up to 200 flows runs on the 471-flow capture, and the other two
# can supply 24 but not 50.  A config that asks for more flows than a capture
# has is SKIPPED by the bandit rather than sampled from a short pool.
#
# CONCURRENCY: the resident service shares iface ``lo`` with every other
# instance, so exactly ONE resident bandit may run at a time.  The phases below
# run sequentially for that reason; do not background them.
#
# Resumable: a phase whose report already exists is skipped unless FORCE=1.
set -uo pipefail
cd /root/.hermes/c2-evasion-rl

PY=/tmp/jev-poc/venv/bin/python
REPORTS=snort_validation/reports
ROUNDS=${ROUNDS:-8}
BATCH=${BATCH:-96}
FORCE=${FORCE:-0}

# capture with the largest measured pool -- the sweep/scale subject
BEST=botnet-capture-20110811-neris
CROSS_CAPTURES="botnet-capture-20110811-neris,botnet-capture-20110810-neris,capture-win13"
# Sweep range: the plan asked for 0.2-1.0, but with the +10 evasion bonus a
# cost of 1.0 is still only ~1.0*5 = 5 against a 10-point bonus, so every cost
# in that range is dominated by "evade at any price" and the sweep comes back
# flat at 100% (measured). The range therefore EXTENDS past the boundary to
# show the frontier; 0.2-1.0 are kept so the plan's requested points are
# present in the table.
SWEEP_COSTS="0.2,0.4,0.6,0.8,1.0,2.0,4.0"
SCALE_FLOWS="24,50,100,200"

phase() {
  local name="$1" out="$2"
  if [ -e "$out" ] && [ "$FORCE" != "1" ]; then
    echo "[=] skip $name (exists: $out)"
    return 1
  fi
  echo "[>] $name"
  return 0
}

echo "=== [1/4] cross-capture validation (24 flows, cost 0.6) ==="
if phase cross "$REPORTS/cross_capture_summary.json"; then
  rm -f "$REPORTS"/cross_capture_*.json
  $PY -u ai_agent/snort_bandit.py --rounds "$ROUNDS" --batch "$BATCH" \
    --corrupt-cost 0.6 --resident --dataset stratosphere \
    --captures "$CROSS_CAPTURES" --flows 24 --out-dir "$REPORTS" || exit 1
  $PY -u snort_validation/aggregate_results.py \
    --cross-capture "$REPORTS/cross_capture_*.json" \
    --out "$REPORTS/cross_capture_summary.json" || exit 1
fi

echo "=== [2/4] corrupt-cost sweep on $BEST (24 flows) ==="
if phase sweep "$REPORTS/sweep_corrupt_cost.json"; then
  $PY -u ai_agent/snort_bandit.py --rounds "$ROUNDS" --batch "$BATCH" \
    --resident --dataset stratosphere --capture "$BEST" --flows 24 \
    --sweep-cost "$SWEEP_COSTS" \
    --out "$REPORTS/sweep_corrupt_cost.json" || exit 1
fi

echo "=== [3/4] flow scale-up $SCALE_FLOWS on $BEST (cost 0.6) ==="
if phase scale "$REPORTS/scale_flows.json"; then
  $PY -u ai_agent/snort_bandit.py --rounds "$ROUNDS" --batch "$BATCH" \
    --corrupt-cost 0.6 --resident --dataset stratosphere --capture "$BEST" \
    --scale-flows "$SCALE_FLOWS" \
    --out "$REPORTS/scale_flows.json" || exit 1
fi

echo "=== [4/4] final results table ==="
$PY -u snort_validation/aggregate_results.py \
  --sweep "$REPORTS/sweep_corrupt_cost.json" "$REPORTS/sweep_corrupt_cost_ctu13.json" \
  --scale "$REPORTS/scale_flows.json" "$REPORTS/scale_flows_ctu13.json" \
  --cross-capture "$REPORTS/cross_capture_*.json" \
  --out "$REPORTS/final_results_table.json" || exit 1

echo
echo "=== final table ==="
$PY - "$REPORTS/final_results_table.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
print(f"{'dataset':<14}{'capture':<34}{'source':<14}{'flows':>6}"
      f"{'cost':>6}{'evasion%':>10}{'mean_corrupt':>14}{'evaded':>8}")
print("-" * 106)
for r in sorted(d["results"], key=lambda x: (x["source"], x["capture"],
                                             x["n_flows"], x["corrupt_cost"])):
    evaded = r.get("deterministic_evaded")
    print(f"{r['dataset']:<14}{r['capture'][:32]:<34}{r['source']:<14}"
          f"{r['n_flows']:>6}{r['corrupt_cost']:>6.1f}"
          f"{r['evasion_pct']:>9.1f}%{r['mean_corrupt']:>14.2f}"
          f"{evaded if evaded is not None else '-':>8}")
print(f"\n{d['count']} rows -> {sys.argv[1]}")
PY
