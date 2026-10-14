#!/bin/bash
# P3 driver (single runner): train 3 seeds on corpus v3fixed (real-Snort
# teacher, ownership=both), then eval all 3 with real Snort.
#
# Parallelism rule (nproc=4): batch1 = s7+s1337 in parallel, then s42 alone.
# --n-flows = the TRAIN split size (22) so the per-epoch rate / 90% early-stop
# are meaningful (the rate divides by N_FLOWS).
set -u
cd /root/.hermes/c2-evasion-rl || exit 1
CORPUS=snort_validation/reports/hidden_defender_corpus_v3fixed.pkl
L=logs/p3_driver.log
: > "$L"
export PYTHONUNBUFFERED=1

train_seed() {
  s=$1
  .venv/bin/python ai_agent/train_hidden_defender_ppo.py \
    --real-snort --ownership both --corpus "$CORPUS" \
    --n-flows 22 --max-epochs 40 --seed "$s" \
    --model-out "models/ppo_v3_both_s${s}.zip" \
    --out "snort_validation/reports/ppo_v3_train_s${s}.json" \
    > "logs/train_v3_s${s}.log" 2>&1
  echo "[driver] train s$s exit=$? $(date -Is)" >> "$L"
}

eval_seed() {
  s=$1
  .venv/bin/python ai_agent/eval_fixed_pipeline.py \
    --model "models/ppo_v3_both_s${s}.zip" --split test \
    --ownership both --corpus "$CORPUS" \
    --out "snort_validation/reports/ppo_v3_both_test_s${s}.json" \
    --progress "snort_validation/reports/.eval_v3_s${s}_progress.jsonl" \
    > "logs/eval_v3_s${s}.log" 2>&1
  echo "[driver] eval s$s exit=$? $(date -Is)" >> "$L"
}

echo "[driver] batch1 (s7,s1337) start $(date -Is)" >> "$L"
train_seed 7 &   P1=$!
train_seed 1337 & P2=$!
wait $P1 $P2
echo "[driver] batch1 done $(date -Is)" >> "$L"

echo "[driver] batch2 (s42) start $(date -Is)" >> "$L"
train_seed 42
echo "[driver] batch2 done $(date -Is)" >> "$L"

echo "[driver] evals start $(date -Is)" >> "$L"
for s in 7 1337 42; do eval_seed "$s"; done
echo "[driver] ALL_DONE $(date -Is)" >> "$L"
