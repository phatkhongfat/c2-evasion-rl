#!/bin/bash
# P3 launcher (single runner). Trains the given seed on corpus v3fixed with a
# real-Snort teacher and ownership=both. --n-flows is set to the TRAIN split
# size (22) so the per-epoch rate and the 90% early-stop are meaningful (the
# rate divides by N_FLOWS).
set -u
cd /root/.hermes/c2-evasion-rl || exit 1
CORPUS=snort_validation/reports/hidden_defender_corpus_v3fixed.pkl
s=$1
export PYTHONUNBUFFERED=1
.venv/bin/python ai_agent/train_hidden_defender_ppo.py \
  --real-snort --ownership both --corpus "$CORPUS" \
  --n-flows 22 --max-epochs 40 --seed "$s" \
  --model-out "models/ppo_v3_both_s${s}.zip" \
  --out "snort_validation/reports/ppo_v3_train_s${s}.json" \
  > "logs/train_v3_s${s}.log" 2>&1
echo "[launch] train s$s exit=$? $(date -Is)" >> logs/p3_launch.log
