#!/bin/bash
# P4 probe: ONE seed (42) with frequency shaping, then real-Snort eval.
# Reports go to *_v3div_* names; P3 artifacts are NEVER touched.
set -u
cd /root/.hermes/c2-evasion-rl || exit 1
export PYTHONUNBUFFERED=1
CORPUS=snort_validation/reports/hidden_defender_corpus_v3fixed.pkl
LAM="${1:?usage: p4_probe.sh LAM}"
TAG="v3div_l${LAM}_s42"
L=logs/p4_probe.log
echo "[probe] start lam=$LAM $(date -Is)" >> $L
.venv/bin/python -u ai_agent/train_hidden_defender_ppo.py \
  --real-snort --ownership both --corpus $CORPUS \
  --n-flows 22 --max-epochs 40 --seed 42 --diversity-coef "$LAM" \
  --model-out "models/ppo_${TAG}" \
  --out "snort_validation/reports/ppo_${TAG}_train.json" \
  > "logs/train_${TAG}.log" 2>&1
echo "[probe] train exit=$? $(date -Is)" >> $L
.venv/bin/python -u ai_agent/eval_fixed_pipeline.py \
  --model "models/ppo_${TAG}.zip" --split test \
  --ownership both --corpus $CORPUS \
  --out "snort_validation/reports/ppo_${TAG}_test.json" \
  --progress "snort_validation/reports/.eval_${TAG}_progress.jsonl" \
  > "logs/eval_${TAG}.log" 2>&1
echo "[probe] eval exit=$? $(date -Is)" >> $L
echo "[probe] DONE $(date -Is)" >> $L
