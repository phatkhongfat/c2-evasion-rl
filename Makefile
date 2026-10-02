# Makefile for C2 Evasion RL
#
# Run from the repo root with the repo-local .venv. That .venv is the only
# interpreter here with gymnasium + stable-baselines3 + scapy; the system
# `python3` has none of them, and running from a subdirectory breaks the
# repo-module imports.
#
# ponytail: only the hidden-defender (current) system's entry points are wired
# up. Retired generations (flow-level, packet-level, directional, snort-aware,
# bandit sweeps, feasibility/frontier solvers) were deleted in the one-version
# cleanup -- everything remains recoverable from git history.

PY := .venv/bin/python
ENV := PYTHONPATH=ai_agent:snort_validation

.PHONY: help install train train-real eval control audit verify test clean

help:
	@echo "C2 Evasion RL (hidden-defender system) -- targets:"
	@echo "  make install     Create the conda env from environment.yml"
	@echo "  make train       Train MaskablePPO (fast surrogate, ~5 min)"
	@echo "  make train-real  Train scored by real Snort (~2 h)"
	@echo "  make eval        Headline: evaluate held-out flows with real Snort (~3 min)"
	@echo "  make control     Negative control: unmutated traffic must alert (~3 min)"
	@echo "  make audit       Surrogate vs real Snort + 14-mechanism sweep (~40 min)"
	@echo "  make verify      Cross-check every report number (instant)"
	@echo "  make test        Run the pytest suite (~8 min)"
	@echo "  make clean       Remove __pycache__, .pyc, pytest cache"

install:
	@echo "[*] Installing conda environment..."
	conda env create -f environment.yml -y

train:
	$(ENV) $(PY) ai_agent/train_hidden_defender_ppo.py

train-real:
	$(ENV) $(PY) ai_agent/train_hidden_defender_ppo.py --real-snort

eval:
	$(ENV) $(PY) ai_agent/eval_masked_ppo_test.py --real-snort

control:
	$(ENV) $(PY) controls/control_noop_real_snort.py

audit:
	$(ENV) $(PY) controls/surrogate_vs_real_snort.py
	$(ENV) $(PY) controls/surrogate_sweep_14mech.py

verify:
	$(PY) controls/verify_report_claims.py

test:
	@echo "[*] Running tests..."
	$(PY) -m pytest tests/ -q

clean:
	@echo "[*] Cleaning up..."
	find . -type d -name __pycache__ -not -path "./.venv/*" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -not -path "./.venv/*" -delete
	rm -rf .pytest_cache/ 2>/dev/null || true
	@echo "[+] Done"

.DEFAULT_GOAL := help