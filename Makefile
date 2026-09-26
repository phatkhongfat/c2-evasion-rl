# Makefile for C2 Evasion RL
#
# Run from the repo root with the repo-local .venv. That .venv is the only
# interpreter here with gymnasium + stable-baselines3 + scapy; the system
# `python3` has none of them, and running from a subdirectory breaks the
# repo-module imports.
#
# ponytail: only the packet-level entry points are wired up. The old flow-level
# targets (train_agent.py / evaluate.py / c2_ppo_tensorboard) are gone because
# that approach is retired -- see README "Project History" -- and `make check`
# is gone because setup_check.py predates the packet-level work. The live
# scripts take no CLI flags; they write fixed report paths. Add a target when
# there is a command worth running twice.

PY := .venv/bin/python

.PHONY: help install feasibility frontier variance test clean

help:
	@echo "C2 Evasion RL -- available targets:"
	@echo "  make install       Create the conda env from environment.yml"
	@echo "  make feasibility   Per-capture feasibility gate (label_feasibility.py)"
	@echo "  make frontier      Exact corruption solver (frontier_exact.py)"
	@echo "  make variance      Harness run-to-run spread (harness_variance.py)"
	@echo "  make test          Run the pytest suite"
	@echo "  make clean         Remove __pycache__, .pyc, pytest cache"

install:
	@echo "[*] Installing conda environment..."
	conda env create -f environment.yml -y

feasibility:
	@echo "[*] Feasibility gate..."
	$(PY) snort_validation/label_feasibility.py

frontier:
	@echo "[*] Exact frontier solver..."
	$(PY) snort_validation/frontier_exact.py

variance:
	@echo "[*] Harness variance..."
	$(PY) snort_validation/harness_variance.py

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
