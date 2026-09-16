# Makefile for C2 Evasion RL

.PHONY: help install check train eval tensorboard clean

help:
	@echo "C2 Evasion RL – Available targets:"
	@echo "  make install       Install dependencies (conda/pip)"
	@echo "  make check         Validate environment setup"
	@echo "  make train         Train PPO agent (50k timesteps)"
	@echo "  make eval          Evaluate trained agent (80 samples)"
	@echo "  make tensorboard   Launch tensorboard (port 6006)"
	@echo "  make clean         Remove logs, models, __pycache__"

install:
	@echo "[*] Installing conda environment..."
	conda env create -f environment.yml -y

install-pip:
	@echo "[*] Installing pip dependencies..."
	pip install -r requirements.txt

check:
	@echo "[*] Validating environment..."
	python3 setup_check.py

train: check
	@echo "[*] Starting PPO training..."
	cd ai_agent && python3 train_agent.py

eval: check
	@echo "[*] Evaluating trained agent..."
	cd ai_agent && python3 evaluate.py

tensorboard:
	@echo "[*] Launching TensorBoard (http://localhost:6006)..."
	tensorboard --logdir=ai_agent/c2_ppo_tensorboard/ --port=6006

clean:
	@echo "[*] Cleaning up..."
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	rm -rf ai_agent/logs/* 2>/dev/null || true
	rm -rf .pytest_cache/ 2>/dev/null || true
	@echo "[+] Done"

.DEFAULT_GOAL := help
