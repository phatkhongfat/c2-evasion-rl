# C2 Evasion RL – Reinforcement Learning for Botnet C2 Traffic Evasion

A reinforcement learning framework that trains an agent to mutate botnet C2 (Command & Control) traffic to evade detection by an IDS (Intrusion Detection System) using PPO (Proximal Policy Optimization).

## Overview

This project combines:
- **Red Team**: PPO agent trained to mutate malicious network flows
- **Blue Team**: Surrogate IDS model (scikit-learn) trained to detect botnet traffic
- **Data**: CTU-13 botnet dataset (13 real botnet capture scenarios)

The agent learns to apply evasion tactics (jitter, padding, protocol hopping, state mutation) while minimizing detection confidence—demonstrating adversarial robustness of security systems.

## Environment Setup

### Option 1: Conda (Recommended)

```bash
conda env create -f environment.yml
conda activate rl_c2_evasion
```

### Option 2: Pip + venv

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Verify Installation

```bash
python3 -c "import gymnasium, stable_baselines3, torch, scapy; print('✓ All dependencies loaded')"
```

## Project Structure

```
c2-evasion-rl/
├── ai_agent/                          # RL training & evaluation
│   ├── train_agent.py                 # PPO agent training script
│   ├── evaluate.py                    # Test trained agent on samples
│   ├── c2_evasion_env.py              # Gymnasium environment (action/reward logic)
│   ├── config.py                      # Hyperparameters & paths
│   ├── evasion_metrics_callback.py    # Custom callback for logging
│   ├── check_importance.py            # Feature importance analysis
│   └── logs/                          # Training logs & tensorboard data
│
├── red_team/                          # C2 mock infrastructure
│   ├── mock_server.py                 # Flask C2 server (beacon listener)
│   ├── mock_client.py                 # Simulated bot client
│   ├── interceptor.py                 # Network flow interception
│   └── live_interceptor.py            # Real-time traffic capture
│
├── blue_team/                         # IDS & surrogate model training
│   ├── train_ids.ipynb                # Train IDS classifier (XGBoost/RF)
│   └── train_surrogate.ipynb          # Train surrogate judge model
│
├── data/                              # Datasets
│   ├── malicious_ctu13.parquet        # Aggregated CTU-13 botnet flows
│   ├── archive/                       # Individual CTU-13 scenarios (1-13)
│   ├── surrogate_ids_ctu13.pkl        # Trained surrogate model (scikit-learn)
│   ├── label_encoder_proto.pkl        # Protocol encoder
│   └── label_encoder_state.pkl        # State encoder
│
├── models/                            # Trained agents (created at runtime)
│   └── ppo_c2_evasion_agent.zip       # Trained PPO policy
│
├── environment.yml                    # Conda environment spec
├── requirements.txt                   # Pip dependencies
└── README.md                          # This file
```

## Quick Start

### 1. Prepare Training Data & Encoders

Before training, generate the surrogate IDS model and label encoders:

```bash
cd blue_team
jupyter notebook train_surrogate.ipynb  # Follow cells to generate pickle files
# Output: data/surrogate_ids_ctu13.pkl, data/label_encoder_*.pkl
cd ..
```

Or use the setup script:

```bash
python3 setup_blue_team.py  # Automates surrogate model generation
```

### 2. Train the PPO Agent

```bash
cd ai_agent
python3 train_agent.py
```

**Expected output:**
- Training logs to `c2_ppo_tensorboard/` (view with TensorBoard)
- Trained model saved to `../models/ppo_c2_evasion_agent.zip`
- Training takes ~5-10 min (50k timesteps) on CPU

Monitor training in real-time:

```bash
tensorboard --logdir=ai_agent/c2_ppo_tensorboard/
# Open http://localhost:6006 in browser
```

### 3. Evaluate the Trained Agent

```bash
cd ai_agent
python3 evaluate.py
```

**Output:** Evasion success rate on 80 random test samples, with tactics breakdown (jitter, padding, protocol hops).

## Configuration

Edit `ai_agent/config.py` to adjust:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `PPO_LEARNING_RATE` | 1e-4 | Learning rate for PPO optimizer |
| `PPO_N_STEPS` | 1024 | Rollout buffer size per update |
| `PPO_BATCH_SIZE` | 32 | Mini-batch size |
| `PPO_GAMMA` | 0.99 | Discount factor (future reward weight) |
| `TOTAL_TIMESTEPS` | 50,000 | Total training steps |
| `REWARD_EVASION` | 50.0 | Reward for successful evasion |
| `REWARD_DETECTION` | -2.0 | Penalty for detection |
| `MAX_STEPS` | 10 | Max evasion mutations per episode |

## Action Space

The agent selects 4 continuous actions per step (normalized to [-1, 1]):

1. **Jitter** (`±5 seconds`) – Shift flow duration
2. **Padding** (`±500 bytes`) – Add/remove payload bytes
3. **Protocol Hop** (binary) – Toggle between TCP/UDP
4. **State Hop** (binary) – Toggle between CON/INT connection states

## Observation Space

6-dimensional flow features (normalized to [-1, 1]):

- `dur` – Flow duration (seconds)
- `tot_pkts` – Total packets
- `tot_bytes` – Total bytes
- `src_bytes` – Source-to-dest bytes
- `proto` – Protocol (encoded: TCP=0, UDP=1)
- `state` – Connection state (encoded: CON=0, INT=1)

## Reward Function

```
reward = R_evasion × (evaded) 
       + R_detection × (not evaded)
       + confidence_bonus × (reduction in malicious confidence)
       - mutation_cost × (magnitude of mutations)
       - step_penalty × (encourage rapid evasion)
```

**Goal:** Agent learns to minimize mutations while maximizing evasion.

## Known Issues & Improvements

### Current Limitations

1. **Missing trained models** – `.pkl` files must be generated from `blue_team/` notebooks
   - **Fix:** Run `blue_team/train_surrogate.ipynb` first or provide pre-trained weights

2. **Hardcoded paths in evaluate.py** – Line 10 uses `~/Projects/...`
   - **Fix:** Use relative paths with `os.path.dirname(os.path.abspath(__file__))`

3. **No `models/` directory** – Agent can't save trained weights
   - **Fix:** Add `.gitkeep` to `models/` folder

4. **No CI/testing** – No automated checks for environment setup
   - **Fix:** Add `test_setup.py` or pytest fixtures

5. **Missing requirements.txt** – Pip users must manually manage versions
   - **Fix:** Auto-generated from `environment.yml`

### Suggested Enhancements

- [ ] Add `Makefile` with `make train`, `make eval`, `make tensorboard` targets
- [ ] Docker support for reproducible environments
- [ ] Wandb integration for experiment tracking
- [ ] Multi-agent training (compete: evasion vs. detection)
- [ ] Real network traffic capture (replace mock flows)
- [ ] Web UI dashboard for monitoring live evasion attempts
- [ ] Adversarial retraining loop (IDS defends → Agent adapts)

## Troubleshooting

### Import Error: `No module named 'gymnasium'`

```bash
# Verify conda/venv is activated
conda activate rl_c2_evasion
# Or for venv:
source venv/bin/activate

# Reinstall if needed
pip install gymnasium==1.3.0
```

### File Not Found: `surrogate_ids_ctu13.pkl`

```bash
cd blue_team
jupyter notebook train_surrogate.ipynb
# Run all cells to generate encoders + surrogate model
```

### Training stuck / very slow

- Check CPU/RAM usage: `top` or `htop`
- Reduce `PPO_N_STEPS` or `TOTAL_TIMESTEPS` in `config.py` for faster iteration
- Use GPU if available (modify `device="cpu"` to `device="cuda"` in `train_agent.py`)

### TensorBoard won't connect

```bash
# Kill existing tensorboard process
pkill -f tensorboard

# Restart with explicit port
tensorboard --logdir=ai_agent/c2_ppo_tensorboard/ --port=6006
```

## Dependencies

### Core ML Stack

- `gymnasium==1.3.0` – RL environment framework
- `stable-baselines3==2.9.0` – PPO, DQN, A2C implementations
- `scikit-learn` – Surrogate IDS classifier
- `pytorch` (CPU) – Neural network backbone
- `tensorboard==2.21.0` – Training visualization

### Data & Utils

- `pandas`, `numpy` – Data manipulation
- `pyarrow` – Parquet file I/O
- `scapy==2.7.0` – Network packet crafting
- `flask==3.1.3` – C2 server mock
- `opencv-python==5.0.0.93` – Image processing (optional)

See `environment.yml` for full dependency list and versions.

## Dataset: CTU-13

**Source:** [CTU-13 Botnet Captures](https://www.stratosphereips.org/datasets-ctu13)

**Composition:**
- 13 scenarios (1 botnet per scenario: Neris, Rbot, Virut, Menti, Sogou, Murlo, NsisAy)
- ~2.8 GB total (binetflow format, pre-converted to Parquet)
- Features: `dur`, `tot_pkts`, `tot_bytes`, `src_bytes`, `proto`, `state`
- Labels: Botnet vs. Normal (benign) traffic

**License:** Public / Research use

## Citation

If you use this project in research, cite:

```bibtex
@misc{c2evasion_rl,
  title={C2 Evasion RL: Adversarial Reinforcement Learning for Botnet Traffic Evasion},
  author={Your Name},
  year={2024},
  howpublished={\url{https://github.com/phatkhongfat/c2-evasion-rl}}
}
```

## References

- [Stable Baselines3 Docs](https://stable-baselines3.readthedocs.io/)
- [Gymnasium Documentation](https://gymnasium.farama.org/)
- [CTU-13 Dataset Paper](https://www.stratosphereips.org/datasets-ctu13)
- [Adversarial Examples in IDS](https://arxiv.org/abs/1810.00912)

## License

MIT License – See LICENSE file for details.

## Contact

**Project Owner:** Lê Hoàng Phát  
**Email:** lehoangphat1511@gmail.com  
**GitHub:** [phatkhongfat](https://github.com/phatkhongfat)

---

**Last Updated:** September 2024  
**Status:** Active Development
