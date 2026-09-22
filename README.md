# C2 Evasion RL – Học Tăng Cường cho Né Tránh Phát Hiện Lưu Lượng C2 Botnet

Khung học tăng cường (RL) huấn luyện một tác tử để biến đổi lưu lượng C2 (Command & Control) của botnet nhằm tránh phát hiện bởi IDS (Intrusion Detection System) sử dụng PPO (Proximal Policy Optimization).

## Tổng Quan

Dự án này kết hợp:
- **Red Team**: Tác tử RL nâng cao (PPO/SAC) huấn luyện biến đổi lưu lượng mạng độc hại
- **Blue Team**: Surrogate IDS hiệu suất cao (XGBoost/LightGBM) huấn luyện phát hiện lưu lượng botnet
- **Phân Tích**: Explainability SHAP + theo dõi tầm quan trọng của tính năng
- **Giám Sát**: Theo dõi thí nghiệm Weights & Biases + sổ đăng ký mô hình MLflow
- **Dữ Liệu**: Tập dữ liệu botnet CTU-13 (13 kịch bản botnet thực tế)

Tác tử học áp dụng các chiến thuật né tránh (jitter, padding, protocol hopping, state mutation) trong khi giảm thiểu độ tin cậy phát hiện—chứng minh tính mạnh mẽ đối kháng của các hệ thống bảo mật.

## Quy Trình Công Việc (Vietnamese Workflow)

### Bước 1: Cài Đặt Môi Trường

```bash
# Cách 1: Conda (Recommended)
conda env create -f environment.yml
conda activate rl_c2_evasion

# Cách 2: Pip + venv
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt  # Nếu cần
```

### Bước 2: Chuẩn Bị Dữ Liệu & Mô Hình Surrogate

```bash
# Chạy notebook huấn luyện surrogate IDS
cd blue_team
jupyter notebook train_surrogate.ipynb
# Output: data/surrogate_ids_ctu13.pkl, data/label_encoder_*.pkl
cd ..
```

### Bước 3: Kiểm Tra Môi Trường

```bash
python3 setup_check.py
# Hoặc sử dụng Makefile:
make check
```

### Bước 4: Huấn Luyện Tác Tử PPO

```bash
make train
# Hoặc thủ công:
cd ai_agent
python3 train_agent.py
```

Theo dõi quá trình huấn luyện:
```bash
make tensorboard
# Truy cập http://localhost:6006
```

### Bước 5: Đánh Giá Tác Tử

```bash
make eval
# Hoặc:
cd ai_agent
python3 evaluate.py
```

### Bước 6: Dọn Dẹp

```bash
make clean
```

---

# C2 Evasion RL – Reinforcement Learning for Botnet C2 Traffic Evasion

A reinforcement learning framework that trains an agent to mutate botnet C2 (Command & Control) traffic to evade detection by an IDS (Intrusion Detection System) using PPO (Proximal Policy Optimization).

## Overview

This project combines:
- **Red Team**: Advanced RL agent (PPO/SAC) trained to mutate malicious network flows
- **Blue Team**: High-performance surrogate IDS (XGBoost/LightGBM) trained to detect botnet traffic
- **Analysis**: SHAP explainability + feature importance tracking
- **Monitoring**: Weights & Biases experiment tracking + MLflow model registry
- **Data**: CTU-13 botnet dataset (13 real botnet capture scenarios)

The agent learns to apply evasion tactics (jitter, padding, protocol hopping, state mutation) while minimizing detection confidence—demonstrating adversarial robustness of security systems.

### Key Improvements Over Basic RL
- **Better algorithms**: SAC (Soft Actor-Critic) for more efficient learning vs PPO
- **Stronger IDS surrogate**: XGBoost/LightGBM replace scikit-learn for better adversarial robustness
- **Explainability**: SHAP + LIME integration to understand evasion strategies
- **Production-ready**: MLflow + Weights & Biases for reproducibility and monitoring

## Workflow (English)

### Step 1: Setup Environment

```bash
# Option 1: Conda (Recommended)
conda env create -f environment.yml
conda activate rl_c2_evasion

# Option 2: Pip + venv
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt  # If needed
```

### Step 2: Prepare Data & Surrogate Model

```bash
# Run surrogate IDS training notebook
cd blue_team
jupyter notebook train_surrogate.ipynb
# Output: data/surrogate_ids_ctu13.pkl, data/label_encoder_*.pkl
cd ..
```

### Step 3: Verify Environment

```bash
python3 setup_check.py
# Or use Makefile:
make check
```

### Step 4: Train PPO Agent

```bash
make train
# Or manually:
cd ai_agent
python3 train_agent.py
```

Monitor training:
```bash
make tensorboard
# Visit http://localhost:6006
```

### Step 5: Evaluate Agent

```bash
make eval
# Or:
cd ai_agent
python3 evaluate.py
```

### Step 6: Cleanup

```bash
make clean
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
│   ├── surrogate_ids_ctu13.pkl        # Trained surrogate model
│   ├── label_encoder_proto.pkl        # Protocol encoder
│   └── label_encoder_state.pkl        # State encoder
│
├── models/                            # Trained agents (created at runtime)
│   └── ppo_c2_evasion_agent.zip       # Trained PPO policy
│
├── environment.yml                    # Conda environment spec
├── Makefile                           # Workflow automation
└── README.md                          # This file
```

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

## Recent Updates (Sep 2026)

### ✅ Callback Fix – Accurate Evasion Metrics

**Issue:** `evasion_metrics_callback.py` was aggregating per-step instead of per-episode, deflating reported evasion rates by ~3×.
- Old: 30% on TensorBoard for a 94% evasion rollout
- Root cause: Successful episodes = 1 step, failed episodes = up to 10 steps → metric ≈ p / L

**Fix:** Callback now aggregates per-episode:
```python
# Accumulate within episode, append only on termination
if done:
    self.episode_evasion_buffer.append(final_success_flag)
```
**Impact:** TensorBoard now reports true episode-level evasion rate. Retrain with the fixed callback for honest benchmarks.

### ✅ Surrogate Upgrade – RandomForest → XGBoost

**Benchmark on CTU-13 (matched hyperparams):**

| Metric | RandomForest | XGBoost | Delta |
|--------|--------------|---------|-------|
| F1 Score | 0.9365 | **0.9476** | +1.2 pp |
| ROC AUC | 0.9835 | **0.9888** | +0.5 pp |
| Inference (ms) | 7.0 | **1.35** | 5.2× faster |
| Model Size | 38.9 MB | **7.5 MB** | 5.2× smaller |
| Proba Sharpness | 54.1% | **71.9%** | +33% (better reward signal) |

**New surrogate notebook:** `blue_team/train_surrogate_xgboost.ipynb`
**Trained model:** `data/surrogate_ids_ctu13.pkl` (XGBoost)

**Recommendation:** Use XGBoost. It wins on every metric and enables faster RL training cycles.

---

## Known Issues & Improvements

### Current Limitations

1. **Missing trained models** – `.pkl` files must be generated from `blue_team/` notebooks
   - **Fix:** Run `blue_team/train_surrogate_xgboost.ipynb` first or provide pre-trained weights

2. **No `models/` directory** – Agent can't save trained weights
   - **Fix:** Add `.gitkeep` to `models/` folder

3. **No CI/testing** – No automated checks for environment setup
   - **Fix:** Add `test_setup.py` or pytest fixtures

### Suggested Enhancements

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

### Core RL Stack

- `gymnasium==1.3.0` – RL environment framework
- `stable-baselines3==2.9.0` – PPO, DQN, A2C implementations
- `sb3-contrib==2.2.1` – SAC, TD3, QRDQN advanced algorithms
- `pytorch>=2.1` – Neural network backbone & GPU support
- `tensorboard==2.21.0` – Training visualization

### Advanced ML (Improved)

- `xgboost>=2.0` – High-performance gradient boosting (surrogate IDS)
- `lightgbm>=4.0` – Alternative gradient boosting
- `shap>=0.42` – Feature importance & explainability
- `lime==0.2.0` – Model-agnostic explanations
- `eli5==0.13.0` – Feature visualization

### Experiment Tracking & Reproducibility

- `wandb==0.15.12` – Weights & Biases for monitoring
- `mlflow==2.8.1` – Model registry & tracking
- `featuretools==1.28.0` – Automated feature engineering

### Data & Utilities

- `pandas>=2.0`, `numpy>=1.24` – Data manipulation (pinned versions)
- `pyarrow>=12.0` – Parquet file I/O
- `scapy==2.7.0` – Network packet crafting
- `flask==3.1.3` – C2 server mock
- `opencv-python==4.8.1.78` – Image processing (stable version)

See `environment.yml` for full dependency list and versions.

## Dataset: CTU-13

**Source:** [CTU-13 Botnet Captures](https://www.stratosphereips.org/datasets-ctu13)

**Composition:**
- 13 scenarios (1 botnet per scenario: Neris, Rbot, Virut, Menti, Sogou, Murlo, NsisAy)
- ~2.8 GB total (binetflow format, pre-converted to Parquet)
- Features: `dur`, `tot_pkts`, `tot_bytes`, `src_bytes`, `proto`, `state`
- Labels: Botnet vs. Normal (benign) traffic

**License:** Public / Research use

## References

- [Stable Baselines3 Docs](https://stable-baselines3.readthedocs.io/)
- [Gymnasium Documentation](https://gymnasium.farama.org/)
- [CTU-13 Dataset Paper](https://www.stratosphereips.org/datasets-ctu13)
- [Adversarial Examples in IDS](https://arxiv.org/abs/1810.00912)

## License

MIT License – See LICENSE file for details.
