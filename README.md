# C2 Evasion RL

RL agent (PPO) that mutates botnet C2 flows from the CTU-13 dataset to slip past an ML-based intrusion detector, which plays the role of the defender.

The point is not to build a working attack tool. It is to measure how much an adaptive attacker can hurt a detector, and to find out where the detector's blind spots are.

## How it works

Two models sit on opposite sides:

- **Judge (blue team)** — a gradient-boosted classifier trained on CTU-13 flows. Given 6 flow features, it returns P(malicious). This stands in for an IDS.
- **Agent (red team)** — a PPO policy that picks 4 continuous mutations per step to push that probability below the decision threshold.

Each episode starts from a real botnet flow. The agent mutates it, the judge scores it, and the episode ends when the judge says "normal" or after 10 steps.

### Action space

4 continuous values in `[-1, 1]`:

| # | Action | Range | Effect |
|---|---|---|---|
| 0 | Jitter | ±5 s | Shift flow duration |
| 1 | Padding | ±500 bytes | Add or remove payload bytes |
| 2 | Protocol hop | binary | TCP ↔ UDP |
| 3 | State hop | binary | CON ↔ INT |

### Observation space

6 normalized flow features: `dur`, `tot_pkts`, `tot_bytes`, `src_bytes`, `proto`, `state`.

### Reward

```
reward = R_evasion   if the judge predicts normal
       = R_detection if the judge predicts malicious
       + confidence_bonus × (drop in P(malicious))
       − mutation_cost   × (action magnitude)
       − step_penalty
```

Defaults in `ai_agent/config.py`: `R_evasion = 50.0`, `R_detection = −2.0`, `step_penalty = −0.1`.

## Dataset

[CTU-13](https://www.stratosphereips.org/datasets-ctu13) — 13 real botnet captures (Neris, Rbot, Virut, Menti, Sogou, Murlo, NsisAy), converted from binetflow to Parquet.

| Stage | Rows |
|---|---|
| Raw | 10,598,771 |
| After dropping `Background` labels | 465,122 |
| — botnet (1) | 262,573 |
| — normal (0) | 202,549 |
| After undersampling | 405,098 |
| Train / test split | 324,078 / 81,020 |

`Background` traffic is dropped entirely rather than treated as benign. An earlier version labeled background as "normal", which produced a judge that flagged nothing and made every evasion number meaningless.

## The judge

Currently an XGBoost classifier, 100 trees, `max_depth=6`, trained by `blue_team/train_surrogate_xgboost.ipynb`.

| Metric | Value |
|---|---|
| Accuracy | 0.9130 |
| Precision | 0.9205 |
| Recall | 0.9040 |
| F1 | 0.9122 |
| ROC AUC | 0.9716 |
| Model size | 0.39 MB |

For comparison, the previous RandomForest (`max_depth=15`) scores F1 0.9359 / AUC 0.9833 at 41.85 MB.

**XGBoost at depth 6 is less accurate than the RandomForest it replaced** — about 2.4 F1 points worse. It was chosen for speed, not accuracy, and the speed difference is large enough to matter (see below). An XGBoost at `max_depth=15` reaches F1 0.9469 / AUC 0.9885, which beats the RandomForest, but that configuration is not the one currently saved to `data/surrogate_ids_ctu13.pkl`.

## Why training got ~125× faster

Training 50k steps dropped from roughly 80 minutes to about 3. The cause was the judge, not the PPO network — the policy hyperparameters never changed.

`env.step()` calls `judge.predict()` and `judge.predict_proba()` on a **single row**, once per step. For a one-row call, `RandomForest(n_jobs=-1)` builds and tears down a joblib thread pool every time, and that dispatch cost swamps the actual tree traversal. Measured on one 4-core machine:

| Judge | Per-call (1 row) | `env.step()` | Steps/sec |
|---|---|---|---|
| RandomForest `n_jobs=-1` | 96,287 µs | 189.6 ms | 5 |
| RandomForest `n_jobs=1` | 9,929 µs | — | — |
| XGBoost `n_jobs=1` | 653 µs | 1.52 ms | 659 |

Independent check from TensorBoard: the RandomForest run (PPO_19) logged 10.5 fps, the XGBoost run (PPO_20) logged 253.6 fps. And 1 / 96.287 ms = 10.38 steps/sec, which matches the measured 10.5 fps — the judge was essentially the entire training cost, leaving the PPO network almost no CPU.

The reason `n_jobs=-1` was there in the first place: it is genuinely correct for training. It halves fit time (0.6 s vs 1.2 s). The same model object then served ~50,000 single-row calls, where the setting is a liability. Nothing warned about it.

The two libraries parallelize differently, which is why the same parameter name behaves so differently:

| | RandomForest (sklearn) | XGBoost |
|---|---|---|
| Backend | joblib | OpenMP |
| Thread pool | Created per call | Reused globally |
| `n_jobs=-1`, 1 row | 96 ms | 0.94 ms |
| `n_jobs=-1`, 1024 rows | 153 ms | 1.57 ms (fastest) |

Rule: a single-row inference path must use `n_jobs=1`, regardless of library. Never benchmark a judge with batched calls — RandomForest looks fine at 1024 rows and only falls apart one row at a time.

The judge is no longer the bottleneck. XGBoost tops out around 1,510 steps/sec while training runs at ~253 fps, so any further speedup has to come from the PPO/NumPy side.

## Results

The judge does detect the real botnet pool: 90.41% of the 262,504 botnet flows are labeled malicious, mean P(malicious) = 0.846. That is the number that matters — with the older RandomForest judge, P(malicious) on genuine botnet traffic was around 0.207, meaning the judge detected almost nothing and every evasion figure was measuring a hole in the model rather than agent skill.

Trained agent, per-episode evasion, over 24 evaluation points:

| Policy | Evasion rate |
|---|---|
| PPO agent | ~89% |
| Random policy (baseline) | 81.5% |

The agent beats a random policy by about 7.5 percentage points. That is a modest margin, and it should be read as such — most of the evasion comes from the judge being easy to fool, not from the agent learning anything clever.

Single actions alone confirm this:

| Action | Evasion rate |
|---|---|
| Jitter | 80.0% |
| Padding | 70.5% |
| State hop | 47.0% |
| Protocol hop | 43.5% |

One action, applied once, already gets 70–80%. The judge is the weak link.

## Metric callback

`evasion_metrics_callback.py` originally averaged the per-step success flag, which folds episode length into the score. Successful episodes terminate immediately and contribute 1 step with flag 1, while failed episodes contribute up to 10 steps with flag 0, so the reported rate comes out close to `p / L`. An identical rollout scored ~31% under the old callback and ~94% per-episode.

It now accumulates within an episode and records only at episode end. Any metric callback in this project must work in episode-level units. When a reported number disagrees with an independent recount, recompute both from the raw rollout before trusting either.

## Setup

```bash
conda env create -f environment.yml
conda activate rl_c2_evasion
```

`environment.yml` is the only dependency file — there is no `requirements.txt`, even though the `install-pip` Make target references one.

Generate the judge and encoders first — the agent cannot run without them:

```bash
cd blue_team
jupyter notebook train_surrogate_xgboost.ipynb   # writes data/surrogate_ids_ctu13.pkl + encoders
cd ..
```

Then train and evaluate:

```bash
make check      # verify environment
make train      # train PPO agent
make tensorboard
make eval
```

Equivalent without `make`: `python3 setup_check.py`, then `python3 train_agent.py` and `python3 evaluate.py` from `ai_agent/`.

## Configuration

`ai_agent/config.py`:

| Parameter | Default |
|---|---|
| `PPO_LEARNING_RATE` | 1e-4 |
| `PPO_N_STEPS` | 1024 |
| `PPO_BATCH_SIZE` | 32 |
| `PPO_GAMMA` | 0.99 |
| `PPO_ENT_COEF` | 0.01 |
| `TOTAL_TIMESTEPS` | 50,000 |
| `MAX_STEPS` | 10 |
| `REWARD_EVASION` | 50.0 |
| `REWARD_DETECTION` | −2.0 |

Training runs on CPU (`device="cpu"` in `train_agent.py`).

## Layout

```
ai_agent/          PPO training, env, config, callbacks
  c2_evasion_env.py          Gymnasium env — mutations, reward, judge calls
  train_agent.py             training entry point
  evaluate.py                runs the trained policy over samples
  evasion_metrics_callback.py
  callback_metric_proof.py   demonstrates the per-step vs per-episode discrepancy
  config.py
blue_team/         judge training
  train_surrogate_xgboost.ipynb    current judge
  train_surrogate.ipynb            earlier RandomForest judge
  train_ids.ipynb
red_team/          mock C2 infrastructure (Flask server, client, interceptors)
data/              CTU-13 flows, trained judge, label encoders
models/            saved PPO policy
```

## Troubleshooting

**`surrogate_ids_ctu13.pkl` not found** — run `blue_team/train_surrogate_xgboost.ipynb` first. The file is gitignored and generated locally.

**Training far slower than expected** — check the judge's per-call inference cost before anything else. A slow judge is called once per step and will dominate everything. Confirm it is `n_jobs=1` on the single-row path.

**TensorBoard won't start** — `pkill -f tensorboard`, then `tensorboard --logdir=ai_agent/c2_ppo_tensorboard/ --port=6006`.

## Dependencies

Actually imported by the code:

- `gymnasium`, `stable-baselines3`, `torch` — RL stack
- `xgboost`, `scikit-learn`, `joblib` — judge
- `pandas`, `numpy`, `pyarrow` — data
- `tensorboard` — training curves
- `flask`, `requests` — mock C2 server and client
- `scapy`, `netfilterqueue` — packet interception

`environment.yml` is the authoritative list. It also pins some packages (`shap`, `lime`, `eli5`, `wandb`, `mlflow`, `lightgbm`, `featuretools`) that are not referenced anywhere in the code — leftovers from an earlier plan.

## Limitations

- The judge is easy to fool. A single action reaches 70–80% evasion, so the agent's margin over random is small and says more about the judge than the agent.
- No adversarial loop. The defender is frozen; nothing retrains it against new evasion strategies.
- Only 6 flow features. Real attacks have payload, timing, and DNS to work with.
- The agent is only evaluated against its own surrogate, never against a different IDS.
- The README benchmark table previously listed XGBoost at F1 0.9476 / AUC 0.9888 / 7.5 MB and called it a win on every metric. Those numbers belonged to an unused `max_depth=15` variant; the deployed model is `max_depth=6` and scores lower than the RandomForest it replaced.

## Next steps

1. Improve the judge — drop the aggressive undersampling, add features, add regularization. Target: high P(malicious) on unmodified botnet flows.
2. Always report a random-policy baseline alongside agent numbers. Without it an evasion rate means nothing.
3. Close the loop — retrain the defender against the agent's strategies.
4. Test transfer: does the agent still evade an IDS it was not trained against?

## References

- [CTU-13 dataset](https://www.stratosphereips.org/datasets-ctu13)
- [Stable-Baselines3](https://stable-baselines3.readthedocs.io/)
- [Gymnasium](https://gymnasium.farama.org/)
