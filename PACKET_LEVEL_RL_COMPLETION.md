# Packet-Level RL Implementation — Completion Report

**Date**: 2026-09-24  
**Branch**: `packet-level-rl`  
**Plan**: `.hermes/plans/2026-09-24_230000-packet-level-rl-ids-evasion.md`

## Summary

Implemented packet-level RL environment where the agent modifies individual packets (TTL, fragmentation, padding, TCP overlaps) instead of flow-level aggregates. Training uses the real Snort replica as the reward function (no XGBoost surrogate mismatch).

**Result**: Agent achieves **92.10% evasion** vs **90.90% random** on the full pool (+1.20 pp, 5 seeds). On the 10.4% of flows long enough to act on (≥10 packets) it is **30.87% vs 20.20%** (+10.67 pp), confirmed against the real Snort binary. The plan's >95% target is **not** met — see [Measured Results](#measured-results) below.

## Deliverables

### Code (6 files)

1. **`ai_agent/packet_modifier.py`** — Applies packet-level actions
   - `apply_actions()`: TTL delta, fragmentation, padding, TCP overlap
   - `to_flow_features()`: Recomputes flow aggregates from modified packets
   - Test: `tests/test_packet_modifier.py` ✓

2. **`ai_agent/packet_level_env.py`** — Gymnasium environment
   - Action space: 4D continuous `[ttl_delta, frag_flag, padding_bytes, overlap_offset]`
   - Observation space: 7D `[pkt_idx, direction, dsize, time, flow_bytes, flow_pkts, detected]`
   - Reward: `replica_snort_verdict()` (real Snort replica, not surrogate)
   - Test: `tests/test_packet_level_env.py` ✓

3. **`ai_agent/train_packet_level_agent.py`** — PPO training script
   - Default: 10K steps (plan specification)
   - `--timesteps N` override for longer runs
   - Checkpoints every 1K steps
   - Output: `models/ppo_packet_level_agent.zip`

4. **`ai_agent/eval_packet_level_agent.py`** — Evaluation script
   - 80 seeded episodes (seed=42)
   - Compares agent vs random baseline
   - Output: `snort_validation/reports/packet_level_agent_evaluation.json`

### Documentation (2 files)

5. **`docs/packet_level_rl.md`** — Full design document
   - Architecture diagram
   - Action/observation/reward tables
   - Measured throughput (~10K steps/s)
   - Known limitations (documented honestly)

6. **`README.md`** — Packet-level RL section
   - Quick-start commands
   - Link to full documentation

### Training Results

**Environment**: PacketLevelEnv  
**Model**: PPO (MlpPolicy, lr=3e-4, n_steps=256, batch_size=64)  
**Training**: 10,000 steps in 16.2 seconds  
**Seed**: 42 (reproducible)

## Measured Results

### Single seeded run (the plan's eval script, 80 episodes, seed=42)

- **Agent**: 76/80 evaded (95.0%)
- **Random**: 75/80 evaded (93.8%)
- **Improvement**: +1.2% over random baseline

This is the run that the plan's `eval_packet_level_agent.py` prints as `[✓] SUCCESS`.
It is a **smoke test, not a result**: 80 episodes puts one episode at 1.25 pp,
and the measured seed-to-seed standard deviation is ~1.1 pp. The +1.2 pp gap is
one episode wide — inside the noise floor of the measurement.

### Multi-seed measurement (5 seeds, 400 episodes/seed full pool, 300/seed subset)

| Population | Agent evasion | Random evasion | Gap |
|---|---|---|---|
| Full pool (262,504 flows) | **92.10%** (std 1.12) | 90.90% (std 0.93) | **+1.20 pp** |
| Flows with ≥10 planned packets (27,237 flows, 10.4%) | **30.87%** (std 1.29) | 20.20% (std 1.42) | **+10.67 pp** |

Per-seed agent evasion on the subset: 28.3 / 31.3 / 31.3 / 32.0 / 31.3 — the gap
holds on every seed. 10.67 pp against a ~1.3 pp seed std is roughly a 6-sigma
effect, so the subset result is solid even though the full-pool result is not.

### Real-Snort ground truth

60 episodes per arm on the subset, each final flow written to a pcap and scored
by the actual Snort 2.9 binary: agent **30.0%** real evasion vs random **21.7%**,
with the replica agreeing on **60/60** flows in both arms. The agent's evasions
survive the real detector at exactly the rate the replica predicts.

These numbers were re-measured in a clean git worktree at commit `f632370`, so
they are tied to the 6-rule reward the model actually trained against. A sibling
change adding `sid:3000007`–`3000011` landed at 00:04:39 on 2026-09-25, after
training (23:54:24); re-measure after any ruleset change.

## Key Findings

### 1. Agent beats random baseline, but only where there is room to act

On the full pool the margin is +1.20 pp. On the subset of flows that run ≥10
packets — the only ones where the agent gets a real decision to make — the
margin is +10.67 pp. The full-pool number is dominated by flows that already
evade and by episodes averaging ~3 steps.

### 2. Measured throughput vs plan estimate

- **Plan estimate**: "2–3 hours for 10K steps"
- **Actual**: 16 seconds for 10K steps (~10,000 steps/s raw rollout, ~700–800 fps under PPO)
- **Ratio**: Plan was ~1000× pessimistic

The bottleneck is `load_malicious_pool()` (5s per process start), not the env itself. Multi-million-step overnight runs are feasible.

### 3. Action space limitation

Three of the four action dimensions are currently **inert**:
- `ttl_delta`: Not read by `replica_snort_verdict()`
- `frag_flag`: Not read by `replica_snort_verdict()`
- `overlap_offset`: Not read by `replica_snort_verdict()`
- `padding_bytes`: **Active** (affects `dsize` → flow features → reward)

Only `padding_bytes` reaches the reward function. The agent cannot gain reward by varying TTL, fragmentation, or TCP overlaps under the current replica implementation.

### 4. Zero-packet flows

`packet_plan()` returns `[]` for ICMP/RTP/unknown protocols (6 of 200 random flows). These terminate on their first step and are scored as evasions, inflating all evasion rates by ~3%.

### 5. No surrogate mismatch

Unlike the flow-level agent (trained on XGBoost, evaluated on real Snort), this agent trains directly on `replica_snort_verdict()`, which agrees with real Snort 99.7% of the time. The surrogate-mismatch problem does not apply here.

## Comparison: Flow-level vs Packet-level

| Metric | Flow-level (CTU-13) | Packet-level | Random |
|--------|---------------------|--------------|--------|
| Evasion rate, full pool | 82.5% | **92.10%** | 90.90% |
| Evasion rate, ≥10-pkt flows | n/a | **30.87%** | 20.20% |
| Training time | 276s (50K steps) | 16s (10K steps) | N/A |
| Reward source | XGBoost surrogate | Real Snort replica | N/A |
| Action space | Flow aggregates | Packet-level tricks | N/A |
| Surrogate mismatch | Yes (82.5% → 7.5% on real Snort) | No | N/A |

## Limitations (documented in `docs/packet_level_rl.md`)

1. **Inert action dimensions**: Only `padding_bytes` affects reward. TTL, fragmentation, and TCP overlap are recorded but not evaluated by the replica.

2. **Zero-packet flows**: ICMP/unknown protocols yield empty packet plans and are auto-scored as evasions.

3. **Partial-flow detection**: Flow features are recomputed after every packet, so detection is evaluated on the *partial* flow. This is what makes episodes terminate mid-flow.

4. **High random baseline**: 93.8% of flows evade with random actions, leaving only 6.2% headroom for the agent to demonstrate skill.

## Future Improvements

1. **Extend the replica** to read TTL, fragmentation, and overlap fields so all four action dimensions become learnable.

2. **Multi-packet actions**: Apply actions to packet groups instead of one-by-one.

3. **Curriculum learning**: Start with easy flows (low packet count), progress to complex.

4. **Real Snort validation**: Test the trained agent against the actual Snort 2.9 binary (not just the replica).

5. **Longer training**: The plan's 10K-step budget was chosen for a 2–3h slot. Actual throughput allows multi-million-step runs overnight.

## Git Log

```
abf21ad docs: record measured packet-level results (5-seed, real-Snort verified)
6f75e27 docs: add completion report for packet-level RL implementation
141528e results: packet-level agent achieves 95.0% Snort evasion   <- single-run claim, corrected above
f632370 docs: add packet-level RL documentation and README section
a5f4729 feat: add evaluation script for packet-level agent
52742dc feat: add training script for packet-level agent
756f8f8 feat: add PacketLevelEnv for packet-level RL
43e1ca4 feat: add PacketModifier for packet-level evasion actions
cf388fe chore: create packet-level-rl branch
```

**Base**: `snort-validation` branch (commit `2855321`)
**HEAD**: `packet-level-rl` branch (see `git log`)
**Commits**: 10 (1 setup + 4 implementation + 5 docs/results)

## Overnight Training

Training was run at two scales. Both are complete; there is no job left running.

| Run | Steps | Wall time | Model |
|---|---|---|---|
| Plan default | 10,000 | 16.2 s | `models/ppo_packet_level_agent.zip` |
| Overnight-scale | 1,000,000 | 1380.7 s (23 min) | `models/ppo_packet_level_agent_1m.zip` |

Command used for the long run (log: `/tmp/train_packet_level_1m.log`):

```bash
.venv/bin/python ai_agent/train_packet_level_agent.py \
    --timesteps 1000000 --checkpoint-freq 100000 --tag "_1m"
```

The plan budgeted "2-3 hours" for 10K steps, so a 1M-step run would have been
~100-300 h under that estimate. Actual throughput is ~700-800 fps under PPO, so
it took 23 minutes and finished well inside the overnight slot.

**Result: more training does not help.** On the same 5 seeds × 300 episodes of
the ≥10-packet subset:

| Model | Subset evasion | std |
|---|---|---|
| 10K steps | 30.87% | 1.29 |
| 1M steps | 30.60% | 1.29 |
| random | 21.60% | 1.42 |

100x the optimisation budget moves the number by -0.27 pp. The 10K-step model is
already at the ceiling this reward function imposes. Spending more of the
overnight slot on training this environment would not change the outcome; the
constraint is that three of the four action dimensions never reach the reward.

## Test Coverage

All new components have unit tests:

```bash
.venv/bin/python tests/test_packet_modifier.py    # ✓ PASS
.venv/bin/python tests/test_packet_level_env.py   # ✓ PASS
```

## Reproducibility

### Training
```bash
cd /root/.hermes/c2-evasion-rl
.venv/bin/python ai_agent/train_packet_level_agent.py
# Output: models/ppo_packet_level_agent.zip (10K steps, seed=42)
```

### Evaluation
```bash
.venv/bin/python ai_agent/eval_packet_level_agent.py
# Output: snort_validation/reports/packet_level_agent_evaluation.json
# Result: 95.0% agent evasion vs 93.8% random baseline
```

### Environment
The repo-local `.venv` has all dependencies (gymnasium, stable-baselines3, torch, numpy, pandas, pyarrow, sklearn, xgboost, joblib). It was created by copying site-packages from `/tmp/jev-poc/venv` (the only working interpreter found on the system).

## Success Criteria

**Plan target**: Agent evasion rate > 95%
**Achieved**: **92.10%** on the full pool, **30.87%** on ≥10-packet flows. **Target not met.**

The earlier claim that this target was met ("95.0%, exact target met") rested on
a single 80-episode run. Re-measured across 5 seeds the agent scores 92.10%, and
the +1.2 pp edge over random is real but small. The 95.0% figure was a lucky
draw inside a ~1.1 pp noise band, not a threshold crossing.

**Plan hypothesis**: Packet-level agent should beat random baseline because:
1. ✓ No surrogate mismatch (trains on real Snort replica)
2. ✗ Packet-level primitives can exploit TTL/frag/padding (only padding is active)
3. ✓ Fine-grained control (modifies each packet individually)

**Outcome**: Hypothesis partially confirmed. The agent does beat random — by
+10.67 pp on the flows where it has room to act, verified against real Snort —
but only one action dimension reaches the reward, which caps what "packet-level"
can mean here.

## Conclusion

Implementation complete. All 7 tasks from the plan are delivered:

- ✓ Task 1: Branch created (`packet-level-rl`)
- ✓ Task 2: PacketModifier implemented + tested
- ✓ Task 3: PacketLevelEnv implemented + tested
- ✓ Task 4: Training script implemented
- ✓ Task 5: Evaluation script implemented
- ✓ Task 6: Documentation written (`docs/packet_level_rl.md`)
- ✓ Task 7: README updated with packet-level RL section

Agent achieves 92.10% evasion on the full pool (vs 90.90% random) and 30.87%
(vs 20.20% random) on ≥10-packet flows, the latter verified against the real
Snort 2.9 binary at 100% replica agreement. The plan's >95% target is not met.

The highest-value next step is **not** more training — it is making TTL,
fragmentation, and overlap actually influence the verdict, so the remaining
three action dimensions become learnable.
