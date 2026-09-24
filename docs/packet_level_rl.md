# Packet-Level RL for IDS Evasion

## Overview

Packet-level RL environment that enables agents to learn **packet-level evasion techniques** (TTL manipulation, fragmentation, padding, TCP overlaps) instead of flow-level feature modifications.

**Key difference from flow-level RL**:
- **Flow-level**: Agent modifies aggregates (dur, tot_pkts, tot_bytes) → 82.5% Snort evasion
- **Packet-level**: Agent modifies individual packets (TTL, fragmentation, padding) → target >95% evasion

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      PacketLevelEnv (Gym)                        │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────────┐   │
│  │   Agent      │   │ PacketModifier│   │ SnortEvaluator  │   │
│  │ (PPO Policy) │──>│ (apply TTL,   │──>│ (Snort replica) │   │
│  │              │   │  frag, pad)   │   │                  │   │
│  └──────────────┘   └──────────────┘   └──────────────────┘   │
│         ▲                                        │               │
│         │                                        │               │
│         └────────────── reward ─────────────────┘               │
└─────────────────────────────────────────────────────────────────┘
```

## Action Space

**4D continuous**: `[ttl_delta, frag_flag, padding_bytes, overlap_offset]`

- `ttl_delta`: ±10 TTL variance per packet
- `frag_flag`: Binary fragmentation flag
- `padding_bytes`: 0-200 bytes extra payload
- `overlap_offset`: ±100 bytes TCP overlap (future work)

## Observation Space

**7D continuous**: `[pkt_idx, direction, dsize, time, flow_bytes_sent, flow_pkts_sent, is_detected]`

- `pkt_idx`: Current packet index (normalized)
- `direction`: 0 = client→server, 1 = server→client
- `dsize`: Payload size (normalized by MTU)
- `time`: Packet timestamp (normalized)
- `flow_bytes_sent`: Cumulative bytes sent
- `flow_pkts_sent`: Cumulative packets sent
- `is_detected`: Snort detection flag (0 = not yet, 1 = detected)

## Reward Structure

- **+10.0**: Successfully evaded through all packets
- **-1.0**: Detected by Snort
- **-0.1**: Per-step penalty (encourage efficiency)

The reward is emitted by `replica_snort_verdict()`, the Python replica of the
rules in `snort_validation/rules/botnet-behavior.rules`. The replica is scored
against the real Snort 2.9 binary by `snort_validation/verify_snort_replica.py`
(99.7% agreement) — there is no XGBoost surrogate in this reward path, so the
surrogate-mismatch problem that capped the flow-level agent does not apply.

## Usage

### Environment

The repo-local virtualenv has every dependency:

```bash
cd /root/.hermes/c2-evasion-rl
.venv/bin/python ai_agent/train_packet_level_agent.py
```

### Training

```bash
cd /root/.hermes/c2-evasion-rl
.venv/bin/python ai_agent/train_packet_level_agent.py
```

**Parameters**:
- Total steps: 10,000 (plan default)
- Checkpoints: every 1,000 steps
- Seed: 42 (reproducible)
- `--timesteps N` to override the step budget, `--tag SUFFIX` to name the outputs

**Output**:
- Model: `models/ppo_packet_level_agent.zip`
- Checkpoints: `models/checkpoints_packet_level/`
- Metadata: `logs/training_packet_level.json`

### Evaluation

```bash
.venv/bin/python ai_agent/eval_packet_level_agent.py
```

**Output**:
- 80 seeded episodes (seed=42)
- Report: `snort_validation/reports/packet_level_agent_evaluation.json`
- Comparison: agent vs random baseline

## Measured Results

See [`packet_level_rl_results.md`](packet_level_rl_results.md) for the full
write-up. Headline, 5 seeds:

| Population | Agent evasion | Random evasion | Gap |
|---|---|---|---|
| Full pool (262,504 flows) | **92.10%** | 90.90% | +1.20 pp |
| Flows with ≥10 planned packets (10.4% of pool) | **30.87%** | 20.20% | **+10.67 pp** |

The subset gap was confirmed against the **real Snort 2.9 binary** at 100%
replica agreement (agent 30.0% real evasion vs random 21.7%).

The plan's stated success criterion (agent evasion > 95%) is **not met** on the
full pool. A single 80-episode seeded run reports 95.0% and prints SUCCESS, but
the seed-to-seed std is ~1.1 pp, so that line is a smoke test rather than a
threshold crossing.

## Expected Results

**Hypothesis**: Packet-level agent should beat random baseline (93.8%) because:
1. **No surrogate mismatch**: Trains directly on real Snort replica
2. **Packet-level primitives**: Can exploit TTL, fragmentation, padding
3. **Fine-grained control**: Modifies each packet individually

**Reality**: hypotheses 1 and 3 hold; hypothesis 2 does not. Only `padding_bytes`
actually reaches the reward function (see Limitations), so the agent learns a
padding/timing policy, not a TTL/fragmentation/overlap policy.

## Comparison: Flow-level vs Packet-level

| Metric | Flow-level (CTU-13) | Packet-level | Random |
|--------|---------------------|--------------|--------|
| Evasion rate, full pool | 82.5% | **92.10%** | 90.90% |
| Evasion rate, ≥10-pkt flows | n/a | **30.87%** | 20.20% |
| Reward source | XGBoost surrogate | Real Snort replica | N/A |
| Action space | Flow aggregates | Packet-level tricks | N/A |

Note the full-pool column is not a like-for-like win over the flow-level agent:
the 6-rule ruleset already misses ~91% of CTU-13 flows unmodified, so most of
that 92.10% is the ruleset, not the agent. The subset column is the one that
isolates the policy.

**Measured throughput**: this environment runs ~10,000 steps/s for a raw
rollout and ~700–800 fps under PPO (measured: 10K steps in 16.2s; 200 random
episodes = 608 steps in 0.1s). The plan's "2-3 hours for 10K steps" estimate is
~1000x pessimistic — a 1M-step run finishes in ~25 minutes. The bottleneck is
not the env; it is that `load_malicious_pool()` costs ~5s per process start.

## Known Limitations

1. **Zero-packet flows.** `packet_plan()` returns `[]` for ICMP/unknown protos
   (no botnet-behavior rule matches them) and for `tot_pkts < 2`. Such an
   episode terminates on its first step and is scored as an evasion, because
   nothing was ever sent to be detected. Measured: 6 of 200 randomly drawn
   flows are in this class. This inflates the evasion rate by roughly that
   margin for any policy, including the random baseline.
2. **The replica never reads TTL, fragmentation, or overlap.** `apply_actions`
   records all four action fields, but `replica_snort_verdict()` only consumes
   `tot_pkts`, `tot_bytes`, `src_bytes`, `dur`, `proto`, `state`. The only
   action field that reaches the reward is `padding_bytes` (via `dsize`), plus
   the packet count. `ttl_delta`, `fragmented`, and `overlap_offset` are
   currently inert — the agent cannot gain reward by varying them.
3. **Flow features are re-derived from the modified packet list.** Because
   `to_flow_features()` recomputes `tot_pkts`/`tot_bytes`/`src_bytes`/`dur`
   from the packets sent so far, detection is evaluated on the *partial* flow
   after every packet. This is what makes the episode terminate mid-flow.

## Future Improvements

1. **TCP overlap exploitation**: Currently `overlap_offset` is passed but not used in Snort replica
2. **Multi-packet actions**: Apply actions to packet groups instead of one-by-one
3. **Curriculum learning**: Start with easy flows (low packet count), progress to complex
4. **Real Snort validation**: Test against actual Snort binary (not just replica)

## References

- HackTricks IDS Evasion: https://hacktricks.wiki/en/generic-methodologies-and-resources/pentesting-network/ids-evasion.html
- PYROLYSE (overlap testing): https://github.com/ANSSI-FR/pyrolyse
