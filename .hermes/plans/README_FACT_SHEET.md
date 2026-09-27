# README rewrite — verified fact sheet

Source of truth for the README subagent. Every number below was read from code
or measured on 2026-09-26. Do NOT invent numbers; if you need one not here,
say so instead of guessing.

## Repo
- Path: /root/.hermes/c2-evasion-rl
- Branch: `packet-level-rl` (push target for this task: `main`, fast-forward)
- Python: repo-local venv `.venv/bin/python`

## Current PPO packet-level system (the part missing from README)

### Action space — `ai_agent/enhanced_packet_level_env.py`
`spaces.Box(low=-1.0, high=1.0, shape=(4,), dtype=np.float32)`, one action per
packet. Env maps normalized -> real in `step()`:
| dim | name | normalized | real range |
|---|---|---|---|
| 0 | ttl_delta | `a*10` | ±10 |
| 1 | frag_flag | as-is | bool(a>0) |
| 2 | padding_bytes | `(a+1)*100` | 0–200 |
| 3 | tcp_overlap | `a*100` | ±100 |

### Observation space
`spaces.Box(low=0.0, high=1.0, shape=(7,), dtype=np.float32)`:
`[pkt_idx, direction, dsize, time, bytes_sent, pkts_sent, is_detected]` (all
normalized). NOTE: `time_norm` is hardcoded `0.0` — an observation dim that
carries no signal.

### Reward
Per step: `-0.1` while the flow is still being emitted. On the terminal step
(`terminated`), verdict from `enhanced_replica_snort_verdict`:
- detected → `-1.0`
- evaded → `+10.0`

### Reward path — why "enhanced" matters
`EnhancedPacketLevelEnv` calls `enhanced_replica_snort_verdict(flow_features,
modified_packets)`, which sees packet-level fields (TTL, fragmented,
overlap_offset). The base `PacketLevelEnv` calls the flow-level
`replica_snort_verdict`, which sees only `{tot_pkts, tot_bytes, src_bytes,
dur, proto, state}`. Measured consequence: under the flow-level replica, the
ttl_delta / frag_flag / overlap_offset action dims have **zero reward spread** —
the agent cannot learn them. `scripts/measure_action_impact.py` quantifies this.

### PacketModifier — `ai_agent/packet_modifier.py`
Clamps: `ttl_delta` int clip ±10; `frag_flag` bool(>0); `padding_bytes` int clip
0–200; `overlap_offset` int clip ±100. `dsize` grows by `padding_bytes`.
`to_flow_features()` derives `{tot_pkts, tot_bytes, src_bytes, dur}` and
hardcodes `proto="tcp"`, `state="CON"`.

## Measured results (verified 2026-09-26)

### Cross-capture PPO eval — `ai_agent/eval_cross_capture.py`
Source: `snort_validation/reports/cross_capture_eval.json`
- train capture: `botnet-capture-20110810-neris`
- eval capture: `botnet-capture-20110811-neris`, 50 flows
- **baseline evasion 4.0%** (seeded random policy)
- **agent evasion 82.0%** (`models/ppo_enhanced.zip`, deterministic)
- **delta +78.0 pp**
- Reproducible: 3 consecutive subprocess runs produce byte-identical JSON,
  sha256 `e86b3fe7611b0f007edd8df92591c2358df053f39a65892877e5a530b7dcf3e5`

Before the determinism fix the same script printed a different baseline on
every run (observed 0.02, 0.04, 0.06, 0.10). Commit `8373686` fixed it.

### The 11-row bandit sweep (already in README, keep as-is)
- cost sweep 0.1–0.6 @ 24 flows: 100% evasion, 2.88 packets corrupted
- scale-up 24→200 flows: 100% at every size
- cross-capture: `20110810-neris` 16.7% vs `20110811-neris` 100%
These came from `snort_validation/reports/final_results_table.json` via the
**bandit** (`ai_agent/snort_bandit.py`), a DIFFERENT system from the PPO agent.
The README currently does not distinguish them. That distinction is the main
thing this rewrite must fix.

## Files that exist now but are absent from README
- `ai_agent/eval_cross_capture.py` — cross-capture PPO eval
- `ai_agent/enhanced_packet_level_env.py` — env whose reward sees packet fields
- `ai_agent/packet_modifier.py` — the 4-dim action → packet mutation
- `ai_agent/train_enhanced_packet_agent.py`, `ai_agent/eval_enhanced_agent.py`
- `tests/test_eval_cross_capture_determinism.py` — determinism regression tests
- `scripts/measure_action_impact.py` — per-dimension reward sensitivity
- `scripts/trace_action_to_reward.py` — action → packet → verdict trace

## Deliberately NOT in the README (user decision, 2026-09-26)
The MCFP parquet lacks `dur` / `src_bytes` / `state`; the env substitutes
defaults, so eval flows are scored against synthetic packet plans. Mapping the
columns correctly moves agent evasion 0.82 → 0.84. Do NOT mention this in the
README. The fact is recorded at
`.hermes/plans/2026-09-26_122500-mcfp-schema-caveat.md` and the README should not
contradict it, but it need not volunteer it.
