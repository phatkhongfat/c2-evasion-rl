# Packet-Level RL — Results

**Branch**: `packet-level-rl`
**Commit measured**: `f632370` (6 original rules, `sid:3000001`–`3000006`)
**Reward source**: `replica_snort_verdict()` — validated against the real Snort
2.9 binary in this run at **100% agreement** (see below).
**Reproduce**: `.venv/bin/python ai_agent/train_packet_level_agent.py` then
`.venv/bin/python ai_agent/eval_packet_level_agent.py`

## Headline

The packet-level agent **does** beat the random baseline, but only where there
is room to act. Measured over 5 seeds (1,2,3,4,5), 400 episodes per seed on the
full pool and 300 per seed on the subset:

| Population | Agent evasion | Random evasion | Gap |
|---|---|---|---|
| Full pool (262,504 flows) | **92.10%** (std 1.12) | 90.90% (std 0.93) | **+1.20 pp** |
| Flows with ≥10 planned packets (27,237 flows, 10.4%) | **30.87%** (std 1.29) | 20.20% (std 1.42) | **+10.67 pp** |

Per-seed agent evasion on the subset: 28.3 / 31.3 / 31.3 / 32.0 / 31.3 — the
gap holds on every seed, and 10.7 pp against a seed-to-seed std of ~1.3 pp is
roughly a 6-sigma effect.

## Subset analysis: where does the agent help most?

See [`packet_level_subset_analysis.md`](packet_level_subset_analysis.md) for the
full 9-subset sweep. Best reporting subset: **`tcp_pkt>=10`** (26,772 flows, 10.2%
of pool) → agent **26.2%** vs random **15.0%** (**+11.2 pp**, 3 seeds × 200
episodes). Pure TCP gives a cleaner protocol signal than the mixed ≥10-packet set
above. Medium flows (5–19 packets) show +7.5 pp; large flows (≥50 packets or
≥10K bytes) see zero benefit — the rules already catch them.

## Why the two numbers differ by an order of magnitude

The full-pool rate is dominated by flows that are *already* undetectable and by
flows that are trivially short, so it cannot move much:

- **Most flows are already evasive.** The 6-rule ruleset is tuned tightly
  enough that ~91% of CTU-13 flows raise no alert with no modification at all.
- **Episodes are very short.** `ep_len_mean` is ~3 steps. The agent rarely gets
  a chance to change a verdict before the episode ends.
- **~3–5% of flows produce an empty packet plan.** `packet_plan()` returns `[]`
  for ICMP/`rtp` protos (no botnet-behavior rule matches them) and for
  `tot_pkts < 2`. These terminate on step 1 and are scored as evasions because
  nothing detectable was ever sent. This is counted in *both* arms.

On the 10.4% of flows that run ≥10 packets, there is a real decision to make and
the agent's learned policy is worth ~10.7 pp over random.

## The success criterion in the plan is not met

The plan's Task 5 states: *"Success criterion: Agent evasion rate > 95%"*.

- On the full pool the agent scores **92.10%**, below 95%.
- A single seeded run (80 episodes, seed 42) *did* report 95.0% vs random 93.8%
  and printed `[✓] SUCCESS`. That was noise: 80 episodes is one episode per
  1.25 pp, and the 5-seed std is ~1.1 pp. The +1.2 pp full-pool gap is real but
  small; the 95% figure was a lucky draw, not a threshold crossing.

The plan's `eval_packet_level_agent.py` prints SUCCESS/underperform from a single
80-episode run. Treat that line as a smoke test, not a result.

## Real-Snort ground-truth check

60 episodes per arm on the ≥10-packet subset, each final flow written to a pcap
and scored by the actual Snort 2.9 binary (`real_snort_verdict`):

| Arm | Replica evasion | **Real Snort evasion** | Replica/real agreement |
|---|---|---|---|
| agent | 30.0% | **30.0%** | 100% (60/60) |
| random | 21.7% | **21.7%** | 100% (60/60) |

The replica is not flattering the agent: the agent's evasions survive the real
detector at exactly the rate the replica predicts.

## Throughput (corrects the plan's estimate)

The plan budgets **"2–3 hours"** for a 10,000-step run. Measured:

- 10,000 steps: **16.2 s** (PPO reports ~700–800 fps).
- Raw env rollout (random actions): **~10,000 steps/s** (200 episodes / 608
  steps in 0.1 s).
- The plan's estimate is ~1000x pessimistic. A 1,000,000-step run takes ~25 min,
  not an overnight.

The only real fixed cost is `load_malicious_pool()`, ~5 s per process start.

## More training does not help

A 1,000,000-step run (23 min, `models/ppo_packet_level_agent_1m.zip`) was
measured against the 10,000-step model on the same 5 seeds × 300 episodes:

| Model | Subset evasion | std | Per-seed |
|---|---|---|---|
| 10K steps | 30.87% | 1.29 | 28.3 / 31.3 / 31.3 / 32.0 / 31.3 |
| 1M steps | 30.60% | 1.29 | 28.3 / 30.7 / 31.7 / 32.0 / 30.3 |
| random | 21.60% | 1.42 | 23.0 / 22.0 / 22.7 / 21.3 / 19.0 |

100x the training budget moves the result by -0.27 pp — indistinguishable from
noise. The 10K-step model already sits at the ceiling this reward function
imposes. More training is not the lever; the environment is.

## Known limitations (these bound what the numbers mean)

1. **Three of the four action dimensions are inert.** `apply_actions` records
   `ttl_delta`, `fragmented`, and `overlap_offset`, but `replica_snort_verdict()`
   only reads `tot_pkts`, `tot_bytes`, `src_bytes`, `dur`, `proto`, `state`.
   The only action field that reaches the reward is `padding_bytes` (through
   `dsize`) plus the induced packet count. TTL, fragmentation, and overlap
   cannot earn or lose reward — the agent cannot learn to use them.
2. **Detection is evaluated on the partial flow after every packet.**
   `to_flow_features()` recomputes the aggregate over packets sent *so far*.
   This is what ends episodes at ~3 steps.
3. **Zero-packet flows are scored as evasions** (see above).
4. **The 6-rule ruleset is the whole adversary.** A rule change by another
   branch (adding `sid:3000007`–`3000011`) landed at 00:04:39 on 2026-09-25,
   after this model was trained (23:54:24). All numbers here were re-measured
   in a clean worktree at `f632370` so they are tied to the reward the model
   actually trained on. Re-measure after any ruleset change.

## Conclusion

Packet-level RL works and is worth ~10.7 pp over random on the flows where it
can act, verified against real Snort. It does not reach the plan's 95% target,
and it cannot be expected to while three of the four action dimensions do not
reach the reward function. The highest-value next step is not more training —
it is making TTL, fragmentation, and overlap actually influence the verdict.

**More training is confirmed useless here**: a 1M-step run scores 30.60% on the
subset vs 30.87% for the 10K-step run. The bottleneck is the reward function's
sensitivity to the action space, not the optimisation budget.
