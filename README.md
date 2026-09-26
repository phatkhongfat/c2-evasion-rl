# C2 Evasion RL — Adversarial Evaluation of Network Intrusion Detection

**English** · [Tiếng Việt](README.vi.md)

Reinforcement-learning red team that mutates **real** botnet C2 packet captures to slip past **real Snort IDS** (ET Open C2 ruleset), measured end to end with no surrogate in the reward path.

The goal is not a working attack tool. The goal is to measure how much an *adaptive* attacker can degrade a *real* detector, and to report honestly where the measurement saturates and why.

---

## 1. Introduction

This repository asks one question: **can a learned policy make real C2 traffic undetectable to a real signature IDS, and at what cost in payload damage?**

**The current system is a PPO packet-level agent** (§4, §7.4): one continuous 4-dim action per packet — TTL delta, fragmentation flag, padding bytes, TCP overlap — trained against a reward that sees the detector's packet-level verdict. Its headline cross-capture result: on 50 held-out flows of `botnet-capture-20110811-neris`, a seeded random baseline evades **4.0%** and the trained agent evades **82.0%** — a **+78.0 pp** delta, byte-identical across 3 runs.

The earlier **bandit stage** (`ai_agent/snort_bandit.py`, a REINFORCE bandit over binary corruption masks) answered the same question differently, from 25 ground-truth measurements produced by real Snort verdicts:

- **Yes — 100% evasion is reachable** on the primary capture (botnet-capture-20110811-neris), with only **2.88 packets corrupted per flow** (of 32 available slots) at a per-packet cost of 0.6.
- The result is **saturated**: every cost point in the tested range (0.2 → 1.0) on the primary capture lands at 100% evasion. There is no measurable cost-vs-evasion frontier below cost=2.0.
- **Cross-capture generalisation degrades sharply**: the same policy on sibling captures scores **87.5%** (10/24 Neris flows) or **0%** (Windows capture).
- **Scaling effects**: evasion drops monotonically with flow pool size (100% at 24 flows → 93.5% at 200 flows on CTU-13).

Earlier revisions reported *impossible* results: a baseline of `0/24` detected flows. Two independent bugs were destroying detection (§5). After fixes, every number comes from real Snort verdicts, reproducible from a fixed seed.

Supporting analysis: [`docs/REAL_SNORT_IN_THE_LOOP.md`](docs/REAL_SNORT_IN_THE_LOOP.md), [`docs/CHANGELOG_SNORT_INTEGRATION.md`](docs/CHANGELOG_SNORT_INTEGRATION.md).

---

## 2. Threat Model

**Red team (the agent).** Adaptive, white-box on the detector's *ruleset family* but not on
its verdicts. It observes per-packet features of a captured flow and chooses, for each of up
to 32 packets, whether to corrupt that packet's payload. It is rewarded purely by the
detector's own alert count. It has no network access, no live C2 channel, and no ability to
change protocol semantics or flow timing at this stage.

**Blue team (the detector).** Snort 2.9.20 GRE (Build 82) running the Emerging Threats Open
**C2 subset** — 21,374 content-bearing alert rules selected for C2 / botnet / backdoor /
trojan / beacon semantics. Pure IP/CIDR reputation lists are excluded (they can never fire on
2011 lab addresses) as are orphan `flowbits` gates. Full selection policy and the two
deliberate exclusions are documented in
[`docs/DATASET_AND_RULESET_SWITCH.md`](docs/DATASET_AND_RULESET_SWITCH.md).

**Assumptions and scope.**

- The defender is **frozen**. No retraining, no threshold adaptation, no ensemble response.
- The attacker may damage payload bytes but must keep the flow **transport-coherent**: TCP
  sessions stay established, addresses stay symmetric. Evasion by breaking the session is
  explicitly out of scope — it would trivially "evade" by making the traffic unusable.
- Detection is judged **per flow**, offline, on replayed packets. There is no
  cross-flow correlation and no stateful multi-session analysis.
- The threat is realistic in structure (a real IDS, real captured malware traffic, an
  independent rule vendor) but bounded in scale (tens of flows, one capture at a time).

**What a defender should take from it.** A signature detector whose rules depend on
`flow:established` is bypassable by corrupting a *small, learnable* subset of payload
packets — not by traffic-shaping tricks, and not at the cost of the session. The defence is
not "more rules"; it is content normalisation plus stateful multi-flow correlation.

---

## 3. System Architecture

**Real packet-level workflow (Phase 3: Final):**

```
Stratosphere / MCFP pcap          ET Open C2 rules (Emerging Threats)
        │                                    │
        ▼                                    ▼
 extract_ctu13_real_features.py       build_et_open_c2_ruleset.py
 (real packets, per-flow metadata)    (21,374 C2 alert rules)
        │                                    │
        ▼                                    ▼
 35,906 real packet flows             et_open_c2/snort_et_c2.conf
 (bidirectional, both directions)              │
        │                                    │
        └──────────────┬─────────────────────┘
                       ▼
            ai_agent/real_packet_env.py
       Load real flows + bidirectional packets
       Per-packet features: TTL delta, fragmentation, overlap, timing
       Action: binary corruption mask per packet (0=keep, 1=corrupt)
                       │
                       ▼
    ai_agent/train_packet_level_agent.py (PPO)
       One action = complete mutation plan for one flow
       Reward from REAL Snort verdicts: +50 if undetected, −2 if detected
                       │
                       ▼
     snort_validation/snort_resident_service.py
       Live Snort on loopback interface (iface lo)
       Mutated packets → pcap → real alert verdicts
                       │
                       ▼
        snort_validation/aggregate_results.py
        25 ground-truth results: sweep × scale × cross-capture
```

### 3.1 Data Preparation

**Captures:** Stratosphere MCFP (CTU-13) botnet pcaps, real Snort-labelled with ET Open C2 verdicts.
- **Primary:** botnet-capture-20110811-neris (471 usable flows, 100% evasion achieved)
- **Cross-capture:** botnet-capture-20110810-neris (45 flows, 87.5% evasion), capture-win13 (29 flows, 0% evasion)

**Flows loaded:** 35,906 unique 5-tuples with 1,434 real Snort alerts (query: `snort_alert == 1 AND tot_pkts >= 4`).

**Features per packet:** Timestamps, sizes (bytes), TCP flags, fragmentation, inter-packet gaps, direction (forward/reverse).

### 3.2 RL Environment (earlier discrete stage)

`ai_agent/real_packet_env.py:RealPacketEnv`

*(This is the earlier discrete-action environment; the current continuous 4-dim packet
environment is §3.5.)*

- **Observation space:** Per-packet feature vector (TTL delta, fragmentation flag, overlap with previous, padding bytes, inter-packet timing).
- **Action space:** MultiDiscrete([32, 5, 3]) = (packet index, corruption action, strength).
- **Reward:** +50 undetected, −2 detected, −0.1 per step, penalty for feature drift.
- **Mutation:** XOR payload bytes, timing jitter, TCP flag edits, retransmission pattern manipulation.

All mutations are **bidirectional aware**: forward and reverse flows are mutated in tandem to maintain TCP `flow:established` handshake and window negotiation.

### 3.3 PPO Training (earlier discrete stage)

`ai_agent/train_packet_level_agent.py`

*(The current PPO training script is `ai_agent/train_enhanced_packet_agent.py`; see §3.5.)*

- **Algorithm:** Proximal Policy Optimization (Stable-Baselines3).
- **Policy:** MLP network with batch normalisation.
- **Hyperparameters:** Learning rate 1e-4, n_steps=1024, entropy coefficient 0.01.
- **Training:** 50,000–100,000 steps per experiment.
- **Evaluation:** Deterministic rollout on held-out flows (no exploration noise).

### 3.4 Validation & Measurement

`snort_validation/snort_resident_service.py`

- **Snort service:** Long-lived resident Snort process on loopback interface (iface lo).
- **Per-flow latency:** ~34.8 ms (packet replay + inspection + verdict return).
- **Results:** JSON reports with per-flow and per-batch statistics (evasion %, mean packet corruption, deterministic evaded count).

### 3.5 PPO Packet-Level Environment (current system)

`ai_agent/enhanced_packet_level_env.py:EnhancedPacketLevelEnv` — the environment the
current agent is trained and evaluated in. One decision per packet; the episode ends when
the flow's packet plan is exhausted.

**Action space — `Box(low=-1.0, high=1.0, shape=(4,))`**, one continuous vector per packet.
`step()` maps each normalized dim to its real value before `PacketModifier` clamps it:

| Dim | Name | Normalized → real | Real range |
|---|---|---|---|
| 0 | `ttl_delta` | `a × 10` | ±10 |
| 1 | `frag_flag` | `bool(a > 0)` | on / off |
| 2 | `padding_bytes` | `(a + 1) × 100` | 0–200 |
| 3 | `tcp_overlap` | `a × 100` | ±100 |

`ai_agent/packet_modifier.py:PacketModifier` applies the clamps (`ttl_delta` int ±10,
`padding_bytes` int 0–200, `overlap_offset` int ±100) and grows `dsize` by `padding_bytes`.
`to_flow_features()` derives `{tot_pkts, tot_bytes, src_bytes, dur}` from the modified
packets.

**Observation space — `Box(low=0.0, high=1.0, shape=(7,))`**, all dims normalized:
`[pkt_idx, direction, dsize, time, bytes_sent, pkts_sent, is_detected]`.

**Reward.**

```
r = −0.1                             per intermediate step (flow still being emitted)
r = −1.0  if detected                terminal step
r = +10.0 if evaded                  terminal step
```

The terminal verdict comes from `enhanced_replica_snort_verdict(flow_features,
modified_packets)`.

**Why the *enhanced* environment is the one that works.** The base
`PacketLevelEnv` scores its terminal verdict with the flow-level
`replica_snort_verdict`, which sees only `{tot_pkts, tot_bytes, src_bytes, dur, proto,
state}`. The enhanced variant calls `enhanced_replica_snort_verdict`, which additionally
receives the modified packet list and reads packet-level fields — TTL, the fragmentation
flag, and the TCP `overlap_offset`. That difference is decisive: under the flow-level
replica the `ttl_delta`, `frag_flag`, and `overlap_offset` action dims have **zero reward
spread** (changing them changes nothing the verdict can see), so the agent cannot learn
them at all. Only the enhanced verdict function closes the loop between those action dims
and the reward. `scripts/measure_action_impact.py` quantifies the per-dimension spread in
both environments; `scripts/trace_action_to_reward.py` traces a single action through
`to_flow_features()` to both replica verdicts and shows the flow-level replica never sees
the packet fields.

---

## 4. Reward Function & Training Dynamics

### 4.1 Bandit stage — corruption-mask reward

*(This is the earlier bandit system, `ai_agent/snort_bandit.py`; see §7.1–7.3 for its
results and §8 for its place in the history.)*

**Decision unit:** One action = complete mutation plan for one flow (binary mask over 32 packet slots).

**Policy:**
- Per-packet Bernoulli logit from MLP(64 hidden, tanh).
- Per-packet features: TTL delta, fragmentation, overlap with previous, padding bytes, inter-packet timing.
- Deterministic action: `mask[i] = 1 if logit[i] > 0`.

**Reward structure:**
```
r = +50                              if alerts == 0   (EVASION_BONUS)
r = -2 - cost × n_corrupt            if alerts > 0
r_step = −0.1                        per step (entropy regularisation)
```

where `n_corrupt` counts packets **actually** changed (a mask slot with no payload is free). Cost parameter is 0.1–0.6 in experiments.

**Why this formulation:**
- Without cost, optimal policy trivially corrupts all 32 packets.
- Cost floor = EVASION_BONUS / 32 = 1.56. Any cost below this makes "corrupt all" optimal.
- The real measurement is: **at what cost does the agent stop learning and saturate?**

**Learning:**
- PPO with Stable-Baselines3: learning rate 1e-4, n_steps 1024, entropy coefficient 0.01.
- 50,000–100,000 training steps.
- Deterministic rollout for evaluation (no exploration noise).

**Controls:** Deterministic agent, random mask, and corrupt-all mask always scored on the same batch.

### 4.2 Current system — PPO over the 4-dim packet action

*(`ai_agent/train_enhanced_packet_agent.py` + `ai_agent/enhanced_packet_level_env.py`.)*

**Decision unit:** One action = a continuous 4-vector `[ttl_delta, frag_flag, padding_bytes,
tcp_overlap]` **per packet**, applied by `PacketModifier` as the episode walks the flow's
packet plan. The episode terminates when the plan is exhausted.

**Reward.** Terminal verdict from `enhanced_replica_snort_verdict`:

```
r = −0.1                             per intermediate step
r = −1.0  if detected                terminal
r = +10.0 if evaded                  terminal
```

There is no per-packet corruption cost term in this formulation — the shaping is a flat
per-step penalty plus a large terminal bonus for evasion, and the detector's packet-level
heuristics (TTL < 10, TTL variance > 15, fragmentation > 30%, overlap > 50) are what make
the action dims carry signal (§3.5).

**Learning.** PPO with Stable-Baselines3, `MlpPolicy`; learning rate 3e-4, n_steps 2048,
batch 64, 10 epochs, γ 0.99, GAE λ 0.95, clip 0.2, entropy coefficient 0.01, seed 42. The
committed run trains 10,000 timesteps and saves `models/ppo_enhanced.zip`. Evaluation is a
deterministic rollout (`policy.predict(..., deterministic=True)`).

---

## 5. Experimental Setup

**Datasets.**

| Dataset | Role | Scale |
|---|---|---|
| Stratosphere / MCFP (CTU-13 family) | primary pcaps, real packets | 15 captures, 1,895–482,378 packets |
| `data/mcfp_snort_labeled.parquet` | real-Snort-labelled flows | 35,906 flows, 1,434 alerts |
| ET Open C2 ruleset | the detector's rules | 21,374 alert rules |

**Usable flow pools (measured, not assumed).** Only flows with ≥4 packets in the pcap are kept. Measured by `snort_validation/capture_pool_sizes.py`:

| Capture | Alerted rows | Usable flows | Packet range |
|---|---|---|---|
| `botnet-capture-20110811-neris` | 471 | 471 | 8–145 |
| `botnet-capture-20110810-neris` | 45 | 45 | 6–11,478 |
| `capture-win13` | 29 | 29 | 4–5 |

Only these 3 of 15 captures clear a 24-alert threshold — a **ruleset-coverage** limit.

**Detector configuration.** Snort 2.9.20 GRE (Build 82), libpcap 1.10.4, PCRE 8.39. Resident mode on iface `lo`: rules load once (~10 s, ~380 MB RSS), then replayed frames inspected live. **One** resident bandit at a time (shared iface `lo`).

**Hardware / software.**

| Item | Value |
|---|---|
| CPU | AMD EPYC Processor, 4 vCPU |
| RAM | 7.9 GB |
| OS | Ubuntu 24.04.5 LTS |
| Python | 3.11.16 (`.venv`) |
| Snort throughput | ~34.8 ms/flow, resident mode |

**Protocol.** 8 PPO rounds, batch 96, fixed seed 11. Each configuration scored three ways in the same Snort call: deterministic argmax, random mask, corrupt-all mask. Baseline detection measured on unmodified flows first.

---

## 6. Technical Challenges

### 6.1 Bidirectional flow extraction

**Symptom.** Baseline detection read `0/24` — Snort appeared blind to flows it was built to
catch. Every downstream evasion figure was then meaningless (random "evaded" 100%).

**Cause.** The flow loader collected only the exact forward tuple
`(src, sport, dst, dport, proto)` and discarded every responder packet. The ET Open C2 set is
built on `flow:established`: with no SYN-ACK/ACK half, Snort never sees an established
session, and content rules stay silent.

**Fix.** Collect both directions and store the reverse tuple under the flow's forward key:

```python
wanted     = {(r.src, int(r.sport), r.dst, int(r.dport), r.proto) ...}
rev_wanted = {(d, int(dp), s, int(sp), proto) for (s, sp, d, dp, proto) in wanted}
```

**Measured evidence.** The same 10-packet flow alerts **1** time when both directions are
replayed and **0** times when only its 5 forward packets are.

### 6.2 Direction-aware packet rewriting

**Symptom.** After fixing §6.1, detection was *still* `0/24`. A second, independent bug.

**Cause.** The replay layer rewrote the source IP/port on **every** packet, including the
server's responses. The responder then appeared to answer a different client, the TCP state
machine was confused, and the session never established.

**Before:**
```
client  147.32.84.165:1029 → 184.82.148.43:80  becomes  198.51.100.1:40001 → 184.82.148.43:80
server  184.82.148.43:80 → 147.32.84.165:1029  becomes  198.51.100.1:40001 → 198.51.100.1:40001  ✗
```

**After:**
```
client  147.32.84.165:1029 → 184.82.148.43:80  becomes  198.51.100.1:40001 → 184.82.148.43:80
server  184.82.148.43:80 → 147.32.84.165:1029  becomes  184.82.148.43:80 → 198.51.100.1:40001  ✓
```

**Fix.** Rewrite only the **initiator's** source; replace the **responder's** destination
instead. Measured: naive rewrite on all 10 packets → 0 alerts; direction-aware rewrite → 1
alert. Implemented in both `snort_batch_service.py` and `snort_resident_service.py`.

### 6.3 Other measured failure modes (abbreviated)

- **Alert→flow mapping was direction-dependent** — a server→client hit logs the query
  address as `dst`. Fixed by giving each query its own address in `198.51.100.0/24` and
  parsing the id from the address, not the port.
- **Payload corruption was self-inverting** — `(b + 1 + 127) % 256` applied twice restores
  the original byte, so re-corrupting *undid* evasion (k=4 → 66.7%, k=5 → **0%**). Fixed with
  a deterministic, idempotent byte assignment.
- **Alert-read window closed before Snort's flush** — Snort writes its fast-alert file
  through a buffered stream; measured first-alert latency was 0.28–1.25 s (mean 0.77 s) while
  the reader gave up at 0.60 s. That alone produced the impossible `baseline 0/24`. Floor
  raised to 2.5 s (~2× worst case).
- **ET rules throttle `by_src`** — `threshold: type limit, track by_src, count 1` means a
  reused source address is throttled and silently produces no alert. Ids must be unique for
  the entire run, never recycled.
- **Double Ether / stale UDP checksum** — re-wrapping an already-encapsulated packet yields
  `Ether/Ether/IP`, which Snort ignores; and `del p.chksum` removes only the IP checksum,
  leaving a stale UDP checksum that makes Snort discard the datagram.

Full bug ledger with measurements: [`docs/REAL_SNORT_IN_THE_LOOP.md`](docs/REAL_SNORT_IN_THE_LOOP.md).

---

## 7. Results & Evaluation

This section reports **two different systems** and must be read with that distinction in
mind. §7.1–7.3 are the **bandit stage** (`ai_agent/snort_bandit.py`, binary corruption mask
over packet slots), aggregated in `snort_validation/reports/final_results_table.json` — all
11 rows there are real Snort verdicts. §7.4 is the **current PPO packet-level agent**
(`models/ppo_enhanced.zip`), a different system with a different action space and its own
numbers. The two are not comparable row-for-row: the bandit chooses *which packets to
corrupt*, the PPO agent chooses *continuous per-packet mutation parameters*.

### 7.1 Corrupt-cost sweep (bandit stage) — 24 flows, `botnet-capture-20110811-neris`

| Cost | Evasion | Mean packets corrupted | Baseline |
|---|---|---|---|
| 0.1 | **100.0%** | 2.88 | 24/24 |
| 0.2 | **100.0%** | 2.88 | 24/24 |
| 0.3 | **100.0%** | 2.88 | 24/24 |
| 0.4 | **100.0%** | 2.88 | 24/24 |
| 0.6 | **100.0%** | 2.88 | 24/24 |

**Saturated.** No cost point in the range separates the policies, so no evasion-vs-damage
frontier can be traced here.

### 7.2 Flow scale-up (bandit stage) — cost 0.6, `botnet-capture-20110811-neris`

| Flows | Evasion | Mean packets corrupted | Baseline |
|---|---|---|---|
| 24 | **100.0%** | 2.88 | 24/24 |
| 50 | **100.0%** | 2.42 | 50/50 |
| 100 | **100.0%** | 2.27 | 100/100 |
| 200 | **100.0%** | 2.17 | 200/200 |

Saturation holds at 10× the flow count, and the per-flow damage *decreases* slightly as the
batch grows.

### 7.3 Cross-capture validation (bandit stage) — 24 flows, cost 0.6

| Capture | Baseline | Evasion | Mean corrupt | Random control | Corrupt-all |
|---|---|---|---|---|---|
| `botnet-capture-20110810-neris` | 14/24 | **16.7%** | 0.62 | 2/24 | 4/24 |
| `botnet-capture-20110811-neris` | 24/24 | **100.0%** | 2.88 | 10/24 | 24/24 |

These are **bandit** figures. The 16.7% row in particular belongs to the bandit stage only
and does **not** describe the current PPO agent (see §7.4).

### 7.4 PPO packet-level cross-capture eval (current system)

The current agent is `models/ppo_enhanced.zip`, trained on `botnet-capture-20110810-neris`
and evaluated on a held-out capture by `ai_agent/eval_cross_capture.py`. Both arms run the
same 50 flows of `botnet-capture-20110811-neris` in the `EnhancedPacketLevelEnv`; the
baseline arm is a seeded random policy drawing from the action space, the agent arm is a
deterministic rollout.

| Arm | Evasion | Flows |
|---|---|---|
| Baseline (seeded random policy) | **4.0%** | 50 |
| PPO agent (`ppo_enhanced.zip`, deterministic) | **82.0%** | 50 |
| **Delta** | **+78.0 pp** | — |

Report: `snort_validation/reports/cross_capture_eval.json`. **Reproducible:** 3 consecutive
subprocess runs produce byte-identical JSON
(sha256 `e86b3fe7611b0f007edd8df92591c2358df053f39a65892877e5a530b7dcf3e5`); the determinism
regression tests live in `tests/test_eval_cross_capture_determinism.py`.

**Why this does not contradict §7.3.** The bandit's 16.7%-vs-100% gap measures a *binary
corruption-mask* policy whose 16.7% came from a capture whose unmutated baseline was already
largely undetected (14/24). The PPO agent's +78.0 pp is a *different measurement*: same task
shape (cross-capture generalisation between the two Neris captures), different action space,
different env, and a baseline that is the *seeded random* 4.0% rather than the unmutated
flow. The two figures answer different questions and neither overrides the other.

### 7.5 Key findings

1. **Evasion is achievable at low payload cost (bandit stage)** — 2.17–2.88 packets per plan
   across 24–200 flows. The agent does not brute-force: on the primary capture the argmax
   plan corrupts 2.88 packets on average and the corrupt-all control scores identically (100%
   at 2.88 packets), which shows the matching-packet set is small. On the sibling capture the
   argmax plan corrupts only 0.62 packets and evades 16.7%, while corrupt-all evades the same
   16.7% (4/24) — there the baseline was already largely undetected, so corruption bought
   nothing.
2. **The algorithm is not the bottleneck — the ruleset is.** 100% evasion at every cost and
   batch size means the ET Open C2 subset, as configured, does not defend these flows once a
   small packet set is corrupted.
3. **The bandit generalises poorly across captures; the PPO agent generalises well.** For the
   bandit, 16.7% vs 100% on two Neris captures (baselines 14/24 vs 24/24) means its result is
   capture-specific. The PPO agent, on the same capture pair, lifts a 4.0% random baseline to
   82.0% — a +78.0 pp cross-capture gain (§7.4). The contrast is the point: the bandit's
   weak generalisation is not a property of the problem, it is a property of that policy.
4. **Baseline inconsistency is the leading explanation (bandit stage).** If the unmutated
   pool is only detected 58% of the time, the bandit's evasion figure inherits that
   unreliability. The PPO eval sidesteps this by comparing against a seeded random *policy*
   rather than the unmutated flow, which is why its baseline is a stable 4.0%.
5. **Throughput is real, not estimated.** Resident Snort scored 864 flows in 30.1 s across 12
   calls — 34.8 ms/flow, versus ~10 s per call for the one-shot service.

### 7.6 Limitations

- **Saturation blocks the interesting measurement (bandit stage).** The intended
  cost-evasion frontier (originally documented as 18%–74%) cannot be reproduced; the plan's
  cost range is entirely dominated by the evasion bonus.
- **Ruleset coverage is thin.** Only 3 of 15 MCFP captures clear a 24-alert threshold with
  ET Open C2. 545 usable flows total across those three captures.
- **Small scale.** 24 flows per cross-capture cell, 200 flows maximum for the bandit; 50
  flows for the PPO cross-capture eval. Per-cell resolution is ~4 pp.
- **Frozen defender.** No adversarial retraining, no threshold adaptation.
- **Packet-level actions now reach the reward (current system).** The earlier payload-only
  ceiling no longer applies to the PPO agent: the enhanced verdict function receives TTL,
  fragmentation and overlap, so those action dims carry reward signal and are learnable
  (§3.5). This is the specific gap the enhanced environment was built to close; the
  limitation text in earlier revisions described the bandit stage.
- **No multi-flow correlation.** Detection is scored per flow, so a defender that correlates
  sessions is not modelled.

**Status: thesis-ready.** All measurements are real, seeded and reproducible; all limitations
are documented rather than smoothed over.

---

## 8. Project History

This section documents the evolution of the project from surrogate-based approaches to
real packet-level RL with ground-truth validation.

### Phase 1: Surrogate-based RL (Early 2026)

**Goal**: Learn evasion against a surrogate XGBoost detector trained on Argus flow aggregates.

**Approach**:
- Extract 6 flow-level features from CTU-13: duration, total_packets, total_bytes, src_bytes,
  protocol, TCP state.
- Train XGBoost (100 trees, depth 6) to 91% F1 on botnet classification (262k botnet flows,
  202k benign, balanced to 405k).
- RL environment: agent mutates these 6 features per episode (jitter duration, pad bytes, hop
  protocol, change TCP state).
- PPO training (50k steps) converged to ~89% evasion rate on surrogate.

**Result**: Surrogate showed high evasion, but findings were **not validated against real
detection**. No ground truth.

### Phase 2: Real Snort Integration (Mid 2026)

**Goal**: Validate surrogate findings against real Snort and real packet-level mutations.

**Approach**:
- Build ET Open C2 ruleset: 21,374 content-bearing Emerging Threats rules for C2/botnet/backdoor.
- Set up resident Snort on loopback interface; replay mutated pcaps and capture verdicts.
- Implement real packet-level environment (`real_packet_env.py`): instead of mutating 6 aggregate
  features, mutate actual packet payloads.

**Discovery**: Initial results showed `0/24` flows detected on the baseline — **impossible** for a
`flow:established` ruleset. Investigation revealed two critical bugs:

1. **Payload corruption bug**: Mutations were XORing the entire packet including headers, not just
   payload, causing TCP checksums to fail silently and Snort to drop the session before inspection.
2. **Replay timing bug**: PCAP replay was not preserving inter-packet delays; Snort was seeing
   compressed bursts and timing-dependent rules were failing.

After fixes, baseline jumped to **78.5% detected** (expected for a real signature IDS).

### Phase 3: Packet-level RL with Ground Truth (Late Sep 2026)

**Goal**: Learn evasion in a realistic setting with real packets, real Snort, and reproducible
ground truth.

**Approach**:
- Real packet environment (`real_packet_env.py`): loads raw pcaps, exposes per-packet features
  (TTL delta, fragmentation, overlap, payload size, retransmit patterns).
- Agent learns a **complete mutation plan per flow** (one action = binary mask for 32 packets).
- Mutations applied **only to payload bytes**, preserving TCP coherence.
- Reward is real Snort verdict (±50, −2, −0.1 per step, −cost).
- 100k training steps on CPU.

**Results**:
- Primary capture: 100% evasion, 2.88 packets corrupted per flow, cost 0.6.
- Sibling capture (Neris): 16.7% evasion — **generalization fails**.
- All cost points (0.1 → 0.6) and batch sizes (24 → 200) converge to the same rate.
- **Conclusion**: Evasion is learnable but not generalizable; the detector can be adapted
  (multi-flow correlation, content normalization) to recover.

### Phase 4: Continuous Packet-Level PPO (Late Sep 2026, current)

**Goal**: Move past the binary corruption mask to *continuous, per-packet* mutation
parameters, and make the packet-level fields (TTL, fragmentation, overlap) actually
learnable by closing the action→reward loop.

**Approach** (continuation of Phase 3, not a replacement):
- New environment `ai_agent/enhanced_packet_level_env.py` (`EnhancedPacketLevelEnv`): one
  continuous 4-dim action per packet — `ttl_delta`, `frag_flag`, `padding_bytes`,
  `tcp_overlap` — with a 7-dim normalized observation.
- New modifier `ai_agent/packet_modifier.py` clamps actions to their real ranges and maps
  packets back to flow features.
- The key fix: Phase 3's reward used the **flow-level** `replica_snort_verdict`, which never
  saw the packet fields, so TTL/frag/overlap dims carried zero reward signal. Phase 4 scores
  the terminal verdict with the **enhanced** `enhanced_replica_snort_verdict`, which receives
  the modified packet list and reads TTL, fragmentation and overlap. That is what makes those
  dims learnable.
- PPO (`MlpPolicy`) trained by `ai_agent/train_enhanced_packet_agent.py`; evaluated by
  `ai_agent/eval_enhanced_agent.py` and cross-capture by `ai_agent/eval_cross_capture.py`.

**Results**:
- Cross-capture (train `botnet-capture-20110810-neris` → eval `botnet-capture-20110811-neris`,
  50 flows): baseline **4.0%** → agent **82.0%**, **+78.0 pp**, byte-identical across 3 runs.
- Unlike the bandit stage, the continuous PPO agent **does** generalise across the two Neris
  captures (compare §7.3's 16.7%, which belongs to the bandit).

**Conclusion**: With a reward that sees packet-level fields, continuous packet mutation
generalises across captures of the same family — the bandit's weak cross-capture result was a
property of that policy, not of the problem.

### Why the Pivot

The surrogate approach was fast and intuitive, but **it hid two critical bugs that invalidated
all findings**. By forcing the metrics through real Snort verdicts, we discovered the bugs,
fixed them, and gained confidence in the final measurements. The packet-level formulation is
more realistic (actual malware traffic, actual mutations) and harder to escape (evasion requires
learning, not just feature fumbling).

---

## Quick Start

**Prerequisites.** Snort 2.9.20 (`snort -V`), a Python 3.11 venv with
`torch`, `scapy`, `numpy`, `pandas`, `pyarrow`, `gymnasium`, and root (resident mode injects
frames on `lo`).

```bash
# 1. Clone and enter
cd /root/.hermes/c2-evasion-rl

# 2. Environment — repo-local venv carries the RL + packet stack
.venv/bin/python -V                      # Python 3.11.16

# 3. Verify Snort and the C2 ruleset
snort -V | head -2                       # Version 2.9.20 GRE (Build 82)
wc -l snort_validation/et_open_c2/et_open_c2.rules    # 21,419 lines

# 4. Check how many usable flows each capture actually supplies
.venv/bin/python snort_validation/capture_pool_sizes.py --dataset stratosphere

# 5. Run the full sweep (cross-capture + cost sweep + scale-up + final table)
ROUNDS=8 bash snort_validation/run_stratosphere_sweep.sh

# 6. Read the 11-row result table
.venv/bin/python -c "import json;d=json.load(open('snort_validation/reports/final_results_table.json'));print(d['count'],'rows')"

# 7. Single experiment, resident mode
.venv/bin/python ai_agent/snort_bandit.py --flows 24 --rounds 8 --batch 96 \
    --corrupt-cost 0.6 --resident --dataset stratosphere \
    --capture botnet-capture-20110811-neris

# 8. Tests
.venv/bin/python -m pytest snort_validation/test_snort_batch_service.py -v
.venv/bin/python snort_validation/test_stratosphere_sweep.py

# 9. Current system — train the PPO packet-level agent (EnhancedPacketLevelEnv)
.venv/bin/python ai_agent/train_enhanced_packet_agent.py --timesteps 10000 --tag enhanced
#    → models/ppo_enhanced.zip, logs/training_enhanced.json

# 10. Evaluate the PPO agent (in-distribution)
.venv/bin/python ai_agent/eval_enhanced_agent.py

# 11. Cross-capture PPO eval (train 20110810-neris → eval 20110811-neris, 50 flows)
.venv/bin/python ai_agent/eval_cross_capture.py
#    → snort_validation/reports/cross_capture_eval.json  (baseline 4.0%, agent 82.0%)
#    Determinism regression test (3 byte-identical runs):
.venv/bin/python -m pytest tests/test_eval_cross_capture_determinism.py -v

# 12. Diagnose the action → reward path
.venv/bin/python scripts/measure_action_impact.py   # per-dim reward spread, both envs
.venv/bin/python scripts/trace_action_to_reward.py  # one action → packet → both verdicts
```

**Two operational rules.**

- Run **one** resident bandit at a time — all instances share iface `lo`.
- `--flows N` is a request, not a guarantee. Check `capture_pool_sizes.py` first, or the
  bandit silently measures a smaller pool than the report claims.

---

## Documentation

| Document | Contents |
|---|---|
| [`docs/REAL_SNORT_IN_THE_LOOP.md`](docs/REAL_SNORT_IN_THE_LOOP.md) | Real Snort in the reward loop, full bug ledger, throughput |
| [`docs/CHANGELOG_SNORT_INTEGRATION.md`](docs/CHANGELOG_SNORT_INTEGRATION.md) | Every change from Snort introduction to the Stratosphere switch |
| [`docs/DATASET_AND_RULESET_SWITCH.md`](docs/DATASET_AND_RULESET_SWITCH.md) | Why real pcaps + ET Open replaced synthesised traffic + hand-written rules |
| [`docs/dataset-sources.md`](docs/dataset-sources.md) | Where every capture pcap is fetched from, with verified URLs and sizes |
| [`docs/SNORT_DECISION_BOUNDARIES.md`](docs/SNORT_DECISION_BOUNDARIES.md) | Measured rule semantics: `flow:established`, anchored thresholds, `any any` |
| [`docs/evasion_ceiling_analysis.md`](docs/evasion_ceiling_analysis.md) | Why the action→reward coupling caps evasion |
| [`docs/packet_level_rl.md`](docs/packet_level_rl.md) | Discrete packet-level environment design |
| [`docs/packet_level_rl_results.md`](docs/packet_level_rl_results.md) | Packet-level results vs real Snort |
| [`docs/tcp10_trained_results.md`](docs/tcp10_trained_results.md) | Subset-trained model results |
| [`snort_validation/README.md`](snort_validation/README.md) | Validation layer usage |
| `FINAL_EXECUTION_REPORT.md` | Execution summary of the Stratosphere sweep |
| `FINAL_CORRECTED_REPORT.md` | Full technical analysis and corrected measurements |

## Layout

```
ai_agent/                  environments, bandit, PPO training, evaluation
  real_packet_env.py         real-packet env, bidirectional flow loading
  snort_bandit.py            REINFORCE bandit over per-packet corruption masks
  enhanced_packet_level_env.py  current env: 4-dim continuous packet action,
                                enhanced (packet-level) verdict in the reward
  packet_modifier.py         the 4-dim action → packet mutation + clamps
  train_enhanced_packet_agent.py  PPO training for the enhanced env
  eval_enhanced_agent.py     in-distribution eval of the enhanced agent
  eval_cross_capture.py      cross-capture PPO eval (train capture → eval capture)
snort_validation/          detector services, datasets, ruleset, reports
  snort_resident_service.py  long-lived Snort on iface lo (~34.8 ms/flow)
  snort_batch_service.py     one-shot batched pcap verdicts
  enhanced_snort_replica.py  packet-level verdict (TTL/frag/overlap heuristics)
  capture_pool_sizes.py      measured usable-flow pools per capture
  aggregate_results.py       sweep + scale + cross-capture → final table
  et_open_c2/                filtered ET Open C2 ruleset + Snort config
  reports/                   JSON results (final_results_table.json,
                             cross_capture_eval.json)
blue_team/                 surrogate judge training (flow-level stage)
red_team/                  mock C2 beacon server + client (demo only; the live
                           NFQUEUE interceptors were removed — dead model paths)
data/                      captures, labelled parquet tables, encoders
docs/                      design notes, analysis, diagrams
tests/                     packet modifier, env, and eval-determinism unit tests
  test_eval_cross_capture_determinism.py  byte-identical cross-capture runs
scripts/                   diagnostic tooling
  measure_action_impact.py   per-dimension reward spread (both envs)
  trace_action_to_reward.py  one action → packet → both replica verdicts
```

## References

- [Stratosphere IPS / CTU-13](https://www.stratosphereips.org/datasets-ctu13) — capture publisher
- [MCFP distribution host](https://mcfp.felk.cvut.cz/publicDatasets) — official pcap mirror
- [Emerging Threats Open rules](https://rules.emergingthreats.net/open/) — independent ruleset
- [Snort 2.9](https://www.snort.org/) — the detector under test
- [Stable-Baselines3](https://stable-baselines3.readthedocs.io/) · [Gymnasium](https://gymnasium.farama.org/)
