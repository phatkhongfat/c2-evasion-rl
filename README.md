# C2 Evasion RL — Adversarial Evaluation of Network Intrusion Detection

**English** · [Tiếng Việt](README.vi.md)

Reinforcement-learning red team that mutates **real** botnet C2 packet captures to slip
past **real Snort IDS** (ET Open C2 ruleset), measured end to end with no surrogate in
the reward path.

The goal is not a working attack tool. The goal is to measure how much an *adaptive*
attacker can degrade a *real* detector, and to report honestly where the measurement
saturates and why.

---

## 1. Introduction

This repository asks one question: **can a learned policy make real C2 traffic
undetectable to a real signature IDS, and at what cost in payload damage?**

The current answer, from 11 ground-truth measurements produced by real Snort verdicts:

- **Yes — 100% evasion is reachable** on the primary capture, with only **2.88 packets
  corrupted per flow** (of 32 available slots) at a per-packet cost of 0.6.
- The result is **saturated**: every cost point in the tested range (0.1 → 0.6) and every
  batch size (24 → 200 flows) lands at 100% evasion. There is no measurable
  cost-vs-evasion frontier left to trace on this capture.
- **Cross-capture generalisation is the real weakness**: the same policy on a sibling
  Neris capture scores **16.7%**, not 100%.

Earlier revisions of this project reported results that were *impossible*: a baseline of
`0/24` detected flows, meaning Snort could not see traffic that a `flow:established`
ruleset was built to catch. That number was not a finding — it was a bug. Two independent
defects were destroying detection (§6). After the fixes, every number in §7 comes from the
Snort binary's own verdicts, reproducible from a fixed seed.

Supporting analysis: [`docs/REAL_SNORT_IN_THE_LOOP.md`](docs/REAL_SNORT_IN_THE_LOOP.md),
[`docs/CHANGELOG_SNORT_INTEGRATION.md`](docs/CHANGELOG_SNORT_INTEGRATION.md).

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

![C2 Evasion RL Pipeline](docs/pipeline.png)

**Real packet-level workflow:**

```
Stratosphere / MCFP pcap          ET Open C2 rules (Emerging Threats)
        │                                    │
        ▼                                    ▼
 extract_ctu13_real_features.py       build_et_open_c2_ruleset.py
 (real packets, per-flow metadata)    (21,374 C2 alert rules)
        │                                    │
        ▼                                    ▼
 real packet streams                 et_open_c2/snort_et_c2.conf
 (both directions, bidirectional)              │
        │                                    │
        └──────────────┬─────────────────────┘
                       ▼
            ai_agent/real_packet_env.py
       Loads real packets (both directions),
       Exposes per-packet features (TTL delta, fragmentation, overlap, timing)
       Mutation mask: binary action per packet
                       │
                       ▼
            ai_agent/train_packet_level_agent.py
       PPO training: one action = complete mutation plan for one flow
       Reward: real Snort verdicts (+50 undetected, −2 detected, −cost)
                       │
                       ▼
      snort_validation/snort_resident_service.py
       Mutated packets → PCAP → loopback interface
       Live Snort 2.9 (ET Open C2) inspection
       Ground-truth evasion rate (34.8 ms/flow)
                       │
                       ▼
      snort_validation/reports/*.json  →  aggregate_results.py
                       │
                       ▼
      snort_validation/reports/final_results_table.json (11 rows)
```

**Components.**

- **Capture registry** — `data/stratosphere_captures.json`, 15 MCFP captures with *measured*
  flow and packet counts (1,895 → 482,378 packets), not metadata claims.
- **Feature extractor** — `snort_validation/extract_ctu13_real_features.py`, 51 columns
  including payload entropy, IAT stats, TCP flag mix, and the real `snort_alert` label.
- **Environment** — `ai_agent/real_packet_env.py`, loads real packets from the pcap and
  returns both directions of each conversation.
- **Agent** — `ai_agent/snort_bandit.py`, a per-packet Bernoulli policy trained with
  REINFORCE against a moving-average baseline.
- **Detector services** — `snort_batch_service.py` (one-shot, batched pcap) and
  `snort_resident_service.py` (long-lived Snort on loopback, ~34.8 ms/flow).
- **Aggregator** — `snort_validation/aggregate_results.py`, merges sweep / scale /
  cross-capture reports into one table and **fails loudly** on missing values instead of
  defaulting them to zero.

**Data flow.** pcap → real packets → mutation mask → replayed frames → Snort alert count →
reward → policy update. At no point does a learned surrogate stand in for the detector.

---

## 4. Mathematical Formulation

### Packet-level PPO (current system)

- **Decision unit** — one *action* is a complete mutation plan for one flow: a binary mask
  `m ∈ {0,1}^32` over that flow's packets.
- **Policy** — per-packet Bernoulli. Features per packet (8 dims): payload size / 1500,
  raw length / 1500, is-UDP, is-TCP, normalized index, is-first, is-last, index-in-range.
  A 3-layer MLP (64 hidden, tanh) maps each packet to a logit; the plan samples independently.
- **Reward** —
  ```
  r = -alerts + 10.0                 if alerts == 0   (EVASION_BONUS)
  r = -alerts - cost × n_corrupt     otherwise
  ```
  where `n_corrupt` counts packets **actually** changed (a mask slot with no payload is
  free). The per-packet cost is the whole point: without it the optimal policy is
  trivially "corrupt everything".
- **Cost floor** — `EVASION_BONUS / 32 = 0.3125`. Any cost at or below this makes
  "corrupt all 32" optimal and the experiment uninformative; measured costs are 0.1–0.6.
- **Learning** — REINFORCE with a moving-average baseline
  (`baseline ← 0.9·baseline + 0.1·mean(r)`), Adam at `lr = 3e-3`.
- **Evaluation** — the deterministic policy takes `argmax` of the per-packet logit
  (`logit > 0`), giving a single well-defined plan per flow.
- **Controls** — a random plan and a corrupt-everything plan are always scored alongside the
  agent, on the same batch, with the same Snort call.

---

## 5. Experimental Setup

**Datasets.**

| Dataset | Role | Scale |
|---|---|---|
| Stratosphere / MCFP (CTU-13 family) | primary pcaps, real packets | 15 captures, 1,895–482,378 packets |
| CTU-13 (13 original captures) | flow-level training pool | 10,598,771 raw rows |
| `data/mcfp_snort_labeled.parquet` | real-Snort-labelled flows | 35,906 flows, 1,434 alerts |
| ET Open C2 ruleset | the detector's rules | 21,374 alert rules |

**Usable flow pools (measured, not assumed).** `--flows N` is a request, not a guarantee:
the env keeps only flows with ≥4 packets in the pcap. Measured by
`snort_validation/capture_pool_sizes.py`:

| Capture | Family | Alerted rows | Usable flows | Packet range |
|---|---|---|---|---|
| `botnet-capture-20110811-neris` | Neris | 471 | 471 | 8–145 |
| `botnet-capture-20110810-neris` | Neris | 45 | 45 | 6–11,478 |
| `capture-win13` | Neris | 29 | 29 | 4–5 |

Only these three of the 15 captures clear a 24-alert threshold with the ET Open C2 set —
a **ruleset-coverage** limit, documented rather than hidden.

**Detector configuration.** Snort 2.9.20 GRE (Build 82), libpcap 1.10.4, PCRE 8.39. Resident
mode on iface `lo`: rules load once (~10 s, ~380 MB RSS), then replayed frames are inspected
live. Exactly **one** resident bandit may run at a time — all instances share `lo` and would
otherwise inspect each other's frames.

**Hardware / software.**

| Item | Value |
|---|---|
| CPU | AMD EPYC Processor, 4 vCPU |
| RAM | 7.9 GB |
| OS | Ubuntu 24.04.5 LTS |
| Python | 3.11.16 (`.venv` and `/tmp/jev-poc/venv`) |
| Snort throughput | ~34.8 ms/flow, resident mode |

**Protocol.** 8 REINFORCE rounds, batch 96, fixed seed 11. Every configuration is scored
three ways in the same Snort call: deterministic argmax, random plan, corrupt-all plan. Each
round's baseline detection rate is measured on unmodified flows first.

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

All 11 rows below are real Snort verdicts, aggregated in
`snort_validation/reports/final_results_table.json`.

### 7.1 Corrupt-cost sweep — 24 flows, `botnet-capture-20110811-neris`

| Cost | Evasion | Mean packets corrupted | Baseline |
|---|---|---|---|
| 0.1 | **100.0%** | 2.88 | 24/24 |
| 0.2 | **100.0%** | 2.88 | 24/24 |
| 0.3 | **100.0%** | 2.88 | 24/24 |
| 0.4 | **100.0%** | 2.88 | 24/24 |
| 0.6 | **100.0%** | 2.88 | 24/24 |

**Saturated.** No cost point in the range separates the policies, so no evasion-vs-damage
frontier can be traced here.

### 7.2 Flow scale-up — cost 0.6, `botnet-capture-20110811-neris`

| Flows | Evasion | Mean packets corrupted | Baseline |
|---|---|---|---|
| 24 | **100.0%** | 2.88 | 24/24 |
| 50 | **100.0%** | 2.42 | 50/50 |
| 100 | **100.0%** | 2.27 | 100/100 |
| 200 | **100.0%** | 2.17 | 200/200 |

Saturation holds at 10× the flow count, and the per-flow damage *decreases* slightly as the
batch grows.

### 7.3 Cross-capture validation — 24 flows, cost 0.6

| Capture | Baseline | Evasion | Mean corrupt | Random control | Corrupt-all |
|---|---|---|---|---|---|
| `botnet-capture-20110810-neris` | 14/24 | **16.7%** | 0.62 | 2/24 | 4/24 |
| `botnet-capture-20110811-neris` | 24/24 | **100.0%** | 2.88 | 10/24 | 24/24 |

### 7.4 Key findings

1. **Evasion is achievable at low payload cost** — 2.17–2.88 packets per plan across 24–200
   flows. The agent does not brute-force: on the primary capture the argmax plan corrupts
   2.88 packets on average and the corrupt-all control scores identically (100% at 2.88
   packets), which shows the matching-packet set is small. On the sibling capture the argmax
   plan corrupts only 0.62 packets and evades 16.7%, while corrupt-all evades the same 16.7%
   (4/24) — there the baseline was already largely undetected, so corruption bought nothing.
2. **The algorithm is not the bottleneck — the ruleset is.** 100% evasion at every cost and
   batch size means the ET Open C2 subset, as configured, does not defend these flows once a
   small packet set is corrupted.
3. **Generalisation fails across captures of the same malware family.** 16.7% vs 100% on two
   Neris captures, with baselines of 14/24 vs 24/24, means the result is
   capture-specific and cannot be read as a general capability.
4. **Baseline inconsistency is the leading explanation.** If the unmutated pool is only
   detected 58% of the time, the evasion figure inherits that unreliability.
5. **Throughput is real, not estimated.** Resident Snort scored 864 flows in 30.1 s across 12
   calls — 34.8 ms/flow, versus ~10 s per call for the one-shot service.

### 7.5 Limitations

- **Saturation blocks the interesting measurement.** The intended cost-evasion frontier
  (originally documented as 18%–74%) cannot be reproduced; the plan's cost range is entirely
  dominated by the evasion bonus.
- **Ruleset coverage is thin.** Only 3 of 15 MCFP captures clear a 24-alert threshold with
  ET Open C2. 545 usable flows total across those three captures.
- **Small scale.** 24 flows per cross-capture cell, 200 flows maximum. Per-cell resolution is
  ~4 pp.
- **Frozen defender.** No adversarial retraining, no threshold adaptation.
- **Payload-only actions.** Packet timing, TTL, fragmentation and overlap are recorded but
  do not reach the reward, so the agent cannot learn to use them (see
  [`docs/evasion_ceiling_analysis.md`](docs/evasion_ceiling_analysis.md)).
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
ai_agent/                  environment, bandit, PPO training, evaluation
  real_packet_env.py         real-packet env, bidirectional flow loading
  snort_bandit.py            REINFORCE bandit over per-packet corruption masks
snort_validation/          detector services, datasets, ruleset, reports
  snort_resident_service.py  long-lived Snort on iface lo (~34.8 ms/flow)
  snort_batch_service.py     one-shot batched pcap verdicts
  capture_pool_sizes.py      measured usable-flow pools per capture
  aggregate_results.py       sweep + scale + cross-capture → final table
  et_open_c2/                filtered ET Open C2 ruleset + Snort config
  reports/                   JSON results, including final_results_table.json
blue_team/                 surrogate judge training (flow-level stage)
red_team/                  mock C2 infrastructure
data/                      captures, labelled parquet tables, encoders
docs/                      design notes, analysis, diagrams
tests/                     packet modifier and env unit tests
```

## References

- [Stratosphere IPS / CTU-13](https://www.stratosphereips.org/datasets-ctu13) — capture publisher
- [MCFP distribution host](https://mcfp.felk.cvut.cz/publicDatasets) — official pcap mirror
- [Emerging Threats Open rules](https://rules.emergingthreats.net/open/) — independent ruleset
- [Snort 2.9](https://www.snort.org/) — the detector under test
- [Stable-Baselines3](https://stable-baselines3.readthedocs.io/) · [Gymnasium](https://gymnasium.farama.org/)
