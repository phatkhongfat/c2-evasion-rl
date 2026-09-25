# Real Snort in the Training Loop — Results

**Date:** 2026-09-25
**Question:** does putting the real Snort binary (ET Open C2) in the RL reward
loop produce a policy that evades it?

**Answer: yes, partially — 37.5% evasion vs 8.3% for a random policy and 0% for
an unmutated baseline. The gain is real but the learned policy depends on
sampling; its deterministic argmax collapses to 0%.**

## 1. Why the previous approaches could not answer this

| Approach | Reward source | Problem |
|---|---|---|
| `c2_evasion_env.py` + XGBoost judge | a surrogate model | agent evades the *model*, not the detector |
| `packet_level_env.py` + `snort_query_service.py` | a Python replica of hand-written rules | agent optimises the replica; 0.9999 in-sample vs 0.678 cross-capture |
| reconstructed pcaps from 6 aggregates | real Snort | synthesized packets carry no real payload → **0 alerts** (measured) |

The common failure: the reward was a *model* of the detector. This work makes
the reward the detector itself.

## 2. What was built

- `snort_validation/snort_batch_service.py` — resolves many flow verdicts per
  Snort invocation. Snort 2.9 spends **~10 s loading 21k ET rules per call,
  independent of pcap size** (measured: 5 packets = 9.9 s), so a per-flow call
  would cost 50k steps × 10 s ≈ **139 hours**. Batching + a verdict cache makes
  it affordable.
- `ai_agent/real_packet_env.py` — mutates **real CTU-13 packets** and scores
  them with real Snort.
- `ai_agent/train_real_snort_agent.py` — PPO against the real verdict.
- `ai_agent/eval_real_snort_agent.py` — clean evaluation of a saved model.

## 3. Bugs found and fixed (each measured, not guessed)

1. **Batched verdicts were wrong for positives.** `del p.chksum` only deletes
   the *IP* checksum, leaving a stale **UDP** checksum; Snort then discards the
   datagram and content rules never fire.

   | rewrite | alerts |
   |---|---|
   | original, untouched | **1** |
   | src IP rewritten, checksums kept | 0 |
   | **current batch method (before fix)** | **0** |
   | explicit per-layer checksum delete | **1** |

2. **Alert→flow mapping was direction-dependent.** Alert lines log the alerting
   packet's direction, so a server→client hit logs the query address as `dst`.
   Fixed by giving each query its own source address in `198.51.100.0/24` and
   parsing the id from the address rather than the port.
3. **The loader dropped flows** (`df.head(n_flows*6)` plus an early `break`):
   4 flows loaded where 24 were requested. Fixed → 8/32/64 all load correctly.
4. **Payload corruption was self-inverting.** `(b + 1 + 127) % 256` applied
   twice returns the original byte, so re-corrupting a packet *restored* it and
   evasion silently collapsed (k=4 → 66.7%, k=5 → **0%**). Fixed by assigning a
   deterministic byte (idempotent) → curve became monotonic.
5. **`step()` returned reward 0**, so PPO had no signal (`ep_rew_mean` stayed
   0). Fixed to return the real verdict on the terminal step.
6. **Binary −1/+1 reward gave no gradient** for partial progress; the policy
   collapsed to one pattern per flow (93.8% cache hit rate) and stalled at 0%.
   Fixed with `alert_counts_chunked`: the *alert count* is a dense, equally real
   signal that falls as coverage grows.
7. **A continuous `frac` rounded to a packet index** is a lossy interface for a
   combinatorial choice; PPO stalled at ~1.17 alerts. Replaced with
   `MultiDiscrete(packet_idx, action, strength)`.
8. **Space sizes derived from the loaded data** broke model reloading
   (`unexpected observation shape (21,) ... use (18,)`). Both spaces are now
   fixed constants.

## 4. The mechanism (why evasion is possible at all)

Measured on real flows:

- A rule matches **several packets per flow, each independently** (flow 0:
  packets 0 and 3 each raise the alert alone; flow 1: all 4).
- **Every matching packet must be corrupted** — evasion cost equals the number
  of matching packets: 7, 5, 2, 4, 3, 5 across flows 0–5.
- **Offset matters**: corrupting the payload start evades; offsets 0.25/0.5/0.75
  do not (the ET signatures match near offset 0).

Resulting evasion-vs-budget curve (16 real flows, real Snort):

| packets corrupted | evasion |
|---|---|
| 0–3 | 0.0% |
| 4–5 | 50.0% |
| 6–7 | 81.2% |
| 8 | **100.0%** |

So 100% evasion is achievable in principle; the RL problem is discovering
*which* packets to hit.

## 5. Training result

PPO, 24 real positive flows, 4096 timesteps, real Snort reward
(alert count + evasion bonus):

| Policy | Evaded | Rate |
|---|---|---|
| Unmutated baseline | 0/24 | 0.0% |
| Random actions | 2/24 | 8.3% |
| **Trained PPO (stochastic)** | **9/24** | **37.5%** |
| Trained PPO (deterministic argmax) | 0/24 | 0.0% |
| Oracle: corrupt all matching packets | 16/16 | 100.0% |

Training reward rose from −0.875 to ≈ −0.69 and peaked at **+1.25**, consistent
with a policy that evades a fraction of episodes.

### The honest caveat

The agent's evasion **depends on sampling**: 37.5% stochastic vs **0%**
deterministic. PPO learned a distribution that puts mass on good actions, but
the argmax action is wrong for most flows — unsurprising, because the correct
packet set differs per flow. Any deployment claim must therefore state which
policy is used, and a single stochastic evaluation is not evidence of a
reliable evader.

## 6. Cost

| Quantity | Value |
|---|---|
| Snort call | ~10 s (rule load dominates, size-independent) |
| Throughput with batching + cache | ~1–6 fps (256–2048 timesteps in ~5 min) |
| Cache effectiveness | 16 episodes → 8 Snort calls in a controlled test |

The fundamental limit is that each *novel* verdict costs ~10 s of rule loading.
A long-lived Snort process (or `snort -A unsock` with a Unix socket) would
remove it; that is the obvious next engineering step.

## 7. Reproduce

```bash
cd /root/.hermes/c2-evasion-rl
# evasion curve + mechanism
/tmp/jev-poc/venv/bin/python ai_agent/verify_real_env.py --flows 16
# correctness of batched verdicts vs per-flow ground truth
/tmp/jev-poc/venv/bin/python -m pytest snort_validation/test_snort_batch_service.py -v -s
# train
/tmp/jev-poc/venv/bin/python ai_agent/train_real_snort_agent.py --flows 24 --timesteps 4096
# evaluate (both sampling modes)
/tmp/jev-poc/venv/bin/python ai_agent/eval_real_snort_agent.py --flows 24
```

## 9. Follow-up: batched bandit (the deterministic collapse is fixed)

The step-by-step env above had two problems: ~10 s per episode (a Snort call per
terminal step) and a policy that only evaded 37.5% *when sampling*, 0% at argmax.

Root cause of the collapse: the action was a per-step choice, so argmax had to
commit to one packet at a time and got the per-flow combinatorial set wrong.
Reformulating as a **bandit** — one action = one complete mutation plan for one
flow — makes argmax well defined and lets ONE Snort call score a whole batch.

`ai_agent/snort_bandit.py` (REINFORCE, per-packet Bernoulli over "corrupt this
packet"):

| Policy | Evasion | Packets corrupted |
|---|---|---|
| Random | 0% | — |
| Corrupt-all | 100% | 32.00 |
| **Deterministic argmax** | **100%** | **5.17** |
| Stochastic (round 9) | 5.2% | 11.48 |

Two findings:

1. **The collapse is gone**: argmax went from 0% to 100%.
2. **The cost matters more than the algorithm.** At `--corrupt-cost 0.25` the
   argmax simply corrupted all 32 packets (`0.25 × 32 = 8 < 10` bonus), which is
   trivial and uninteresting. The cost must exceed `EVASION_BONUS / 32 = 0.3125`
   to make "corrupt everything" suboptimal. At 0.6 the agent reached 100% evasion
   while corrupting **5.17** packets.

The 5.17 independently cross-validates: the separate budget diagnostic measured
2–7 matching packets per flow (mean 4.3). The agent rediscovered the actual
matching-packet sets instead of brute-forcing.

Throughput: 768 scored plans in ~4 min, versus ~0.1 episodes/s for the
step-by-step env — because the batch amortises the 9.9 s rule load.

**Caveat:** 24 flows from a single capture. The stochastic policy is *worse* than
argmax here (5.2% vs 100%), which is the opposite of the step-by-step result and
suggests the stochastic exploration is simply too noisy at this batch size —
more rounds would be needed before reading anything into it.

## 10. Socket / resident mode: attempted, partially working

Goal: remove the ~9.9 s rule-load cost per verdict. Measured baseline: **1 packet
= 9.93 s, 120k packets = 11.8 s**, so the load dominates and batching only
amortised it (one call per batch).

### What does NOT work

`snort --pcap-dir <dir> --pcap-reset` is **not resident** in Snort 2.9 — it
scans the directory once and exits, so it removes nothing.

### What does work

`snort -i lo` (IDS mode on loopback) is genuinely resident: rules load once, then
frames replayed onto `lo` are inspected live, with fast-alerts written to a file.
`snort_validation/snort_resident_service.py` implements this and is **verified
correct: 12/12 agreement with the one-shot batch service** on a mixed set
(6 positives from `bot`, 6 negatives from `neris`, 9 detected).

### Six bugs found by measurement

1. **Double Ether.** Real CTU-13 packets already carry an Ether layer; wrapping
   them again produced `Ether/Ether/IP`, which Snort ignores — measured
   `double = 0 alerts`, `original preserved = 41`.
2. **Persistent fd returned nothing.** A long-lived `O_RDWR` descriptor on the
   alert file read back empty while reading the same bytes **by path** returned
   the full text.
3. **Fixed-sleep readiness.** Frames injected while Snort is still loading its
   21k rules are silently dropped. Replaced with an active readiness probe that
   injects a known-alerting DNS frame and waits for its alert line.
4. **The big one — ET rules throttle `by_src`.** Content rules carry
   `threshold: type limit, track by_src, count 1`, so a query source address
   reused inside the window is **throttled and produces no alert**. Measured:
   first injection of 24 flows → 35 alert lines covering all 24 flows; an
   immediate *second* injection of the same flows → **zero**. Ids must be unique
   for the whole run (unique `ip:port` per query, never reused).
5. **Off-by-stride.** `_uid_base` was incremented before the parser subtracted
   it, shifting every id out of range.
6. **Wrong injection socket.** scapy `L2socket.send` costs ~0.4 ms/pkt vs
   ~0.003 ms/pkt for a raw `AF_PACKET` socket; the per-packet Python build cost
   (7907 frames = 3.95 s to build, 0.02 s to send) is what made a batch slow.

### Honest status

The **standalone service is verified**. The **bandit integration is NOT
correct**: `snort_bandit.py --resident` still reports an impossible
`baseline detected 0/24` (unmutated flows are detected in file mode) and
implausible round-to-round swings, because all batches share one alert stream and
the uid stride does not isolate a batch's alerts from the previous batch's
still-in-flight frames.

Controls in the resident run are at least sane — random policy **0%** (matching
file mode) and corrupt-all **100%** — but the agent numbers from `--resident` are
**not trustworthy**. Use the per-batch service for bandit results; the file-mode
numbers (100% argmax at 5.17/32 packets) remain the reference.

Next step for resident mode: give each batch its own interface or stop/start
Snort between batches, or add a generation marker to the frames so a batch can
unambiguously separate its own alerts.

## 11. Open items / next steps

1. **Fix the resident/bandit integration** (see §10). The service itself is
   verified; the integration is not. Highest-value next step, and the only thing
   standing between here and ~100× cheaper experiments.
2. **More flows and more captures.** 24 flows from one capture is a proof of
   concept. The bandit's 5.17-packet result should be re-run cross-capture
   (as the surrogate work did) before any generalisation claim.
3. **Sweep `--corrupt-cost`** to trace the evasion-vs-payload-damage frontier.
   The interesting quantity is the minimum damage that still evades, and the
   current single point (0.6 → 5.17 packets) does not pin it down.


