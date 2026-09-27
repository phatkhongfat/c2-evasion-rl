# Fix the real-Snort evasion pipeline (5 defects, measured)

Date: 2026-09-27
Repo: `/root/.hermes/c2-evasion-rl`
Interpreter: `.venv/bin/python` (the only one with gymnasium + stable-baselines3 + scapy)

---

## Goal

Make an RL policy actually evade the real Snort binary (ET Open C2 ruleset) on the
Neris capture, by fixing the five measured defects that currently pin every policy
at 0% evasion.

## Current context / assumptions

### What was measured (all real, on this machine)

| Arm (24 real Neris flows, real Snort) | Detected | Evasion |
|---|---|---|
| baseline, unmodified real packets | 24/24 | 0% |
| `corrupt_all` (every payload packet, offset 0) | 0/24 | **100%** |
| shipped `ppo_real_snort_agent.zip` | 24/24 | 0% |
| 1200-step fine-tune in real-Snort env | 24/24 | 0% |
| `ppo_enhanced.zip` applied to real packets | 24/24 | 0% |

`corrupt_all` proves the 0-alert region is **reachable** — the task is not
impossible. Every learned policy fails, so the defects are in the harness.

### The five defects

1. **`_corrupted` bookkeeping lies.** `ai_agent/real_packet_env.py:268-269`
   ```python
   out = [p.copy() for p in packets]
   if aid == A_CORRUPT:
       self._corrupted.add(target)          # unconditional
   ```
   `target` is added even when that packet has no `Raw` layer. The 10-dim
   observation feature `coverage = len(self._corrupted) / n` (line 376) therefore
   rises every step while nothing is corrupted. Measured: the policy selects
   `CORRUPT` at packet index 1 on all 12 steps of all 32 flows and reports
   `_corrupted == {1}` — but index 1 carries no payload (payload is at 3 and 5).

2. **Action-space mismatch between checkpoint and env.** Saved model is
   `MultiDiscrete([11 6 3])`; the env builds `MultiDiscrete([32 6 3])` because
   `max_packets` is derived from the loaded data (lines 146-147). The policy can
   only reach packet indices 0..10. Verified:
   ```
   env action_space=MultiDiscrete([32  6  3])  model action_space=MultiDiscrete([11  6  3])
   ```

3. **Reward has no gradient.** `ai_agent/real_packet_env.py:443-446`
   ```python
   detected = alerts > 0
   reward = -float(alerts)
   if not detected:
       reward += REWARD_EVASION_BONUS
   ```
   `alerts` never falls while no payload packet is corrupted, so every action
   sequence scores identically. Nothing points at the payload packet.

4. **`EnhancedPacketLevelEnv` is scored by a Python replica, not Snort.**
   `ai_agent/enhanced_packet_level_env.py:100` imports
   `enhanced_snort_replica.enhanced_replica_snort_verdict`, which is 5 hand-written
   heuristics (TTL<10, TTL std>15, >30% frag, overlap>50, 2-of-3) plus the 6
   synthetic threshold rules in `snort_validation/snort_query_service.py:55-76`.
   The ET Open C2 ruleset is never consulted. Measured consequence: the policy's
   real-Snort evasion is 0% while its replica-reported evasion is 82%.

5. **TTL / fragmentation / overlap cannot affect any rule.** Measured on
   `snort_validation/et_open_c2/et_open_c2.rules`:
   ```
   ttl: 0     ip_ttl: 0     fragbits: 0     fragoffset: 0
   content: 21,374 / 21,374 alert rules
   ```
   All 21,374 rules match payload bytes. Mutating TTL/frag/overlap is
   **structurally** unable to evade. Applying the enhanced policy's own decisions
   to real packets (161 TTL changes, 294 pads, 0 frag flags) left 24/24 detected.

### Assumptions

- `.venv/bin/python` is the interpreter for every command below.
- `make test` runs `.venv/bin/python -m pytest tests/ -q`; there is no
  `pytest.ini`/`conftest.py`, tests add `ai_agent`/`snort_validation` to
  `sys.path` themselves.
- Snort 2.9.20 is on `PATH` at `/usr/sbin/snort`; conf is
  `snort_validation/et_open_c2/snort_et_c2.conf`.
- `corrupt_all` is an **upper bound only** — it destroys C2 semantics. It is a
  reachability probe, never a result to report as an attack.
- Existing models (`models/ppo_real_snort_agent.zip`, `models/ppo_enhanced.zip`)
  will become unusable once the action space changes. That is intended; they are
  being replaced, not preserved.

## Architecture / proposed approach

Fix the three correctness defects first (they are shared by both code paths and
provable by unit test without Snort), then make the payload action space honest
and rule-aligned, then point training at real Snort with a verdict cache. Keep
`RealPacketEnv` as the single env: it already batches real Snort calls and caches
verdicts by `(flow, corrupted set)` — the step-by-step `EnhancedPacketLevelEnv`
cannot afford one Snort call per episode and its replica scorer is defect 4, so
it is retired rather than repaired.

---

## Phase 0 — Safety net

### Task 0.1 — Confirm the suite is green before touching anything

```bash
cd /root/.hermes/c2-evasion-rl && make test
```
Expected: `32 passed` (counts: 4+10+3+8+3+2 = 30 collected across 6 files; if the
number differs, record the actual baseline in the commit message and move on).

### Task 0.2 — Add a shared test helper for a payload-bearing flow

Create `tests/_packets.py`:

```python
"""Shared scapy packet builders for env tests (no Snort, no pcap needed)."""
from scapy.all import IP, Raw, TCP


def tcp_flow(n_payload: int = 2, pad: int = 0):
    """A TCP flow: 3 handshake packets (no payload) then n_payload data packets.

    Data packets land at indices 3, 4, ... so a test can assert that corrupting
    index 1 (handshake) is a no-op while corrupting index 3 is not.
    """
    pkts = [
        IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80, flags="S"),
        IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=80, dport=1234, flags="SA"),
        IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80, flags="A"),
    ]
    for i in range(n_payload):
        payload = bytes([65 + i] * 100 + [0] * pad)
        pkts.append(IP(src="10.0.0.1", dst="10.0.0.2")
                    / TCP(sport=1234, dport=80, flags="PA") / Raw(load=payload))
    return pkts
```

Verify it imports and the payload indices are what the tests assume:

```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python -c "
import sys; sys.path.insert(0,'tests')
from _packets import tcp_flow
from scapy.all import Raw
p = tcp_flow(2)
print('n_pkts', len(p), 'payload_idx', [i for i,x in enumerate(p) if Raw in x])
"
```
Expected: `n_pkts 5 payload_idx [3, 4]`

Commit: `test: add shared payload-flow builder for env tests`

---

## Phase 1 — Fix the three correctness defects

### Task 1.1 — Failing test: corrupting a payload-free packet must not count

Create `tests/test_corrupted_bookkeeping.py`:

```python
"""`_corrupted` must only record packets that actually carry a payload.

Defect (measured): real_packet_env.py:268-269 added `target` to
`self._corrupted` unconditionally, so the observation's `coverage` feature rose
while nothing was mutated. The policy then reported progress it had not made.
"""
import sys
from pathlib import Path

import numpy as np
import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "tests"))

from _packets import tcp_flow  # noqa: E402
from real_packet_env import A_CORRUPT, A_PAD  # noqa: E402


@pytest.fixture
def env():
    """A RealPacketEnv with no pcap and no Snort: only `_corrupted` is needed.

    `object.__new__` deliberately bypasses `__init__`, which would otherwise
    load flows from disk and spawn a Snort service.
    """
    from real_packet_env import RealPacketEnv
    e = object.__new__(RealPacketEnv)
    e._corrupted = set()
    return e


def test_corrupt_on_handshake_packet_records_nothing(env):
    pkts = tcp_flow(2)                       # payload at indices 3, 4
    action = np.array([1, A_CORRUPT, 1])     # index 1 == handshake, no payload
    env._apply_mutation(pkts, action)
    assert env._corrupted == set(), (
        "corrupting a payload-free packet must not register as progress")


def test_corrupt_on_payload_packet_records_index(env):
    pkts = tcp_flow(2)
    action = np.array([3, A_CORRUPT, 1])
    out = env._apply_mutation(pkts, action)
    assert env._corrupted == {3}
    from scapy.all import Raw
    assert bytes(out[3][Raw].load)[:4] == bytes([13, 110, 207, 48])
```

Run it and watch it fail:
```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python -m pytest tests/test_corrupted_bookkeeping.py -q
```
Expected: `test_corrupt_on_handshake_packet_records_nothing` **FAILS**
(`assert {1} == set()`); the second test passes.

### Task 1.2 — Implement the fix

In `ai_agent/real_packet_env.py`, delete the early bookkeeping block (lines
268-269) and move it into the real `A_CORRUPT` branch. Replace:

```python
        out = [p.copy() for p in packets]
        if aid == A_CORRUPT:
            self._corrupted.add(target)

        if aid == A_PAD:
```

with:

```python
        out = [p.copy() for p in packets]

        if aid == A_PAD:
```

Then in the `elif aid == A_CORRUPT:` branch (currently starting at line 322),
replace:

```python
            p = out[target]
            if Raw in p:
                payload = bytearray(bytes(p[Raw].load))
                if payload:
```

with:

```python
            p = out[target]
            if Raw in p:
                payload = bytearray(bytes(p[Raw].load))
                if payload:
                    # Bookkeeping must mirror the mutation exactly: a packet
                    # with no payload cannot be corrupted, so recording it would
                    # make the observation's `coverage` feature lie.
                    self._corrupted.add(target)
```

Run the test:
```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python -m pytest tests/test_corrupted_bookkeeping.py -q
```
Expected: `2 passed`

Commit: `fix(env): only record corruption on packets that carry a payload`

### Task 1.3 — Failing test: the action space must not depend on loaded data

Append to `tests/test_corrupted_bookkeeping.py`:

```python
def test_action_space_is_data_independent():
    """The space must be a constant so a checkpoint reloads on any flow set.

    Defect (measured): max_packets was min(max flow length, ACTION_MAX_PACKETS),
    so a model trained when the longest flow had 11 packets could only reach
    indices 0..10 against an env that offered 0..31.
    """
    from real_packet_env import ACTION_MAX_PACKETS
    from real_packet_env import RealPacketEnv
    for cap, ds in [("botnet-capture-20110811-neris", "stratosphere"),
                    ("botnet-capture-20110819-bot", "ctu13")]:
        e = RealPacketEnv(n_flows=8, capture=cap, dataset=ds)
        assert e.action_space.nvec[0] == ACTION_MAX_PACKETS, (
            f"{cap}: space width {e.action_space.nvec[0]} != {ACTION_MAX_PACKETS}")
```

```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python -m pytest tests/test_corrupted_bookkeeping.py::test_action_space_is_data_independent -q
```
Expected: **FAILS** for `botnet-capture-20110819-bot` with
`space width 32 != 32` is not the failure — the failure will be on whichever
capture's longest flow is under 32; if both happen to be 32, the test passes and
you should still make the change in Task 1.4 for determinism, noting it in the
commit.

### Task 1.4 — Pin the action space

In `ai_agent/real_packet_env.py`, replace lines 146-147:

```python
        self.max_packets = int(min(
            max(len(p) for _k, p in self.flows), ACTION_MAX_PACKETS))
```

with:

```python
        # ALWAYS the constant, never derived from the loaded flows.  A data-
        # derived width changes the action space between runs, and a checkpoint
        # trained under one width silently loses the ability to address packets
        # beyond it (measured: model [11 6 3] against env [32 6 3] -> the policy
        # could only ever corrupt indices 0..10, and picked a payload-free one).
        self.max_packets = ACTION_MAX_PACKETS
```

Run the whole suite:
```bash
cd /root/.hermes/c2-evasion-rl && make test
```
Expected: all pass, count = baseline + 3.

Commit: `fix(env): pin action space to a constant width`

### Task 1.5 — Add a loud guard against checkpoint/env mismatch

In `ai_agent/real_packet_env.py`, add after the `self.action_space = ...`
assignment:

```python
    def assert_model_compatible(self, model) -> None:
        """Raise if a loaded checkpoint cannot address this env's packets.

        A silent mismatch is the worst failure mode here: the policy runs, the
        reward is computed, and the result is 0% with no indication that the
        agent could not reach the packets it needed.
        """
        want = tuple(int(x) for x in self.action_space.nvec)
        got = tuple(int(x) for x in model.action_space.nvec)
        if want != got:
            raise ValueError(
                f"action-space mismatch: env {want} vs model {got}. Retrain the "
                f"model against this env, or set ACTION_MAX_PACKETS to "
                f"{got[0]} before loading it.")
```

Wire it into the two eval scripts so the failure is impossible to miss.
In `ai_agent/eval_real_snort_agent.py`, after `model = PPO.load(...)` (line 41),
add `env.assert_model_compatible(model)`. Same in
`ai_agent/eval_cross_capture.py` after its `PPO.load` (line ~105).

Verify the guard fires on the stale checkpoint:
```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python -c "
import sys; sys.path.insert(0,'ai_agent')
from stable_baselines3 import PPO
from real_packet_env import RealPacketEnv
e = RealPacketEnv(n_flows=8, capture='botnet-capture-20110811-neris', dataset='stratosphere')
m = PPO.load('models/ppo_real_snort_agent.zip', device='cpu')
try:
    e.assert_model_compatible(m); print('NO GUARD TRIP -- investigate')
except ValueError as ex: print('guard fired:', ex)
"
```
Expected: `guard fired: action-space mismatch: env (32, 6, 3) vs model (11, 6, 3). ...`

Commit: `fix(eval): fail loudly on checkpoint/env action-space mismatch`

---

## Phase 2 — Make the payload action space honest and rule-aligned

### Task 2.1 — Failing test: the policy must be able to name a payload packet

Create `tests/test_payload_actions.py`:

```python
"""The action space must be able to address every corruptable packet.

Measured defect: on `botnet-capture-20110811-neris` payload sits at packet
indices 3 and 5, but the shipped policy only ever emitted index 1.  Even with a
correct width, a policy has no reason to prefer a payload packet unless the
observation makes payload location visible and the reward pays for coverage.
"""
import sys
from pathlib import Path

import numpy as np

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "tests"))

from _packets import tcp_flow  # noqa: E402


def test_observation_marks_payload_packets():
    """The mask must distinguish payload-bearing packets from handshake."""
    from real_packet_env import RealPacketEnv
    e = object.__new__(RealPacketEnv)
    e.obs_max_packets = 32
    e.max_mutations = 12
    e._mutations = 0
    e._corrupted = set()
    obs = e._obs(tcp_flow(2))
    # payload packet at index 3 must be distinguishable from index 0
    assert obs.shape == (42,)
    assert not np.allclose(obs[10:42][:3], obs[10:42][3]), (
        "payload packet index 3 looks identical to handshake index 0")
```

```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python -m pytest tests/test_payload_actions.py -q
```
Expected: **FAILS** — the current mask only encodes `_corrupted`, not payload
location, so all zero entries are identical.

### Task 2.2 — Extend the observation mask to encode payload location

The mask currently encodes only "already corrupted". Add a third state so the
policy can see where the payload is. In `ai_agent/real_packet_env.py`, replace the
mask construction (lines 377-381):

```python
        mask = np.zeros(self.obs_max_packets, dtype=np.float32)
        for i in range(min(len(packets), self.obs_max_packets)):
            mask[i] = 1.0 if i in self._corrupted else 0.0
```

with:

```python
        # 0.0 = no payload (cannot be corrupted), 0.5 = corruptable but clean,
        # 1.0 = already corrupted.  Without the 0.5 state the policy cannot tell
        # a handshake packet from a data packet, which is why it kept selecting
        # index 1 while the payload sat at 3 and 5.
        mask = np.zeros(self.obs_max_packets, dtype=np.float32)
        for i in range(min(len(packets), self.obs_max_packets)):
            if not corruptable(packets[i]):
                continue
            mask[i] = 1.0 if i in self._corrupted else 0.5
```

Add the helper next to `corrupt_targets`-style logic, near the top of the module
(after the action constants):

```python
def corruptable(pkt) -> bool:
    """True when this packet carries payload the mutator can overwrite.

    Must stay in lockstep with `_apply_mutation`'s A_CORRUPT branch, or the
    observation advertises packets the agent cannot actually corrupt.
    """
    from scapy.all import Raw
    return Raw in pkt and len(bytes(pkt[Raw].load)) > 0


def payload_indices(packets) -> list:
    """Indices of packets the agent can corrupt."""
    return [i for i, p in enumerate(packets) if corruptable(p)]
```

```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python -m pytest tests/test_payload_actions.py -q
```
Expected: `1 passed`

Commit: `feat(env): expose payload location in the observation mask`

### Task 2.3 — Give the reward a gradient

Append to `tests/test_payload_actions.py`:

```python
def test_reward_rewards_partial_coverage():
    """Partial coverage must score strictly better than none.

    Measured defect: reward was `-alerts + bonus` and `alerts` never fell while
    nothing was corrupted, so all action sequences tied at the same value.
    """
    from real_packet_env import coverage_reward

    none = coverage_reward(alerts=3, n_payload=2, n_covered=0)
    half = coverage_reward(alerts=3, n_payload=2, n_covered=1)
    full = coverage_reward(alerts=3, n_payload=2, n_covered=2)
    assert none < half < full, (none, half, full)


def test_reward_pays_evasion_bonus_only_at_zero_alerts():
    from real_packet_env import REWARD_EVASION_BONUS, coverage_reward
    assert coverage_reward(alerts=0, n_payload=2, n_covered=2) >= REWARD_EVASION_BONUS
    assert coverage_reward(alerts=1, n_payload=2, n_covered=2) < REWARD_EVASION_BONUS
```

```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python -m pytest tests/test_payload_actions.py -q
```
Expected: **FAILS** with `ImportError: cannot import name 'coverage_reward'`

### Task 2.4 — Implement `coverage_reward` and use it

In `ai_agent/real_packet_env.py`, add a module-level function after
`REWARD_EVASION_BONUS`:

```python
def coverage_reward(alerts: int, n_payload: int, n_covered: int) -> float:
    """Terminal reward: real alert count, shaped by how much payload was hit.

    `-alerts` alone gives no gradient when the agent has not yet found a payload
    packet (measured: every sequence scored identically and the policy stalled
    at 0%).  The coverage term is a pure function of state the env already
    tracks, so it adds no new measurement and cannot be gamed by the agent
    without actually corrupting payload.
    """
    cov = (n_covered / n_payload) if n_payload else 0.0
    r = -float(alerts)
    if alerts == 0:
        return r + REWARD_EVASION_BONUS
    return r + 2.0 * REWARD_EVASION_BONUS * cov
```

Then replace the reward block in `step()` (lines 443-446):

```python
            detected = alerts > 0
            reward = -float(alerts)
            if not detected:
                reward += REWARD_EVASION_BONUS
```

with:

```python
            detected = alerts > 0
            pay = payload_indices(self._cur_packets)
            reward = coverage_reward(alerts, len(pay),
                                     sum(1 for i in pay if i in self._corrupted))
```

```bash
cd /root/.hermes/c2-evasion-rl && make test
```
Expected: all pass.

Commit: `feat(env): shape the reward by payload coverage`

---

## Phase 3 — Point training at real Snort

### Task 3.1 — Retire the replica-scored env

`EnhancedPacketLevelEnv` is scored by `enhanced_snort_replica`
(`ai_agent/enhanced_packet_level_env.py:100`), which never consults ET Open C2 —
measured consequence: 82% replica evasion vs 0% real-Snort evasion. It also costs
one Snort call per episode if wired to the real detector, which the ~10 s rule
load makes unaffordable.

Add a deprecation header to `ai_agent/enhanced_packet_level_env.py` at the top of
the module docstring:

```python
DEPRECATED (2026-09-27).  This env scores with `enhanced_snort_replica`, a
Python heuristic that never reads the ET Open C2 ruleset.  Measured: a policy
trained here reports 82% evasion against the replica and 0% against the real
Snort binary on the same flows.  Use `RealPacketEnv` (real Snort verdicts,
batched, cached).  Kept only so existing reports remain reproducible.
```

Commit: `docs(env): mark the replica-scored env deprecated`

### Task 3.2 — Cache the baseline verdict per flow

`RealPacketEnv.step()` caches by `(flow_idx, corrupted_set)` but the *baseline*
(unmutated) verdict is recomputed by every caller. Add a cache so repeated evals
are cheap. In `ai_agent/real_packet_env.py`, add to `__init__` (after
`self._verdict_cache = {}`):

```python
        self._baseline_cache: Dict[int, int] = {}
```

and add a method after `service_stats`:

```python
    def baseline_alert_counts(self) -> Dict[int, int]:
        """Alert count for every flow, unmodified.  Cached: the baseline is a
        fixed property of the capture, and re-measuring it costs one Snort call
        per flow."""
        missing = [i for i in range(len(self.flows)) if i not in self._baseline_cache]
        if missing:
            items = [(self.flows[i][1], i) for i in missing]
            got = self._svc.alert_counts_chunked(items)
            for i in missing:
                self._baseline_cache[i] = int(got.get(i, 1))
        return dict(self._baseline_cache)
```

Verify on real Snort (expect 24/24 detected, matching the measured control):
```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python -c "
import sys; sys.path.insert(0,'ai_agent')
from real_packet_env import RealPacketEnv
e = RealPacketEnv(n_flows=24, capture='botnet-capture-20110811-neris', dataset='stratosphere')
b = e.baseline_alert_counts()
print('detected', sum(1 for v in b.values() if v>0), '/', len(b))
print('second call (should be cache-only):', e.baseline_alert_counts() == b)
"
```
Expected:
```
detected 24 / 24
second call (should be cache-only): True
```

Commit: `perf(env): cache per-flow baseline alert counts`

### Task 3.3 — Retrain with the fixed harness

The checkpoint must be rebuilt: the action space and observation changed, so
`models/ppo_real_snort_agent.zip` is now incompatible (Task 1.5's guard will say
so).

```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python ai_agent/train_real_snort_agent.py \
  --flows 24 --timesteps 4000 --eval-flows 24 --eval-every 512 2>&1 | tail -20
```
Expected shape of output (values will differ; the **baseline must be 24/24** and
evasion must move off 0 by the last eval):
```
[*] train env: 24 real flows from botnet-capture-20110819-bot
[eval @ 512] real-Snort evasion k/24 (x%)
...
[*] real-Snort evasion: last=x% best=y%
```
Runtime warning: ~10 s per Snort call; 4000 timesteps took 4020 s previously.
Budget ~2 hours, or reduce `--timesteps` and accept a weaker policy.

**If the last eval is still 0%, stop and do Task 3.4 before spending more compute.**

Commit: `train: retrain real-Snort agent on the fixed harness`

### Task 3.4 — Diagnostic if evasion is still 0%

Re-run the action distribution probe and read which indices the policy picks:

```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python -c "
import sys; sys.path.insert(0,'ai_agent')
from collections import Counter
import numpy as np
from stable_baselines3 import PPO
from real_packet_env import RealPacketEnv, payload_indices
e = RealPacketEnv(n_flows=16, capture='botnet-capture-20110811-neris', dataset='stratosphere')
m = PPO.load('models/ppo_real_snort_agent.zip', device='cpu')
idx, cov = Counter(), []
for i,(_k,pkts) in enumerate(e.flows):
    e._idx=i; e._cur_packets=[p.copy() for p in pkts]; e._mutations=0; e._corrupted=set()
    obs=e._obs(e._cur_packets)
    for _ in range(e.max_mutations):
        a,_=m.predict(obs,deterministic=True); idx[int(a[0])]+=1
        e._cur_packets=e._apply_mutation(e._cur_packets,a); e._mutations+=1
        obs=e._obs(e._cur_packets)
    pay=payload_indices(e._cur_packets); cov.append(len(e._corrupted & set(pay))/max(len(pay),1))
print('indices chosen:', idx.most_common(6))
print('mean coverage:', round(float(np.mean(cov)),3))
"
```
Read it:
- `mean coverage` near 0 → the policy still is not finding payload. Increase
  `ent_coef` in `ai_agent/train_real_snort_agent.py:105` from `0.01` to `0.05`
  (exploration) and retrain Task 3.3.
- `mean coverage` near 1 but evasion 0% → corruption is happening but Snort still
  alerts. That is the `capture-win13` situation: the alerting rule does not match
  payload bytes the agent can reach. Re-check with the control in Task 4.1.

---

## Phase 4 — Validation

### Task 4.1 — Beat the corrupt-all control

This is the acceptance test. `corrupt_all` is the trivial non-learned policy; the
agent must **match or beat** it, otherwise the training bought nothing.

Create `snort_validation/validate_real_snort_agent.py`:

```python
#!/usr/bin/env python3
"""Acceptance gate: the trained policy must beat the corrupt-all control.

corrupt_all (corrupt every payload packet at offset 0) is the trivial non-learned
policy and an UPPER BOUND on evasion for this action space -- it destroys C2
semantics, so it is a reachability probe, not an attack.  A learned policy that
does not match it has learned nothing, whatever its reward curve looked like.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
from stable_baselines3 import PPO

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))

from real_packet_env import RealPacketEnv, payload_indices  # noqa: E402
from snort_bandit import apply_corrupt_mask  # noqa: E402
from snort_batch_service import SnortBatchService  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--capture", default="botnet-capture-20110811-neris")
    ap.add_argument("--dataset", default="stratosphere")
    ap.add_argument("--flows", type=int, default=24)
    ap.add_argument("--model", default=str(REPO / "models/ppo_real_snort_agent.zip"))
    ap.add_argument("--out", default=str(REPO / "snort_validation/reports/real_snort_acceptance.json"))
    args = ap.parse_args()

    env = RealPacketEnv(n_flows=args.flows, batch_size=1, capture=args.capture,
                        dataset=args.dataset, max_mutations=12, seed=7)
    model = PPO.load(args.model, device="cpu")
    env.assert_model_compatible(model)
    flows, n = env.flows, len(env.flows)
    svc = SnortBatchService(batch_size=n)

    arms = {
        "baseline": [(pkts, i) for i, (_k, pkts) in enumerate(flows)],
        "corrupt_all": [
            (apply_corrupt_mask(pkts,
                                np.array([1.0 if j < len(pkts) else 0.0
                                          for j in range(len(pkts))])), i)
            for i, (_k, pkts) in enumerate(flows)],
    }

    agent = []
    for i, (_k, packets) in enumerate(flows):
        env._idx = i
        env._cur_packets = [p.copy() for p in packets]
        env._mutations = 0
        env._corrupted = set()
        obs = env._obs(env._cur_packets)
        for _ in range(env.max_mutations):
            a, _ = model.predict(obs, deterministic=True)
            env._cur_packets = env._apply_mutation(env._cur_packets, a)
            env._mutations += 1
            obs = env._obs(env._cur_packets)
        agent.append((env._cur_packets, i))
    arms["agent"] = agent

    res = {}
    for name, arm in arms.items():
        v = svc.verdicts_chunked(arm)
        ev = sum(1 for d in v.values() if not d)
        res[name] = {"evaded": ev, "flows": n, "evasion_pct": round(100 * ev / n, 2)}
        print(f"[*] {name:>12}: {ev}/{n} evaded ({100*ev/n:.1f}%)", flush=True)

    res["agent_beats_control"] = res["agent"]["evaded"] >= res["corrupt_all"]["evaded"]
    res["capture"] = args.capture
    res["dataset"] = args.dataset
    Path(args.out).write_text(json.dumps(res, indent=2))
    print(f"\n[*] agent beats corrupt-all control: {res['agent_beats_control']}")
    print(f"[+] {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

Run it:
```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python snort_validation/validate_real_snort_agent.py --flows 24
```
Expected (baseline and control reproduce the measurements this plan is based on):
```
[*]     baseline: 0/24 evaded (0.0%)
[*]  corrupt_all: 24/24 evaded (100.0%)
[*]        agent: <must be > 0>
[*] agent beats corrupt-all control: <bool>
```

Commit: `test(validation): add corrupt-all acceptance gate for real-Snort agent`

### Task 4.2 — Guard against the vacuous-evasion trap

The synthesized-pcap bridge produced `baseline 0/12` and a meaningless "100%".
Make that impossible to report again. Append to `tests/test_payload_actions.py`:

```python
def test_vacuous_evasion_is_rejected():
    """Evasion is only meaningful when the baseline is detected.

    Measured trap: materialising the enhanced policy's synthesized packet plan
    gave baseline 0/12, so every policy including a no-op 'evaded' 100%.
    """
    from validate_real_snort_agent import assert_non_vacuous
    assert assert_non_vacuous(baseline_detected=24, flows=24) is True
    try:
        assert_non_vacuous(baseline_detected=0, flows=12)
    except ValueError as ex:
        assert "vacuous" in str(ex).lower()
    else:
        raise AssertionError("a 0/N baseline must be rejected")
```

Add to `snort_validation/validate_real_snort_agent.py`:

```python
def assert_non_vacuous(baseline_detected: int, flows: int) -> bool:
    """A baseline that is not detected makes every evasion figure meaningless."""
    if baseline_detected <= 0:
        raise ValueError(
            f"vacuous measurement: baseline detected 0/{flows}. Every policy "
            f"would score 100% evasion. The synthesised pcaps do not trigger "
            f"Snort -- score real packets instead.")
    return True
```

Call it in `main()` right after the baseline arm is scored. Run:
```bash
cd /root/.hermes/c2-evasion-rl && make test
```
Expected: all pass.

Commit: `test: reject vacuous evasion measurements`

---

## Phase 5 — Report the correction

### Task 5.1 — Fix the stale summary and the contradicting README numbers

`snort_validation/reports/cross_capture_summary.json` (21:35) reports
`botnet-capture-20110810-neris` at 87.5% (21/24), but the per-capture report it
aggregates, `cross_capture_botnet-capture-20110810-neris.json` (21:55), says
16.67% (4/24). The summary predates its input. `README.md:21` and `README.md:104`
carry the 87.5% figure.

Re-generate the summary from the reports rather than hand-editing:

```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python snort_validation/aggregate_results.py \
  --cross-capture "snort_validation/reports/cross_capture_*.json" \
  --out snort_validation/reports/cross_capture_summary.json
```
Then read the regenerated file and confirm each `evasion_pct` matches its
per-capture report:
```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python -c "
import json, glob
summ = {r['capture']: r for r in json.load(open('snort_validation/reports/cross_capture_summary.json'))['summary']}
for f in sorted(glob.glob('snort_validation/reports/cross_capture_*.json')):
    if f.endswith('summary.json') or f.endswith('eval.json'): continue
    d = json.load(open(f))
    s = summ[d['capture']]
    ok = abs(s['evasion_pct'] - d['deterministic_pct']) < 0.01
    print(('OK  ' if ok else 'MISMATCH '), d['capture'], s['evasion_pct'], 'vs', d['deterministic_pct'])
"
```
Expected: three `OK` lines. If a `MISMATCH` appears, the aggregator still
recomputes instead of reading the measured integer — fix `rows_from_cross` in
`snort_validation/aggregate_results.py:75-88` to read
`d["deterministic_evaded"]` (the comment there already says it should).

Commit: `fix(reports): regenerate cross-capture summary from its source reports`

### Task 5.2 — Correct the README's generalisation claims

In `README.md`, replace the cross-capture generalisation claim with the measured
facts. At line 21, the current text:

```
- **Cross-capture generalisation degrades sharply**: the same policy on sibling captures scores **87.5%** (10/24 Neris flows) or **0%** (Windows capture).
```

Replace with:

```
- **The cross-capture spread is not a family effect.** All three evaluated captures
  (`botnet-capture-20110810-neris`, `botnet-capture-20110811-neris`, `capture-win13`)
  share MD5 `bf08e6b02e00d2bc6dd493e93e69872f` — one binary, three days. `capture-win13`
  scores 0% because all 29 usable flows are payload-free UDP/53 (0 corruptable packets),
  so the mutation action space is empty, not because its "family" differs.
```

Add a limitations bullet after `README.md:464`:

```
- **One malware family.** Only Neris has ever been evaluated; the other 12 MCFP
  captures on disk were never labelled (they are absent from
  `data/mcfp_snort_labeled.parquet`). Zeus, Emotet, Dridex, Trickbot, Qakbot and
  Ramnit have no pcaps, no flows and no runs in this repo — no claim about them
  is supported by the data here.
- **No PPO policy evades real Snort.** Measured on 24 real Neris flows with the
  real binary: baseline 24/24 detected, `corrupt_all` 0/24 detected (100% evasion,
  an upper bound that destroys C2 semantics), every trained checkpoint 0%.
```

Commit: `docs(readme): replace unsupported generalisation claim with measured facts`

### Task 5.3 — Final full verification

```bash
cd /root/.hermes/c2-evasion-rl && make test && \
  .venv/bin/python snort_validation/validate_real_snort_agent.py --flows 24
```
Expected: tests all pass; validation prints baseline 0/24 evaded, corrupt_all
24/24, and `agent beats corrupt-all control: True`.

Commit: `chore: final verification of the real-Snort evasion fix`

---

## Tests / validation

| Gate | Command | Pass condition |
|---|---|---|
| Unit suite | `make test` | all pass (baseline count + new tests) |
| Bookkeeping | `pytest tests/test_corrupted_bookkeeping.py -q` | corrupting payload-free packet records nothing |
| Action space | `pytest tests/test_corrupted_bookkeeping.py::test_action_space_is_data_independent -q` | width is `ACTION_MAX_PACKETS` on both captures |
| Mismatch guard | Task 1.5 snippet | raises `ValueError` on the stale checkpoint |
| Reward gradient | `pytest tests/test_payload_actions.py -q` | `none < half < full` |
| Real-Snort acceptance | `validate_real_snort_agent.py --flows 24` | `agent beats corrupt-all control: True` |
| Non-vacuity | `pytest tests/test_payload_actions.py::test_vacuous_evasion_is_rejected -q` | 0/N baseline rejected |
| Report consistency | Task 5.1 snippet | three `OK` lines |

## Risks, tradeoffs, and open questions

**Risks**

- **Compute is the binding constraint.** Real Snort costs ~10 s per call
  (4020 s for 4000 timesteps measured). A full retrain is ~2 h. Mitigation: the
  verdict cache in `step()` plus the new baseline cache; keep `--flows` small.
- **The acceptance gate may still fail.** `corrupt_all` reaches 100% by
  destroying payload content. A learned policy that corrupts *fewer* packets may
  legitimately score lower while being the more interesting result. If the agent
  lands at, say, 60% with 2 packets corrupted, that is a real finding, not a
  failure — report it against the control rather than hiding it.
- **Changing `ACTION_MAX_PACKETS` semantics invalidates every existing
  checkpoint.** Intended, but it means old numbers in `snort_validation/reports/`
  cannot be reproduced without the old code. Note this in the commit.
- **`capture-win13` cannot be fixed by any of this.** Its 29 flows have 0 payload
  bytes, so the action space is empty. It should be reported as out-of-scope for
  payload mutation, not as a 0% evasion result.

**Tradeoffs**

- Retiring `EnhancedPacketLevelEnv` discards the TTL/frag/overlap action space
  the thesis narrative is built around. The honest framing: those fields are
  unreachable against a `content:`-only ruleset (0 `ttl:`/`fragbits:`/
  `fragoffset:` rules measured), so aligning the action space with the detector's
  matching surface is itself the finding. Keeping the env for reproducibility is
  cheap; keeping it as a *result* is not defensible.
- Pinning the action width to 32 wastes policy output on unreachable indices on
  short flows. Acceptable: correctness beats parameter efficiency here.

**Open questions for the supervisor**

1. Is "action space must align with the detector's rule fields" a contribution,
   or does it narrow the problem to triviality?
2. Should `corrupt_all` be reported as an upper bound, or is a
   semantics-preserving evasion metric required before any number is publishable?
3. Is labelling 2–3 of the 12 unlabelled captures worth the compute, given each
   Snort pass over a full pcap costs minutes?
4. Which cross-capture number is authoritative for the thesis — the regenerated
   summary, or a rerun of all three captures on the fixed harness?
