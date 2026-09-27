#!/usr/bin/env python3
"""Gym env for the hidden-defender problem.

One episode = one flow = one query.  The agent sees 8 black-box statistical
features and picks one evasion mechanism; it never sees the ruleset.  Reward is
+10 for a valid evasion (no alert AND semantics preserved), -10 for breaking the
C2 command while dodging the alert, and -1 for still alerting.

Scoring uses RealRulesReplica by default (0.33 ms/flow, measured 8/8 agreement
with the real Snort binary).  Pass `real_snort=True` to score with the actual
binary instead (1340 ms/flow) -- used by the final verification, not by training.

The action space keeps only mechanisms that were MEASURED to be either valid
evaders or useful negatives, plus the structural Rbot finding (split cannot
break a pattern whose length equals the fragment unit, so prepend must be in
the space for the agent to have any chance on that family).
"""
from __future__ import annotations

import pickle
import sys
from pathlib import Path

import gymnasium as gym
import numpy as np
from gymnasium import spaces
from scapy.all import IP, Raw, TCP, UDP

REPO = Path("/root/.hermes/c2-evasion-rl")
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))

from real_packet_env import payload_indices  # noqa: E402
from snort_batch_service import SnortBatchService  # noqa: E402

CORPUS_PKL = REPO / "snort_validation/reports/hidden_defender_corpus.pkl"

# 12 mechanisms.  split8/16/24 and prepend4/8/12 measured; pad/reorder/ttl
# measured as 0/80 evaders (kept as informative negatives); corrupt8 breaks
# semantics (kept so the -10 penalty is observable); noop is the null action.
ACTION_NAMES = [
    "split8", "split16", "split24",
    "prepend4", "prepend8", "prepend12",
    "pad16", "reorder", "ttl",
    "corrupt8", "overlap8", "noop",
]
N_ACTIONS = len(ACTION_NAMES)

OBS_DIM = 8

REWARD_EVADE = 10.0
REWARD_BREAK_SEMANTICS = -10.0
REWARD_ALERTED = -1.0


def payloads_of(pkts):
    return [bytes(p[Raw].load) for p in pkts if Raw in p]


def semantics_intact(original_payloads, pkts) -> bool:
    """True only when the C2 command still reaches the endpoint intact.

    The earlier version checked `op in joined` per original segment.  That bar is
    too weak and it silently endorsed broken channels: prepend inserts junk in
    FRONT of every segment, so each original segment is still present as a
    substring while the reassembled stream no longer begins with the command.
    Measured on real Snort that turned prepend into 16/16 "evasion" that simply
    stopped being C2 traffic.

    For a stream protocol the only honest bar is byte equality of the
    reassembled stream, which is what fragmentation preserves by construction.
    """
    return b"".join(payloads_of(pkts)) == b"".join(original_payloads)


def apply_mech(pkts, mech: str):
    """Apply a mechanism.  Logic mirrors /tmp/mechanism_matrix.py exactly.

    Rewrites IP/UDP/TCP checksums where a payload changed -- without this Snort
    drops the packets and every mechanism would 'evade' for the wrong reason.
    """
    out = [p.copy() for p in pkts]
    pay_idx = payload_indices(out)

    if mech.startswith("split"):
        from fragment_ops import fragment_plan_to_packets, split_fragments
        off = int(mech[5:])
        rebuilt, i = [], 0
        for p in out:
            if Raw in p:
                payload = bytes(p[Raw].load)
                if 0 < off < len(payload):
                    frags = split_fragments(payload, off)
                    rebuilt.extend(fragment_plan_to_packets(out, frags, i))
                    i += 1
                    continue
            rebuilt.append(p)
            i += 1
        return rebuilt

    if mech == "overlap8":
        from fragment_ops import fragment_plan_to_packets, overlap_fragments
        rebuilt, i = [], 0
        for p in out:
            if Raw in p:
                payload = bytes(p[Raw].load)
                if 8 < len(payload):
                    frags = overlap_fragments(payload, 8)
                    rebuilt.extend(fragment_plan_to_packets(out, frags, i))
                    i += 1
                    continue
            rebuilt.append(p)
            i += 1
        return rebuilt

    if mech.startswith("pad"):
        n = int(mech[3:])
        for i in pay_idx:
            p = out[i]
            p[Raw].load = bytes(p[Raw].load) + bytes(n)

    elif mech.startswith("prepend"):
        n = int(mech[7:])
        for i in pay_idx:
            p = out[i]
            p[Raw].load = bytes(n) + bytes(p[Raw].load)

    elif mech.startswith("corrupt"):
        k = int(mech[7:])
        for i in pay_idx:
            p = out[i]
            pl = bytearray(bytes(p[Raw].load))
            for j in range(min(k, len(pl))):
                pl[j] = (j * 97 + 13) % 256
            p[Raw].load = bytes(pl)

    elif mech == "reorder":
        if len(out) >= 4:
            out[1], out[2] = out[2], out[1]

    elif mech == "ttl":
        for p in out:
            if IP in p:
                p[IP].ttl = 33

    elif mech == "noop":
        pass

    if mech not in ("reorder", "ttl", "noop"):
        for p in out:
            if Raw not in p:
                continue
            if IP in p:
                del p[IP].chksum
            if UDP in p:
                del p[UDP].chksum
            elif TCP in p:
                del p[TCP].chksum
    else:
        for p in out:
            if IP in p:
                del p[IP].chksum
    return out


def load_corpus(split: str = "train"):
    with open(CORPUS_PKL, "rb") as fh:
        data = pickle.load(fh)
    return data[split]


class HiddenDefenderEnv(gym.Env):
    """One flow per episode; the agent never observes the ruleset."""

    metadata = {"render_modes": []}

    def __init__(self, split: str = "train", real_snort: bool = False,
                 seed: int = 42, max_steps: int = 1):
        super().__init__()
        self._flows = load_corpus(split)
        self.real_snort = real_snort
        self._svc = SnortBatchService(batch_size=1) if real_snort else None
        self.max_steps = max_steps
        self._rng = np.random.default_rng(seed)

        self.action_space = spaces.Discrete(N_ACTIONS)
        self.observation_space = spaces.Box(low=0.0, high=1.0,
                                            shape=(OBS_DIM,), dtype=np.float32)
        self._idx = 0
        self._last = None

    # -- scoring ----------------------------------------------------------
    def _detected(self, flow, pkts) -> bool:
        """True when the defender fires.  Replica or the real Snort binary."""
        if self.real_snort:
            svc = self._svc
            assert svc is not None
            res = svc.verdicts_chunked([(pkts, 0)])
            return bool(res.get(0, True))
        return bool(flow["replica"].verdict(pkts))

    def score(self, flow, mech: str):
        """Return (evaded, semantics_ok, alert) for one (flow, mechanism)."""
        pkts = flow["packets"]
        orig = payloads_of(pkts)
        mut = apply_mech(pkts, mech)
        sem = semantics_intact(orig, mut)
        alert = self._detected(flow, mut)
        return (not alert), sem, alert

    # -- gym API ----------------------------------------------------------
    def reset(self, *, seed=None, options=None):
        super().reset(seed=seed)
        self._idx = 0
        return self._obs(), {}

    def _obs(self) -> np.ndarray:
        if self._idx >= len(self._flows):
            return np.zeros(OBS_DIM, dtype=np.float32)
        return np.asarray(self._flows[self._idx]["obs"], dtype=np.float32)

    def step(self, action: int):
        flow = self._flows[self._idx]
        mech = ACTION_NAMES[int(action)]
        evaded, sem, alert = self.score(flow, mech)

        if evaded and sem:
            reward = REWARD_EVADE
        elif evaded and not sem:
            reward = REWARD_BREAK_SEMANTICS
        else:
            reward = REWARD_ALERTED

        self._idx += 1
        terminated = self._idx >= len(self._flows)
        truncated = False
        info = {
            "alert": alert,
            "evaded": evaded,
            "semantics_ok": sem,
            "action": mech,
            "flow_id": flow["flow_id"],
        }
        obs = self._flows[self._idx]["obs"] if not terminated else self._obs()
        return np.asarray(obs, dtype=np.float32), reward, terminated, truncated, info

    def service_stats(self):
        return self._svc.stats() if self._svc else None
