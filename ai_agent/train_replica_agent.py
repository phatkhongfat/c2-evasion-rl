#!/usr/bin/env python3
"""Train PPO against the REAL ET Open C2 rules, at Python speed.

WHY THIS IS POSSIBLE NOW
------------------------
`snort_validation/real_rules_replica.py` parses the actual ET Open C2 rules that
fire on a capture and evaluates their `content:` byte patterns against real
packet payloads.  Measured against the real Snort binary on the same flows:

    arm             real det   replica det   agreement
    baseline          12/12       12/12       12/12  (100%)
    first_payload      1/12        1/12       12/12  (100%)
    all_payload        0/12        0/12       12/12  (100%)

So training against the replica optimises the REAL matching surface -- unlike the
old `enhanced_snort_replica` (5 heuristics + 6 hand-written rules), which scored
82% evasion while real Snort scored 0%.

Training is now ~milliseconds per step instead of ~10 s per Snort call, so the
policy can actually be trained to convergence.  The honest number still comes
from a real-Snort eval afterwards.

Usage:
    python ai_agent/train_replica_agent.py --capture botnet-capture-20110811-neris \
        --flows 64 --timesteps 20000
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path

import numpy as np
import gymnasium as gym
from gymnasium import spaces
from stable_baselines3 import PPO

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))

from real_packet_env import (  # noqa: E402
    ACTION_MAX_PACKETS, N_ACTIONS, OBS_MAX_PACKETS, REWARD_EVASION_BONUS,
    RealPacketEnv, payload_indices,
)
from real_rules_replica import RealRulesReplica  # noqa: E402


class ReplicaPacketEnv(gym.Env):
    """Same action/observation contract as RealPacketEnv, scored by the replica.

    Deliberately mirrors RealPacketEnv's spaces so a policy trained here can be
    evaluated by `RealPacketEnv` against the real binary without any shape or
    action-space mismatch (`assert_model_compatible` enforces it).
    """

    metadata = {"render_modes": []}

    def __init__(self, flows, replica: RealRulesReplica, max_mutations: int = 12,
                 seed: int = 42):
        super().__init__()
        self.flows = list(flows)
        self.replica = replica
        self.max_mutations = max_mutations
        self.rng = np.random.default_rng(seed)
        self.max_packets = ACTION_MAX_PACKETS
        self.obs_max_packets = OBS_MAX_PACKETS
        self.action_space = spaces.MultiDiscrete([self.max_packets, N_ACTIONS, 3])
        self.observation_space = spaces.Box(
            low=-5.0, high=5.0, shape=(10 + self.obs_max_packets,),
            dtype=np.float32)
        self._reset_state()

    def _reset_state(self):
        self._idx = 0
        self._cur = []
        self._mutations = 0
        self._corrupted: set = set()
        self._last_alerts = 0

    # -- observation: MUST match RealPacketEnv._obs ------------------------
    def _obs(self, packets) -> np.ndarray:
        from scapy.all import IP, TCP
        sizes, iats, flags = [], [], []
        last = None
        for p in packets:
            sz = len(bytes(p[IP].payload)) if IP in p else 0
            sizes.append(sz)
            t = float(getattr(p, "time", 0.0))
            if last is not None:
                iats.append(max(t - last, 0.0))
            last = t
            flags.append(int(p[TCP].flags) if TCP in p else 0)

        sizes_a = np.array(sizes, dtype=float) if sizes else np.zeros(1)
        iats_a = np.array(iats, dtype=float) if iats else np.zeros(1)
        n = max(len(packets), 1)
        coverage = len(self._corrupted) / n

        # 0.0 = no payload (uncorruptable), 0.5 = corruptable+clean, 1.0 = done
        mask = np.zeros(self.obs_max_packets, dtype=np.float32)
        pay = set(payload_indices(packets))
        for i in range(min(len(packets), self.obs_max_packets)):
            if i not in pay:
                continue
            mask[i] = 1.0 if i in self._corrupted else 0.5

        head = np.array([
            len(packets) / 20.0,
            sizes_a.mean() / 500.0,
            sizes_a.std() / 500.0,
            sizes_a.max() / 1500.0,
            len(np.unique(sizes_a)) / 10.0,
            iats_a.mean() / 1.0,
            iats_a.std() / 1.0,
            float(np.mean(flags)) / 255.0,
            self._mutations / max(self.max_mutations, 1),
            coverage,
        ], dtype=np.float32)
        return np.clip(np.concatenate([head, mask]), -5.0, 5.0)

    # -- mutation: identical semantics to RealPacketEnv._apply_mutation ----
    def _apply(self, packets, action):
        from scapy.all import IP, Raw, TCP, UDP
        action = np.asarray(action)
        pkt_idx, aid, strength_i = int(action[0]), int(action[1]), int(action[2])
        strength = strength_i / 2.0
        n = len(packets)
        target = int(np.clip(pkt_idx, 0, n - 1))
        out = [p.copy() for p in packets]

        if aid == 0:                                    # A_PAD
            pad = 1 + int(strength * 120)
            p = out[target]
            payload = bytes(p[Raw].load) if Raw in p else b""
            new = payload + bytes(pad)
            if Raw in p:
                p[Raw].load = new
            else:
                out[target] = p / Raw(load=new)
                p = out[target]
            if IP in p:
                del p[IP].chksum
            if UDP in p:
                del p[UDP].chksum
            elif TCP in p:
                del p[TCP].chksum
        elif aid == 1:                                  # A_SPLIT
            p = out[target]
            if Raw in p and len(bytes(p[Raw].load)) > 8:
                payload = bytes(p[Raw].load)
                cut = max(1, int(len(payload) * (0.2 + 0.6 * strength)))
                p[Raw].load = payload[:cut]
                tail = p.copy()
                if Raw in tail:
                    tail[Raw].load = payload[cut:]
                out.insert(target + 1, tail)
                for q in (p, tail):
                    if IP in q:
                        del q[IP].chksum
                    if UDP in q:
                        del q[UDP].chksum
                    elif TCP in q:
                        del q[TCP].chksum
        elif aid == 2:                                  # A_TTL
            p = out[target]
            if IP in p:
                p[IP].ttl = int(np.clip(64 + (strength - 0.5) * 40, 1, 255))
                del p[IP].chksum
        elif aid == 3:                                  # A_REORDER
            j = min(target + 1, n - 1)
            if j != target:
                out[target], out[j] = out[j], out[target]
        elif aid == 4:                                  # A_DROP
            if len(out) > 3:
                out.pop(target)
        elif aid == 5:                                  # A_CORRUPT
            p = out[target]
            if Raw in p:
                payload = bytearray(bytes(p[Raw].load))
                if payload:
                    self._corrupted.add(target)
                    k = max(1, int(len(payload) * (0.25 + 0.5 * strength)))
                    k = min(k, len(payload))
                    for i in range(k):
                        payload[i] = (i * 97 + 13) % 256
                    p[Raw].load = bytes(payload)
                    if IP in p:
                        del p[IP].chksum
                    if UDP in p:
                        del p[UDP].chksum
                    elif TCP in p:
                        del p[TCP].chksum
        return out

    # -- gym API ----------------------------------------------------------
    def reset(self, *, seed=None, options=None):
        if seed is not None:
            self.rng = np.random.default_rng(seed)
        self._reset_state()
        self._idx = int(self.rng.integers(0, len(self.flows)))
        self._cur = [p.copy() for p in self.flows[self._idx][1]]
        return self._obs(self._cur), {"flow_index": self._idx}

    def step(self, action):
        self._cur = self._apply(self._cur, action)
        self._mutations += 1
        terminated = self._mutations >= self.max_mutations
        reward = 0.0
        info = {}
        if terminated:
            alerts = self.replica.alert_count(self._cur)
            self._last_alerts = alerts
            pay = payload_indices(self._cur)
            cov = (len(self._corrupted & set(pay)) / len(pay)) if pay else 0.0
            reward = -float(alerts)
            if alerts == 0:
                reward += REWARD_EVASION_BONUS
            else:
                # Pay for real progress: fewer alerts than the baseline, plus
                # coverage.  Without this the agent has no gradient toward the
                # payload packets (measured: it stalled at 0% for 1200 steps).
                reward += 2.0 * REWARD_EVASION_BONUS * cov
            info = {"detected": alerts > 0, "evaded": alerts == 0,
                    "alerts": alerts, "coverage": cov}
        return self._obs(self._cur), reward, terminated, False, info


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--capture", default="botnet-capture-20110811-neris")
    ap.add_argument("--dataset", default="stratosphere")
    ap.add_argument("--flows", type=int, default=64)
    ap.add_argument("--timesteps", type=int, default=20000)
    ap.add_argument("--max-mutations", type=int, default=12)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default=str(REPO / "models/ppo_replica_agent.zip"))
    ap.add_argument("--report",
                    default=str(REPO / "snort_validation/reports/replica_training.json"))
    args = ap.parse_args()

    # Real flows, so the policy sees real packet structure.
    loader = RealPacketEnv(n_flows=args.flows, batch_size=1, capture=args.capture,
                           dataset=args.dataset, max_mutations=args.max_mutations)
    flows = loader.flows
    replica = RealRulesReplica.for_capture(args.capture, args.dataset)
    print(f"[*] {len(flows)} real flows, {len(replica.rules)} real ET rules")

    base_det = sum(1 for _k, pk in flows if replica.verdict(pk))
    print(f"[*] replica baseline: {base_det}/{len(flows)} detected")
    if base_det == 0:
        raise SystemExit(
            "vacuous: the replica detects nothing unmutated, so 'evasion' would "
            "be meaningless. Check firing_sids() for this capture.")

    env = ReplicaPacketEnv(flows, replica, args.max_mutations, args.seed)
    model = PPO("MlpPolicy", env, verbose=0, device="cpu", seed=args.seed,
                n_steps=256, batch_size=64, learning_rate=3e-4,
                gamma=0.95, ent_coef=0.02, tensorboard_log=None)

    t0 = time.time()
    model.learn(total_timesteps=args.timesteps)
    dur = time.time() - t0
    model.save(args.out)
    print(f"[+] saved {args.out} ({dur:.0f}s, {args.timesteps/max(dur,1):.0f} steps/s)")

    # deterministic eval, replica side
    evaded = 0
    idx_counts = Counter()
    covs = []
    for i, (_k, pkts) in enumerate(flows):
        env._reset_state()
        env._idx = i
        env._cur = [p.copy() for p in pkts]
        obs = env._obs(env._cur)
        for _ in range(env.max_mutations):
            a, _ = model.predict(obs, deterministic=True)
            idx_counts[int(a[0])] += 1
            env._cur = env._apply(env._cur, a)
            env._mutations += 1
            obs = env._obs(env._cur)
        if not replica.verdict(env._cur):
            evaded += 1
        pay = payload_indices(env._cur)
        covs.append(len(env._corrupted & set(pay)) / len(pay) if pay else 0.0)

    n = len(flows)
    rep = {"capture": args.capture, "dataset": args.dataset, "flows": n,
           "timesteps": args.timesteps, "seconds": round(dur, 1),
           "replica_baseline_detected": base_det,
           "replica_agent_evaded": evaded,
           "replica_agent_evasion_pct": round(100 * evaded / n, 2),
           "mean_coverage": round(float(np.mean(covs)), 3),
           "top_packet_indices": idx_counts.most_common(6),
           "model": args.out}
    Path(args.report).parent.mkdir(parents=True, exist_ok=True)
    Path(args.report).write_text(json.dumps(rep, indent=2))
    print(json.dumps(rep, indent=2))
    print(f"[+] report {args.report}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
