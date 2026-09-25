#!/usr/bin/env python3
"""
Packet-level RL environment whose reward comes from REAL Snort.

WHY NOT THE OLD ENV
-------------------
``packet_level_env.py`` synthesizes flows from 6 aggregate numbers and scores
them with a Python *replica* of hand-written rules.  Two consequences:

* Synthesized packets carry no real payload, so content-based ET Open C2 rules
  can never fire -- measured: 0 alerts on reconstructed flows.
* The replica is a model of the ruleset, so the agent can overfit the model
  instead of the detector (the same failure the surrogate had: 0.9999
  in-sample, 0.678 cross-capture).

This environment mutates REAL CTU-13 packets and scores them with the real
Snort binary, so the reward is the detector's actual behaviour.

REWARD COST
-----------
Snort spends ~10 s loading 21k rules per invocation regardless of pcap size.
``SnortBatchService`` amortises that over a batch, so N=200 flows costs
~11.5 s total (~57 ms/flow) instead of 10 s/flow.  The env therefore collects
transitions and resolves them in batches via ``resolve_batch()``; ``step()``
returns a shaped interim reward and the authoritative verdict arrives when the
batch flushes.

Actions (all payload-preserving, so content rules keep seeing the same bytes
unless the agent explicitly corrupts them):

  0  padding_bytes   add padding to selected packets      (breaks size rules)
  1  split_chunks    split a payload into smaller segments (breaks DHT/P2P
                     length assumptions)
  2  ttl_shift       change TTL                           (no-op for these rules)
  3  reorder         swap two adjacent packets            (breaks thresholds)
  4  drop_segment    drop one packet                      (breaks threshold
                     counts / DHT request shape)

Usage:
    from real_packet_env import RealPacketEnv
    env = RealPacketEnv(n_flows=64)
    obs, info = env.reset()
    obs, r, term, trunc, info = env.step(env.action_space.sample())
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

import numpy as np
import gymnasium as gym
from gymnasium import spaces

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "snort_validation"))

from snort_batch_service import SnortBatchService  # noqa: E402

LABELED = REPO / "data" / "ctu13_snort_labeled.parquet"
CAPTURE_DIR = REPO / "data" / "stratosphere" / "CTU-13-Dataset"

# Actions
N_ACTIONS = 6
(A_PAD, A_SPLIT, A_TTL, A_REORDER, A_DROP, A_CORRUPT) = range(N_ACTIONS)

# Bonus added to the (negative) alert-count reward when Snort fires zero times,
# so "fully evaded" always outranks "fewer alerts but still detected".
REWARD_EVASION_BONUS = 10.0

# Fixed space sizes (independent of the loaded capture) so a saved model can be
# reloaded against any flow set without shape/action-space mismatches.
ACTION_MAX_PACKETS = 32
OBS_MAX_PACKETS = 32


def _capture_dir_for(capture: str) -> Optional[Path]:
    """Map a capture name to its extraction subdirectory."""
    for d in sorted(CAPTURE_DIR.glob("*")):
        if d.is_dir() and (d / f"{capture}.pcap").exists():
            return d
    return None


class RealPacketEnv(gym.Env):
    """Mutate real packets; reward from real Snort verdicts."""

    metadata = {"render_modes": []}

    def __init__(
        self,
        n_flows: int = 64,
        capture: str = "botnet-capture-20110819-bot",
        positives_only: bool = True,
        batch_size: int = 64,
        seed: int = 42,
        max_mutations: int = 8,
        snort_service: Optional[SnortBatchService] = None,
    ):
        super().__init__()
        self.n_flows = n_flows
        self.capture = capture
        self.positives_only = positives_only
        self.batch_size = batch_size
        self.max_mutations = max_mutations
        self.rng = np.random.default_rng(seed)

        self._svc = snort_service or SnortBatchService(batch_size=batch_size)

        self.flows: List[Tuple[Tuple, List]] = []
        self._load_flows()

        # Discrete per-packet control.  A continuous `frac` that is rounded to a
        # packet index is a lossy interface for what is really a combinatorial
        # choice ("corrupt these specific packets"), and measured PPO stalled at
        # ~1.17 alerts without ever reaching 0.  MultiDiscrete lets the agent
        # name the packet and the action directly.
        # Both spaces are FIXED so a saved model reloads on any flow set.
        # Deriving them from the loaded data made the env non-portable (a model
        # trained with max_packets=18 raised "unexpected observation shape" when
        # evaluated on a set with 21), and it also changed the action space,
        # which silently invalidates the network's output layer.
        self.max_packets = int(min(
            max(len(p) for _k, p in self.flows), ACTION_MAX_PACKETS))
        self.obs_max_packets = OBS_MAX_PACKETS
        self.action_space = spaces.MultiDiscrete(
            [self.max_packets, N_ACTIONS, 3])  # (packet_idx, action, strength)
        # observation: per-flow summary + mutation progress + coverage mask
        self.observation_space = spaces.Box(
            low=-5.0, high=5.0, shape=(10 + self.obs_max_packets,),
            dtype=np.float32)

        self._idx = 0
        self._mutations = 0
        self._cur_packets: List = []
        self._corrupted: set = set()
        self._pending: List[Tuple[List, int]] = []
        self._pending_keys: List[int] = []
        self._last_verdicts: Dict[int, bool] = {}
        self._episode_qid: Optional[int] = None
        self._verdict_cache: Dict[Tuple, int] = {}
        self._cache_hits = 0
        self._cache_misses = 0
        self._next_qid = 0

    # -- data -------------------------------------------------------------
    def _load_flows(self):
        import pandas as pd
        from scapy.all import IP, PcapReader, TCP, UDP

        if not LABELED.exists():
            raise FileNotFoundError(
                f"{LABELED} missing -- run build_real_snort_dataset.py first")

        df = pd.read_parquet(LABELED)
        df = df[df["capture"] == self.capture]
        if self.positives_only:
            df = df[df["snort_alert"] == 1]
        df = df[df["tot_pkts"] >= 4]
        if len(df) == 0:
            raise ValueError(f"no flows for capture {self.capture}")

        wanted = {(r.src, int(r.sport), r.dst, int(r.dport), r.proto)
                  for r in df.head(self.n_flows * 20).itertuples()}

        capdir = _capture_dir_for(self.capture)
        if capdir is None:
            raise FileNotFoundError(f"pcap for {self.capture} not found")
        pcap = capdir / f"{self.capture}.pcap"

        found: Dict[Tuple, List] = {}
        with PcapReader(str(pcap)) as rd:
            for pkt in rd:
                if IP not in pkt:
                    continue
                if TCP in pkt:
                    proto, layer = "tcp", TCP
                elif UDP in pkt:
                    proto, layer = "udp", UDP
                else:
                    continue
                key = (pkt[IP].src, int(pkt[layer].sport), pkt[IP].dst,
                       int(pkt[layer].dport), proto)
                if key in wanted:
                    found.setdefault(key, []).append(pkt)
            # no early break: keep scanning so short flows are not lost

        usable = [(k, v) for k, v in found.items() if len(v) >= 4]
        usable.sort(key=lambda kv: kv[0])
        self.flows = usable[: self.n_flows]
        if not self.flows:
            raise ValueError("no usable multi-packet flows loaded")
        self.n_loaded = len(self.flows)

    # -- mutation ---------------------------------------------------------
    def _apply_mutation(self, packets: List, action) -> List:
        from scapy.all import IP, Raw, TCP, UDP

        action = np.asarray(action)
        if action.shape == (3,) and action.dtype.kind in "iu":
            # MultiDiscrete: (packet_idx, action_id, strength)
            pkt_idx = int(action[0])
            aid = int(action[1])
            strength = float(action[2]) / 2.0
            n = len(packets)
            target = int(np.clip(pkt_idx, 0, n - 1))
            frac = target / max(n - 1, 1)
        else:
            # legacy continuous Box action (kept for the diagnostic scripts)
            aid = int(np.clip(action[0], 0, N_ACTIONS - 1e-3))
            frac = float(np.clip(action[1], 0.0, 1.0))
            strength = float(np.clip(action[2], 0.0, 1.0))
            n = len(packets)
            target = int(frac * (n - 1))

        out = [p.copy() for p in packets]
        if aid == A_CORRUPT:
            self._corrupted.add(target)

        if aid == A_PAD:
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

        elif aid == A_SPLIT:
            p = out[target]
            if Raw in p and len(bytes(p[Raw].load)) > 8:
                payload = bytes(p[Raw].load)
                cut = max(1, int(len(payload) * (0.2 + 0.6 * strength)))
                head, tail = payload[:cut], payload[cut:]
                p[Raw].load = head
                tail_pkt = p.copy()
                if Raw in tail_pkt:
                    tail_pkt[Raw].load = tail
                out.insert(target + 1, tail_pkt)
                for q in (p, tail_pkt):
                    if IP in q:
                        del q[IP].chksum
                    if UDP in q:
                        del q[UDP].chksum
                    elif TCP in q:
                        del q[TCP].chksum

        elif aid == A_TTL:
            p = out[target]
            if IP in p:
                p[IP].ttl = int(np.clip(64 + (strength - 0.5) * 40, 1, 255))
                del p[IP].chksum

        elif aid == A_REORDER:
            j = min(target + 1, n - 1)
            if j != target:
                out[target], out[j] = out[j], out[target]

        elif aid == A_DROP:
            if len(out) > 3:
                out.pop(target)

        elif aid == A_CORRUPT:
            # Overwrite bytes at the START of the payload.  Measured: the ET
            # content signatures (P2P DHT, TROJAN checkin) match near offset 0,
            # and corrupting at offset 0.25/0.5/0.75 does NOT evade while
            # offset 0 does.  `frac` therefore selects WHICH packet to hit
            # (see target above), not the byte offset -- conflating the two
            # made the action unable to evade a rule matching >1 packet.
            p = out[target]
            if Raw in p:
                payload = bytearray(bytes(p[Raw].load))
                if payload:
                    k = max(1, int(len(payload) * (0.25 + 0.5 * strength)))
                    k = min(k, len(payload))
                    # ASSIGN a deterministic byte, do NOT add a delta.
                    # Measured: `(b + 1 + 127) % 256` applied twice returns the
                    # original byte, so re-corrupting a packet RESTORES it and
                    # evasion silently collapses (k=4 -> 66.7%, k=5 -> 0.0%).
                    # Assignment is idempotent, so coverage is monotonic.
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
    def _obs(self, packets: List) -> np.ndarray:
        from scapy.all import IP, TCP, UDP

        sizes, iats, flags = [], [], []
        last = None
        for p in packets:
            sz = len(bytes(p[IP].payload)) if IP in p else 0
            sizes.append(sz)
            t = float(getattr(p, "time", 0.0))
            if last is not None:
                iats.append(max(t - last, 0.0))
            last = t
            f = 0
            if TCP in p:
                f = int(p[TCP].flags)
            flags.append(f)

        sizes_a = np.array(sizes, dtype=float) if sizes else np.zeros(1)
        iats_a = np.array(iats, dtype=float) if iats else np.zeros(1)
        n = max(len(packets), 1)
        # fraction of packets whose payload has already been corrupted: evasion
        # requires EVERY matching packet to be corrupted, so coverage is the
        # signal that tells the agent when it is done.
        coverage = len(self._corrupted) / n
        # per-packet mask: which packets still need corrupting.  Evasion needs
        # EVERY matching packet corrupted, so this is the actionable state.
        mask = np.zeros(self.obs_max_packets, dtype=np.float32)
        for i in range(min(len(packets), self.obs_max_packets)):
            mask[i] = 1.0 if i in self._corrupted else 0.0
        obs = np.array([
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
        return np.clip(np.concatenate([obs, mask]), -5.0, 5.0)

    def reset(self, *, seed=None, options=None):
        super().reset(seed=seed)
        self._idx = self.rng.integers(0, len(self.flows))
        _key, packets = self.flows[self._idx]
        self._cur_packets = [p.copy() for p in packets]
        self._mutations = 0
        self._corrupted = set()
        self._episode_qid = None
        return self._obs(self._cur_packets), {"flow_index": int(self._idx)}

    def step(self, action: np.ndarray):
        self._cur_packets = self._apply_mutation(self._cur_packets, action)
        self._mutations += 1

        # The Snort verdict is only needed ONCE per episode -- on the FINAL
        # mutation.  Queuing every intermediate step (as an earlier version
        # did) meant the batch never filled and each episode cost its own
        # ~10 s Snort call (measured: 0 fps).
        terminated = self._mutations >= self.max_mutations
        reward = 0.0
        info = {"pending": len(self._pending)}

        if terminated:
            # Resolve THIS episode's verdict so the reward is never lost, but
            # serve it from a cache keyed by (flow, corrupted packet set).
            # A Snort call costs ~10 s of rule loading regardless of pcap size,
            # so caching is what makes per-episode rewards affordable: the
            # agent revisits the same (flow, corruption) combinations and those
            # repeat visits cost nothing.
            cache_key = (int(self._idx), tuple(sorted(self._corrupted)))
            if cache_key in self._verdict_cache:
                alerts = self._verdict_cache[cache_key]
                self._cache_hits += 1
                hit = True
            else:
                qid = 0
                c = self._svc.alert_counts_chunked([(self._cur_packets, qid)])
                alerts = int(c.get(qid, 1))
                self._verdict_cache[cache_key] = alerts
                self._cache_misses += 1
                hit = False

            # Dense, real reward.  Snort reports how many times it fired, and
            # that count falls as more matching packets are corrupted (measured
            # 7 -> 2 -> 1).  A binary -1/+1 reward gave no gradient for partial
            # progress and the policy stalled at 0% evasion; the count is
            # equally real (same Snort binary) but shaped toward evasion.
            detected = alerts > 0
            reward = -float(alerts)
            if not detected:
                reward += REWARD_EVASION_BONUS

            info["detected"] = bool(detected)
            info["evaded"] = bool(not detected)
            info["alerts"] = alerts
            info["cache_hit"] = hit

        return self._obs(self._cur_packets), reward, terminated, False, info

    def flush_pending(self) -> Dict[int, bool]:
        """Force a Snort flush of everything queued (kept for batch callers)."""
        if not self._pending:
            return {}
        v = self.resolve_batch()
        self._last_verdicts = v
        return v

    def resolve_batch(self) -> Dict[int, bool]:
        """Flush queued flows through real Snort and return their verdicts."""
        if not self._pending:
            return {}
        verdicts = self._svc.verdicts_chunked(self._pending)
        self._pending = []
        self._pending_keys = []
        return verdicts

    def service_stats(self) -> Dict:
        s = dict(self._svc.stats())
        s["cache_hits"] = self._cache_hits
        s["cache_misses"] = self._cache_misses
        s["cache_entries"] = len(self._verdict_cache)
        return s


# ---------------------------------------------------------------------------
# smoke test
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import argparse
    import time

    ap = argparse.ArgumentParser()
    ap.add_argument("--flows", type=int, default=16)
    ap.add_argument("--episodes", type=int, default=16)
    args = ap.parse_args()

    env = RealPacketEnv(n_flows=args.flows, batch_size=args.flows)
    print(f"[*] loaded {len(env.flows)} real flows from {env.capture}")

    # baseline: unmutated real flows (all should alert, they are positives)
    baseline = []
    for _key, pkts in env.flows:
        baseline.append((pkts, len(baseline)))
    base_v = env._svc.verdicts_chunked(baseline)
    base_det = sum(base_v.values())
    print(f"[*] baseline (no mutation): {base_det}/{len(base_v)} detected")

    # random agent
    t0 = time.time()
    obs, _ = env.reset()
    pending = []
    mutated = []
    for ep in range(args.episodes):
        obs, _ = env.reset()
        for _ in range(env.max_mutations):
            obs, r, term, trunc, info = env.step(env.action_space.sample())
            if term:
                break
        mutated.append((env._cur_packets, ep))
    v = env.resolve_batch()
    evaded = sum(1 for q, d in v.items() if not d)
    print(f"[*] random agent: {evaded}/{len(v)} EVADED "
          f"({100*evaded/max(len(v),1):.1f}%)")
    print(f"[*] snort stats: {env.service_stats()}")
    print(f"[*] wall time: {time.time()-t0:.1f}s")
