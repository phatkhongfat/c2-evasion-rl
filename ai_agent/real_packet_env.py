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

        # action: (action_id, target_packet_index_normalised, strength)
        self.action_space = spaces.Box(
            low=np.array([0.0, 0.0, 0.0], dtype=np.float32),
            high=np.array([N_ACTIONS - 1e-3, 1.0, 1.0], dtype=np.float32),
        )
        # observation: per-flow summary + mutation progress
        self.observation_space = spaces.Box(
            low=-5.0, high=5.0, shape=(10,), dtype=np.float32)

        self.flows: List[Tuple[Tuple, List]] = []
        self._load_flows()

        self._idx = 0
        self._mutations = 0
        self._cur_packets: List = []
        self._corrupted: set = set()
        self._pending: List[Tuple[List, int]] = []
        self._pending_keys: List[int] = []
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
    def _apply_mutation(self, packets: List, action: np.ndarray) -> List:
        from scapy.all import IP, Raw, TCP, UDP

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
        return np.clip(obs, -5.0, 5.0)

    def reset(self, *, seed=None, options=None):
        super().reset(seed=seed)
        self._idx = self.rng.integers(0, len(self.flows))
        _key, packets = self.flows[self._idx]
        self._cur_packets = [p.copy() for p in packets]
        self._mutations = 0
        self._corrupted = set()
        return self._obs(self._cur_packets), {"flow_index": int(self._idx)}

    def step(self, action: np.ndarray):
        self._cur_packets = self._apply_mutation(self._cur_packets, action)
        self._mutations += 1

        # queue for a batched real-Snort verdict
        qid = self._next_qid
        self._next_qid += 1
        self._pending.append((self._cur_packets, qid))
        self._pending_keys.append(qid)

        terminated = self._mutations >= self.max_mutations
        # Interim reward is 0: the authoritative signal is the real Snort
        # verdict, delivered by resolve_batch().  Shaping here would risk the
        # agent optimising the shaping instead of the detector.
        reward = 0.0
        info = {"qid": qid, "pending": len(self._pending)}
        if terminated and len(self._pending) >= self.batch_size:
            info["verdicts"] = self.resolve_batch()
        return self._obs(self._cur_packets), reward, terminated, False, info

    def resolve_batch(self) -> Dict[int, bool]:
        """Flush queued flows through real Snort and return their verdicts."""
        if not self._pending:
            return {}
        verdicts = self._svc.verdicts_chunked(self._pending)
        self._pending = []
        self._pending_keys = []
        return verdicts

    def service_stats(self) -> Dict:
        return self._svc.stats()


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
