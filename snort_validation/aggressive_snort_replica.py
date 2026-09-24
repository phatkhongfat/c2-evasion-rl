#!/usr/bin/env python3
"""Aggressive Snort replica (70-80% detection baseline) for snort-direct reward training.

All verdict functions return ``True`` when Snort DETECTS the flow and ``False``
when the flow evades.

* ``replica_snort_verdict`` -- fast Python replica of the exact rule semantics
  in ``rules/botnet-behavior.rules``.  Used as the training reward: a real
  Snort CLI call costs ~0.8 s, so 50k training steps would take ~11 h.
* ``mock_snort_verdict``    -- the plan's Task-3 stub (``tot_pkts > 50``), kept
  only as a documented negative control (it agrees with real Snort 56.7% of the
  time, the replica 99.7%).
* ``real_snort_verdict``    -- the ground truth: synthesize the pcap with
  ``flow_to_pcap``, run Snort 2.9, parse the alert file.

The replica is NOT trusted on faith.  ``verify_snort_replica.py`` scores it
against real Snort verdicts on every flow that has one.

Measured Snort semantics encoded here (all three were derived empirically and
each one changed the verdicts -- see verify_snort_replica.py for the evidence):

1. ``flow:established`` rules do not count the pre-establishment packets (SYN,
   SYN-ACK).  The client ACK that completes the handshake does count.
2. ``threshold:type both`` anchors its window on the FIRST matching packet and
   counts matches within ``seconds`` of that anchor.  A sliding window is
   wrong: 10 small TCP packets spread over 90 s trip a sliding window but real
   Snort stays silent.
3. Rules are written ``any any -> any any``, so they match in BOTH directions.
   ``track by_src`` groups by the packet's SOURCE address (client for
   client->server packets, server for server->client packets) -- not by the
   rule's intended direction.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from flow_to_pcap import _plan_flow_packets, synthesize_flow_pcap  # noqa: E402

REPO_ROOT = _HERE.parent
SNORT_CONF = _HERE / "rules" / "snort.conf"

# ---------------------------------------------------------------------------
# Rule constants, read off rules/botnet-behavior.rules.
# (sid, proto, dsize_lo, dsize_hi, count, seconds, needs_established, track)
# track: 'by_src' | 'by_dst' | None (no threshold keyword -> fires on 1 match)
# ---------------------------------------------------------------------------
RULES = [
    # Aggressive ruleset (sid 4000001-4000008)
    (4000001, "tcp", None, None, 2, 30, True, "by_src"),
    (4000002, "udp", None, 100, 2, 20, False, "by_src"),
    (4000003, "tcp", 200, 1500, 3, 60, True, "by_src"),
    (4000004, "tcp", 800, None, 2, 120, True, "by_src"),
    (4000005, "tcp", 1400, None, 1, 0, False, None),
    (4000006, "tcp", None, None, 6, 15, True, "by_src"),
    (4000007, "udp", 200, 600, 2, 30, False, "by_src"),
    (4000008, "tcp", 1000, None, 2, 120, True, "by_dst"),
]


def _clamp_features(features: Dict) -> Tuple[int, int, int, float]:
    """Reproduce the clamping synthesize_flow_pcap applies before packetizing."""
    tot_pkts = max(int(features.get("tot_pkts", 10)), 2)
    tot_bytes = max(int(features.get("tot_bytes", 1000)), tot_pkts * 40)
    src_bytes = min(int(features.get("src_bytes", 500)), tot_bytes - 40)
    dur = max(float(features.get("dur", 1.0)), 0.0)
    return tot_pkts, tot_bytes, src_bytes, dur


def packet_plan(features: Dict) -> List[Tuple[str, int, float]]:
    """[(direction, dsize, time), ...] mirroring flow_to_pcap's output.

    ``direction`` is 'src' for client->server and 'dst' for server->client.
    ``dsize`` is the payload length Snort sees.
    """
    proto = str(features.get("proto", "tcp")).lower()
    state = str(features.get("state", "CON"))
    tot_pkts, tot_bytes, src_bytes, dur = _clamp_features(features)
    dst_bytes = tot_bytes - src_bytes
    ts = dur / max(tot_pkts - 1, 1) if tot_pkts > 1 else 0.0

    if proto == "tcp":
        plan = _plan_flow_packets(src_bytes, dst_bytes, max(tot_pkts - 3, 0),
                                  1460, tot_pkts)
        n_handshake = min(max(0, tot_pkts - len(plan)), 3)
        pkts: List[Tuple[str, int, float]] = []
        t = 0.0
        for i in range(n_handshake):
            # 0: SYN (src), 1: SYN-ACK (dst), 2: ACK (src)
            pkts.append(("dst" if i == 1 else "src", 0, t))
            t += ts
        for direction, size in plan:
            pkts.append(("src" if direction == "ctrl" else direction, size, t))
            t += ts
        if "FIN" in state.upper() or "CLOSE" in state.upper():
            if len(pkts) < tot_pkts:
                pkts.append(("src", 0, t))
                t += ts
            if len(pkts) < tot_pkts:
                pkts.append(("dst", 0, t))
        return pkts[:tot_pkts]

    if proto == "udp":
        plan = _plan_flow_packets(src_bytes, dst_bytes, tot_pkts, 1472, tot_pkts)
        pkts = []
        for i, (direction, size) in enumerate(plan):
            if direction == "ctrl":
                # UDP has no ACK: a tiny 1-byte keep-alive datagram
                pkts.append(("src", 1, i * ts))
            else:
                pkts.append((direction, size, i * ts))
        return pkts[:tot_pkts]

    # ICMP / unknown: no botnet-behavior rule matches ICMP.
    return []


def _window_hit(times: List[float], count: int, seconds: float) -> bool:
    """True if >= ``count`` matches fall inside the anchored threshold window.

    Semantics measured against the real Snort binary; see module docstring.
    """
    if count <= 1:
        return len(times) >= 1
    ts = sorted(times)
    if not ts:
        return False
    anchor = ts[0]
    return sum(1 for t in ts if (t - anchor) < seconds) >= count


def _countable_pkts(pkts: List[Tuple[str, int, float]],
                    established_rule: bool, n_handshake: int):
    """Packets Snort can count for a rule (see module docstring, note 1)."""
    if not established_rule:
        return list(pkts)
    # index n_handshake-1 is the ACK that completes the handshake
    return list(pkts[max(n_handshake - 1, 0):])


def aggressive_snort_verdict(features: Dict) -> bool:
    """Rule-level replica of Snort's verdict for one synthesized flow."""
    proto = str(features.get("proto", "tcp")).lower()
    if proto not in ("tcp", "udp"):
        return False

    pkts = packet_plan(features)
    if not pkts:
        return False

    # flow:established -- stream5 must have seen the full handshake.
    n_handshake = 0
    for _direction, dsize, _t in pkts[:3]:
        if dsize == 0:
            n_handshake += 1
        else:
            break
    established = n_handshake >= 3

    for _sid, rproto, lo, hi, count, seconds, need_est, track in RULES:
        if rproto != proto:
            continue
        if need_est and not established:
            continue
        countable = _countable_pkts(pkts, need_est, n_handshake)
        matches = [(d, t) for d, s, t in countable
                   if (lo is None or s > lo) and (hi is None or s < hi)]
        if not matches:
            continue
        if track is None:
            # no threshold keyword: a single match fires the rule
            return True
        # Group by the packet's SOURCE address (note 3 in the module docstring).
        groups: Dict[str, List[float]] = {}
        for d, t in matches:
            is_client_src = (d == "src")
            if track == "by_src":
                key = "client" if is_client_src else "server"
            else:  # by_dst -> packet destination address
                key = "server" if is_client_src else "client"
            groups.setdefault(key, []).append(t)
        for times in groups.values():
            if _window_hit(times, count, seconds):
                return True
    return False


def mock_snort_verdict(features: Dict) -> bool:
    """The plan's Task-3 stub: flag flows with tot_pkts > 50.

    Kept as a negative control only -- it agrees with real Snort on 56.7% of
    labelled flows, versus 99.7% for the replica.
    """
    return features.get("tot_pkts", 0) > 50


def real_snort_verdict(features: Dict, workdir: Optional[Path] = None,
                       tag: str = "q") -> bool:
    """Ground truth: synthesize a pcap and run the real Snort binary."""
    workdir = Path(workdir or "/tmp/c2scratch/snort_query")
    workdir.mkdir(parents=True, exist_ok=True)
    pcap = workdir / f"{tag}.pcap"
    logdir = workdir / f"log_{tag}"
    logdir.mkdir(exist_ok=True)
    for stale in logdir.glob("alert*"):
        stale.unlink()

    synthesize_flow_pcap(features, output_path=pcap)
    subprocess.run(["snort", "-c", str(SNORT_CONF), "-r", str(pcap),
                    "-l", str(logdir), "-q", "-A", "fast"],
                   capture_output=True, text=True, timeout=60)
    alerts = 0
    for af in logdir.glob("alert*"):
        alerts += len([ln for ln in open(af, errors="ignore")
                       if ln.strip() and not ln.startswith("#")])
    return alerts > 0


def query_snort_verdict(features: Dict, mode: str = "replica") -> bool:
    """Dispatcher used by the RL environment's snort-direct reward.

    mode: 'replica' (default, fast), 'mock' (plan stub), 'real' (Snort CLI).
    """
    if mode == "mock":
        return mock_snort_verdict(features)
    if mode == "real":
        return real_snort_verdict(features)
    return replica_snort_verdict(features)


if __name__ == "__main__":
    demo = {"dur": 0.5, "tot_pkts": 60, "tot_bytes": 3000,
            "src_bytes": 2000, "proto": "udp", "state": "CON"}
    print("Mock verdict (tot_pkts=60):", mock_snort_verdict(demo))
    print("Mock verdict (tot_pkts=30):",
          mock_snort_verdict({**demo, "tot_pkts": 30}))
    print("Replica verdict (tot_pkts=60):", replica_snort_verdict(demo))
    print("Replica verdict (tot_pkts=3):",
          replica_snort_verdict({**demo, "tot_pkts": 3}))
