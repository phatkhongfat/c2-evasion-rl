#!/usr/bin/env python3
"""Verify mutations are applied AND find which packet carries the match."""
import subprocess
import sys
import tempfile
from pathlib import Path

import numpy as np

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))
from real_packet_env import A_CORRUPT, RealPacketEnv  # noqa: E402
from snort_batch_service import SNORT_CONF  # noqa: E402
from scapy.all import IP, Raw, UDP, wrpcap  # noqa: E402


def alerts(packets, label):
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        pcap, logdir = td / "x.pcap", td / "l"
        logdir.mkdir()
        wrpcap(str(pcap), packets)
        subprocess.run(["snort", "-c", str(SNORT_CONF), "-r", str(pcap),
                        "-l", str(logdir), "-q", "-A", "fast"],
                       capture_output=True, text=True, timeout=300)
        n = 0
        for af in logdir.glob("alert*"):
            n += len([ln for ln in open(af, errors="ignore")
                      if ln.strip() and not ln.startswith("#")])
        print(f"  {label:<46} alerts={n}")
        return n


env = RealPacketEnv(n_flows=4, batch_size=4)
key, packets = env.flows[0]
print(f"flow {key}  packets={len(packets)}")
for i, p in enumerate(packets):
    n = len(bytes(p[Raw].load)) if Raw in p else 0
    print(f"    pkt {i}: dsize={len(bytes(p[IP].payload))} raw={n}")

print("\n[A] each packet alone, others dropped")
for i in range(len(packets)):
    alerts([packets[i]], f"only packet {i}")

print("\n[B] original whole flow")
alerts(packets, "original")

print("\n[C] corrupt EVERY packet (frac varied), strength=1.0")
for frac in (0.0, 0.5, 1.0):
    act = np.array([float(A_CORRUPT), frac, 1.0], dtype=np.float32)
    pkts = [p.copy() for p in packets]
    for _ in range(3):
        pkts = env._apply_mutation(pkts, act)
    # prove the bytes really changed
    before = bytes(packets[0][Raw].load) if Raw in packets[0] else b""
    after = bytes(pkts[0][Raw].load) if Raw in pkts[0] else b""
    print(f"    [frac={frac}] payload changed: {before != after} "
          f"({len(before)}B -> {len(after)}B)")
    alerts(pkts, f"corrupt all, frac={frac}")

print("\n[D] corrupt only packet 0 vs only last packet")
for idx in (0, len(packets) - 1):
    pkts = [p.copy() for p in packets]
    act = np.array([float(A_CORRUPT), 0.0, 1.0], dtype=np.float32)
    pkts[idx] = env._apply_mutation([pkts[idx]], act)[0]
    alerts(pkts, f"corrupt packet {idx} only")
