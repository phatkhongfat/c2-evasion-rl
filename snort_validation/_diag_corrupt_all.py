#!/usr/bin/env python3
"""
Decisive test: is evasion possible when EVERY matching packet is corrupted?

Diagnosis so far (see _diag_mutation.py):
  * packets 0 and 3 EACH independently trigger the alert (1 alert alone)
  * _apply_mutation targets ONE packet index per call (deterministic frac),
    so repeating an action corrupts the same packet over and over
  => single-target actions can never evade a rule that matches >1 packet

This script corrupts the payload of ALL packets and reports the verdict.
If evasion appears here, the mechanism is proven and the RL action space must
let the agent choose WHICH packet(s) to mutate.
"""
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))
from real_packet_env import A_CORRUPT, RealPacketEnv  # noqa: E402
from snort_batch_service import SNORT_CONF  # noqa: E402
from scapy.all import IP, Raw, TCP, UDP, wrpcap  # noqa: E402


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
        print(f"  {label:<44} alerts={n}")
        return n


def corrupt_one(pkt, offset_frac=0.0, strength=1.0):
    """Corrupt bytes inside a single packet's payload."""
    from scapy.all import Raw
    p = pkt.copy()
    if Raw not in p:
        return p
    payload = bytearray(bytes(p[Raw].load))
    if not payload:
        return p
    k = max(1, int(len(payload) * (0.1 + 0.4 * strength)))
    start = int(offset_frac * max(len(payload) - k, 0))
    for i in range(start, min(start + k, len(payload))):
        payload[i] = (payload[i] + 1 + int(strength * 127)) % 256
    p[Raw].load = bytes(payload)
    if IP in p:
        del p[IP].chksum
    if UDP in p:
        del p[UDP].chksum
    elif TCP in p:
        del p[TCP].chksum
    return p


env = RealPacketEnv(n_flows=3, batch_size=3)
for fi, (key, packets) in enumerate(env.flows):
    print(f"\nflow {fi}: {key}  ({len(packets)} pkts)")
    alerts(packets, "original")

    # which packets match on their own
    solo = []
    for i in range(len(packets)):
        solo.append(alerts([packets[i]], f"  packet {i} alone"))

    # corrupt only the packets that matched on their own
    matchers = [i for i, a in enumerate(solo) if a > 0]
    print(f"    -> matching packets: {matchers}")

    if matchers:
        pk = [p.copy() for p in packets]
        for i in matchers:
            pk[i] = corrupt_one(pk[i], 0.0, 1.0)
        alerts(pk, f"corrupt ALL matchers {matchers}")

        # also try multiple offsets, in case the match is not at offset 0
        for off in (0.25, 0.5, 0.75):
            pk2 = [p.copy() for p in packets]
            for i in matchers:
                pk2[i] = corrupt_one(pk2[i], off, 1.0)
            alerts(pk2, f"corrupt matchers @offset={off}")

    # corrupt every packet wholesale
    pk3 = [corrupt_one(p, 0.0, 1.0) for p in packets]
    alerts(pk3, "corrupt EVERY packet")
