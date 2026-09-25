#!/usr/bin/env python3
"""
Decisive experiment: how many mutations does real-Snort evasion require?

Established facts (from _diag_mutation.py / _diag_corrupt_all.py):
  * a rule matches SEVERAL packets in a flow, each independently
  * corrupting the payload START of ALL matching packets -> alerts=0
  * corrupting only some of them -> still alerts

So evasion cost = (number of matching packets).  This script measures that
cost per flow and reports the evasion-vs-budget curve, which is exactly what
sets ``max_mutations`` in the RL environment.

Usage:
    /tmp/jev-poc/venv/bin/python snort_validation/_diag_budget.py --flows 16
"""
import argparse
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))
from real_packet_env import RealPacketEnv  # noqa: E402
from snort_batch_service import SNORT_CONF  # noqa: E402
from scapy.all import IP, Raw, TCP, UDP, wrpcap  # noqa: E402


def n_alerts(packets):
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
        return n


def corrupt_head(pkt, frac_of_payload=0.5):
    p = pkt.copy()
    if Raw not in p:
        return p
    pl = bytearray(bytes(p[Raw].load))
    if not pl:
        return p
    k = max(1, int(len(pl) * frac_of_payload))
    for i in range(min(k, len(pl))):
        pl[i] = (pl[i] + 137) % 256
    p[Raw].load = bytes(pl)
    if IP in p:
        del p[IP].chksum
    if UDP in p:
        del p[UDP].chksum
    elif TCP in p:
        del p[TCP].chksum
    return p


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--flows", type=int, default=16)
    args = ap.parse_args()

    env = RealPacketEnv(n_flows=args.flows, batch_size=8)
    print(f"[*] {len(env.flows)} positive flows from {env.capture}\n")

    budget_needed = []
    print(f"{'flow':>5} {'pkts':>5} {'base':>5} {'matchers':>9} "
          f"{'budget':>7} {'evaded_at':>10}")
    print("-" * 52)
    for fi, (key, packets) in enumerate(env.flows):
        base = n_alerts(packets)
        # which packets match on their own
        matchers = [i for i in range(len(packets))
                    if n_alerts([packets[i]]) > 0]
        if not matchers:
            print(f"{fi:>5} {len(packets):>5} {base:>5} {0:>9} "
                  f"{'n/a':>7} {'n/a':>10}")
            continue

        # corrupt the first k matchers, increasing k until it evades
        evaded_at = None
        for k in range(1, len(matchers) + 1):
            pk = [p.copy() for p in packets]
            for i in matchers[:k]:
                pk[i] = corrupt_head(pk[i])
            if n_alerts(pk) == 0:
                evaded_at = k
                break
        budget_needed.append(evaded_at if evaded_at else len(matchers) + 1)
        print(f"{fi:>5} {len(packets):>5} {base:>5} {len(matchers):>9} "
              f"{len(matchers):>7} {str(evaded_at):>10}")

    if budget_needed:
        import numpy as np
        b = np.array(budget_needed)
        print(f"\n[*] flows measured: {len(b)}")
        print(f"[*] mutations needed: median={np.median(b):.0f} "
              f"mean={b.mean():.1f} max={b.max()}")
        print(f"[*] flows needing >3 mutations: "
              f"{int((b > 3).sum())}/{len(b)}")
        print("\n=> max_mutations must be >= the largest budget above for the "
              "agent to be able to evade at all.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
