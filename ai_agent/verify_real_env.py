#!/usr/bin/env python3
"""
End-to-end proof that the real-Snort env is learnable.

Policy: "corrupt every packet's payload head" -- the strategy the budget
diagnosis showed is REQUIRED (evasion cost == number of matching packets).
Reports evasion rate against real Snort before/after.

Run:
    /tmp/jev-poc/venv/bin/python ai_agent/verify_real_env.py --flows 24
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "ai_agent"))

from real_packet_env import A_CORRUPT, RealPacketEnv  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--flows", type=int, default=24)
    args = ap.parse_args()

    env = RealPacketEnv(n_flows=args.flows, batch_size=args.flows,
                        max_mutations=12)
    n = len(env.flows)
    print(f"[*] {n} positive flows from {env.capture}")

    # baseline: untouched
    base = env._svc.verdicts_chunked(
        [(pkts, i) for i, (_k, pkts) in enumerate(env.flows)])
    base_det = sum(base.values())
    print(f"[*] baseline detected: {base_det}/{n} ({100*base_det/n:.0f}%)\n")

    # sweep coverage: corrupt the first k packets of every flow
    max_pkts = max(len(p) for _k, p in env.flows)
    print(f"{'corrupt k pkts':>14} {'detected':>9} {'evaded':>7} {'evasion%':>9}")
    print("-" * 44)
    for k in range(0, min(max_pkts, 12) + 1):
        items = []
        for i, (_key, packets) in enumerate(env.flows):
            pkts = [p.copy() for p in packets]
            for t in range(k):
                act = np.array([min(t, len(pkts) - 1), int(A_CORRUPT), 2],
                               dtype=np.int64)
                pkts = env._apply_mutation(pkts, act)
            items.append((pkts, i))
        v = env._svc.verdicts_chunked(items)
        det = sum(v.values())
        ev = n - det
        print(f"{k:>14} {det:>9} {ev:>7} {100*ev/n:>8.1f}%")

    print(f"\n[*] snort stats: {env.service_stats()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
