#!/usr/bin/env python3
"""
Per-action ablation: which packet mutations actually evade real Snort?

For each action, apply it deterministically to every loaded positive flow and
report the fraction that real Snort (ET Open C2) stops detecting.

Run:
    /tmp/jev-poc/venv/bin/python ai_agent/ablate_actions.py --flows 24
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "ai_agent"))

from real_packet_env import (  # noqa: E402
    A_CORRUPT, A_DROP, A_PAD, A_REORDER, A_SPLIT, A_TTL, N_ACTIONS, RealPacketEnv,
)

NAMES = {A_PAD: "pad", A_SPLIT: "split", A_TTL: "ttl",
         A_REORDER: "reorder", A_DROP: "drop", A_CORRUPT: "corrupt"}


def run(env: RealPacketEnv, action_id: int, strength: float, frac: float):
    """Apply one action to every flow.

    IMPORTANT: each call targets ONE packet index (``frac`` selects it), so
    repeating the same call re-hits the same packet.  To emulate an agent that
    can choose any packet, sweep every target index and keep the best outcome.
    Reporting a single fixed target is what made an earlier version of this
    ablation claim 0% evasion when evasion was in fact achievable.
    """
    n_pkts = max(len(p) for _k, p in env.flows)
    best = None
    for t in range(n_pkts):
        items = []
        for i, (_key, packets) in enumerate(env.flows):
            pkts = [p.copy() for p in packets]
            act = np.array([min(t, len(pkts) - 1), int(action_id),
                            int(round(strength * 2))], dtype=np.int64)
            pkts = env._apply_mutation(pkts, act)
            items.append((pkts, i))
        v = env._svc.verdicts_chunked(items)
        if best is None:
            best = v
        else:
            for q, d in v.items():
                best[q] = best.get(q, True) and d
    return best


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--flows", type=int, default=24)
    ap.add_argument("--strength", type=float, default=1.0)
    ap.add_argument("--frac", type=float, default=0.5)
    args = ap.parse_args()

    env = RealPacketEnv(n_flows=args.flows, batch_size=args.flows)
    n = len(env.flows)
    print(f"[*] {n} real positive flows from {env.capture}")

    base = env._svc.verdicts_chunked(
        [(pkts, i) for i, (_k, pkts) in enumerate(env.flows)])
    base_det = sum(base.values())
    print(f"[*] baseline detected: {base_det}/{n} "
          f"({100*base_det/n:.0f}%)\n")

    print(f"{'action':<10} {'detected':>9} {'evaded':>7} {'evasion%':>9}")
    print("-" * 40)
    rows = []
    for aid in range(N_ACTIONS):
        v = run(env, aid, args.strength, args.frac)
        det = sum(v.values())
        ev = n - det
        pct = 100 * ev / n
        rows.append((NAMES[aid], det, ev, pct))
        print(f"{NAMES[aid]:<10} {det:>9} {ev:>7} {pct:>8.1f}%")

    # random policy over all actions
    rng = np.random.default_rng(0)
    items = []
    for i, (_k, packets) in enumerate(env.flows):
        pkts = [p.copy() for p in packets]
        for _ in range(env.max_mutations):
            a = np.array([rng.integers(0, N_ACTIONS),
                          rng.random(), rng.random()], dtype=np.float32)
            pkts = env._apply_mutation(pkts, a)
        items.append((pkts, i))
    v = env._svc.verdicts_chunked(items)
    det = sum(v.values())
    print(f"{'RANDOM':<10} {det:>9} {n-det:>7} {100*(n-det)/n:>8.1f}%")

    print(f"\n[*] snort stats: {env.service_stats()}")
    best = max(rows, key=lambda r: r[3])
    print(f"[*] best single action: {best[0]} ({best[3]:.1f}% evasion)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
