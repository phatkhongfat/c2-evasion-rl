#!/usr/bin/env python3
"""
Evaluate a trained agent against real Snort, with a clean harness.

The callback inside train_real_snort_agent.py replays flows by poking env
internals and reported 0/16 even when the training reward (+1.25) implied the
policy was evading ~10% of episodes.  This script re-evaluates the SAVED model
with a straightforward loop so the number can be trusted.

Usage:
    /tmp/jev-poc/venv/bin/python ai_agent/eval_real_snort_agent.py \
        --model models/ppo_real_snort_agent.zip --flows 32
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
from stable_baselines3 import PPO

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "ai_agent"))

from real_packet_env import RealPacketEnv  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default=str(REPO / "models/ppo_real_snort_agent.zip"))
    ap.add_argument("--flows", type=int, default=32)
    ap.add_argument("--capture", default="botnet-capture-20110819-bot")
    ap.add_argument("--out", default=str(REPO / "snort_validation/reports/real_agent_eval.json"))
    args = ap.parse_args()

    env = RealPacketEnv(n_flows=args.flows, batch_size=args.flows,
                        capture=args.capture, max_mutations=12, seed=7)
    n = len(env.flows)
    model = PPO.load(args.model, device="cpu")
    print(f"[*] model={args.model}")
    print(f"[*] {n} real flows from {args.capture}")

    # baseline (unmutated)
    base = env._svc.verdicts_chunked(
        [(pkts, i) for i, (_k, pkts) in enumerate(env.flows)])
    print(f"[*] baseline detected: {sum(base.values())}/{n}")

    # deterministic policy rollout, one episode per flow
    items = []
    for i, (_key, packets) in enumerate(env.flows):
        env._idx = i
        env._cur_packets = [p.copy() for p in packets]
        env._mutations = 0
        env._corrupted = set()
        obs = env._obs(env._cur_packets)
        for _ in range(env.max_mutations):
            action, _ = model.predict(obs, deterministic=True)
            env._cur_packets = env._apply_mutation(env._cur_packets, action)
            env._mutations += 1
            obs = env._obs(env._cur_packets)
        items.append((env._cur_packets, i))

    counts = env._svc.alert_counts_chunked(items)
    detected = sum(1 for v in counts.values() if v > 0)
    evaded = n - detected
    rate = 100 * evaded / n
    print(f"\n[*] agent: detected {detected}/{n}  evaded {evaded}/{n} "
          f"({rate:.1f}%)")
    print(f"[*] alerts total: {sum(counts.values())}")

    # random-policy control
    rng = np.random.default_rng(0)
    ritems = []
    for i, (_key, packets) in enumerate(env.flows):
        pkts = [p.copy() for p in packets]
        for _ in range(env.max_mutations):
            a = np.array([rng.integers(0, env.max_packets),
                          rng.integers(0, 6), rng.integers(0, 3)],
                         dtype=np.int64)
            pkts = env._apply_mutation(pkts, a)
        ritems.append((pkts, i))
    rc = env._svc.alert_counts_chunked(ritems)
    rdet = sum(1 for v in rc.values() if v > 0)
    print(f"[*] random control: detected {rdet}/{n} evaded {n-rdet}/{n} "
          f"({100*(n-rdet)/n:.1f}%)")

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w") as f:
        json.dump({
            "model": args.model, "capture": args.capture, "flows": n,
            "baseline_detected": int(sum(base.values())),
            "agent_detected": int(detected), "agent_evaded": int(evaded),
            "agent_evasion_pct": round(rate, 2),
            "random_detected": int(rdet),
            "random_evasion_pct": round(100 * (n - rdet) / n, 2),
            "snort_stats": env.service_stats(),
        }, f, indent=2)
    print(f"[+] report: {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
