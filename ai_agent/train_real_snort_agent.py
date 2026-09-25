#!/usr/bin/env python3
"""
Train PPO to evade REAL Snort.

Unlike ``train_packet_level_agent.py`` (which scores a Python replica of
hand-written rules), the reward here comes from the real Snort binary running
the ET Open C2 ruleset.  ``RealPacketEnv`` batches verdicts so the ~10 s rule
load is amortised over a batch instead of paid per flow.

Reward: +1 when real Snort does NOT alert on the mutated flow, -1 when it
does.  The verdict is authoritative and is read from the batch flush, so the
agent cannot optimise a surrogate or a shaping term instead of the detector.

Run:
    /tmp/jev-poc/venv/bin/python ai_agent/train_real_snort_agent.py \
        --flows 24 --timesteps 4000
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import deque
from pathlib import Path

import numpy as np
from stable_baselines3 import PPO
from stable_baselines3.common.callbacks import BaseCallback

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "ai_agent"))

from real_packet_env import RealPacketEnv  # noqa: E402

MODEL_DIR = REPO / "models"
REPORT_DIR = REPO / "snort_validation" / "reports"


class SnortVerdictCallback(BaseCallback):
    """Roll out the current policy and score it with real Snort."""

    def __init__(self, eval_flows: int = 24, every: int = 512, verbose: int = 0):
        super().__init__(verbose)
        self.eval_flows = eval_flows
        self.every = every
        self.history = []
        self._eval_env = None

    def _make_env(self):
        if self._eval_env is None:
            self._eval_env = RealPacketEnv(
                n_flows=self.eval_flows, batch_size=self.eval_flows,
                max_mutations=12, seed=1234)
        return self._eval_env

    def _on_step(self) -> bool:
        if self.n_calls % self.every:
            return True
        env = self._make_env()
        n = len(env.flows)
        items = []
        for i, (_k, packets) in enumerate(env.flows):
            pkts = [p.copy() for p in packets]
            obs, _ = env.reset()
            # replay the policy on this specific flow by setting the index
            env._idx = i
            env._cur_packets = [p.copy() for p in packets]
            env._mutations = 0
            env._corrupted = set()
            obs = env._obs(env._cur_packets)
            for _ in range(env.max_mutations):
                action, _ = self.model.predict(obs, deterministic=True)
                env._cur_packets = env._apply_mutation(env._cur_packets, action)
                env._mutations += 1
                obs = env._obs(env._cur_packets)
            items.append((env._cur_packets, i))
        v = env._svc.verdicts_chunked(items)
        det = sum(v.values())
        ev = n - det
        rate = 100 * ev / n
        self.history.append({"step": int(self.n_calls), "evasion_rate": rate,
                             "detected": int(det), "flows": n})
        print(f"[eval @ {self.n_calls}] real-Snort evasion "
              f"{ev}/{n} ({rate:.1f}%)")
        return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--flows", type=int, default=24)
    ap.add_argument("--timesteps", type=int, default=4000)
    ap.add_argument("--eval-flows", type=int, default=24)
    ap.add_argument("--eval-every", type=int, default=512)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    env = RealPacketEnv(n_flows=args.flows, batch_size=args.flows,
                        max_mutations=8, seed=args.seed)
    print(f"[*] train env: {len(env.flows)} real flows from {env.capture}")

    model = PPO(
        "MlpPolicy", env, verbose=1, device="cpu", seed=args.seed,
        n_steps=256, batch_size=64, learning_rate=3e-4,
        gamma=0.95, ent_coef=0.01, tensorboard_log=None,
    )

    cb = SnortVerdictCallback(eval_flows=args.eval_flows,
                              every=args.eval_every)
    model.learn(total_timesteps=args.timesteps, callback=cb)

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    out = MODEL_DIR / "ppo_real_snort_agent.zip"
    model.save(str(out))
    print(f"[+] model saved: {out}")

    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    rep = REPORT_DIR / "real_snort_agent_training.json"
    with open(rep, "w") as f:
        json.dump({
            "flows": args.flows, "timesteps": args.timesteps,
            "capture": env.capture, "eval_history": cb.history,
            "snort_stats": env.service_stats(),
        }, f, indent=2)
    print(f"[+] report: {rep}")
    if cb.history:
        best = max(h["evasion_rate"] for h in cb.history)
        last = cb.history[-1]["evasion_rate"]
        print(f"[*] real-Snort evasion: last={last:.1f}% best={best:.1f}%")
    return 0


if __name__ == "__main__":
    sys.exit(main())
