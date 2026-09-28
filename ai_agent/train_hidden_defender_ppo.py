#!/usr/bin/env python3
"""PPO on the hidden-defender env.

Each flow is one independent decision, but PPO needs trajectories of n_steps
before it updates.  A thin multi-flow wrapper presents n_flows consecutive flows
as ONE episode, so the rollout is 64 transitions of real decisions instead of 64
episodes of length 1 (which would force n_steps=1 and destroy the advantage
estimate).

Queries are counted as real defender queries: every env.step() the agent takes
during rollout.  Because the env is 1-decision-per-flow, the query total is
also the number of flows the agent has seen, so sample efficiency is directly
comparable to the baselines.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import gymnasium as gym
import numpy as np
from sb3_contrib import MaskablePPO
from stable_baselines3.common.callbacks import BaseCallback

REPO = Path("/root/.hermes/c2-evasion-rl")
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))

from hidden_defender_env import HiddenDefenderEnv  # noqa: E402

REPORTS = REPO / "snort_validation/reports"
TARGET = 0.90
SEED = 42
N_FLOWS = 64
MAX_EPOCHS = 40


class BatchEnv(gym.Env):
    """Present n_flows one-step decisions as a single n_flows-step episode."""

    metadata = {"render_modes": []}

    def __init__(self, split="train", seed=SEED, real_snort=False):
        self.inner = HiddenDefenderEnv(split=split, seed=seed,
                                      real_snort=real_snort)
        self.action_space = self.inner.action_space
        self.observation_space = self.inner.observation_space
        self.n = len(self.inner._flows)
        self._i = 0

    def reset(self, *, seed=None, options=None):
        self._i = 0
        obs, _ = self.inner.reset()
        return obs, {}

    def step(self, action):
        obs, reward, terminated, _trunc, info = self.inner.step(action)
        self._i += 1
        # End the batch episode after the final flow only; PPO needs a single
        # long trajectory, not a reset every decision.
        done = self._i >= self.n
        if done:
            self._i = 0
        return obs, reward, done, False, info

    def action_masks(self) -> np.ndarray:
        """Delegate to the inner env so the mask tracks the CURRENT flow.

        BatchEnv advances the inner env's flow index inside step(), so the mask
        must be recomputed per step rather than cached at reset -- the protocol
        of the next flow is not known until we get there.
        """
        return self.inner.action_masks()


class QueryCounter(BaseCallback):
    """Count distinct flows solved, not raw steps (PPO revisits flows)."""

    def __init__(self):
        super().__init__()
        self.queries = 0
        self.solved = set()
        self.sem_break = 0

    def _on_step(self):
        self.queries += 1
        info = self.locals.get("infos", [{}])[0]
        if not info:
            return True
        if info.get("evaded") and info.get("semantics_ok"):
            self.solved.add(info["flow_id"])
        if info.get("evaded") and not info.get("semantics_ok"):
            self.sem_break += 1
        return True


def main() -> int:
    REPORTS.mkdir(parents=True, exist_ok=True)
    env = BatchEnv(split="train", seed=SEED)
    model = MaskablePPO("MlpPolicy", env, n_steps=N_FLOWS, batch_size=N_FLOWS,
                        n_epochs=10, learning_rate=3e-4, ent_coef=0.01,
                        gamma=0.0, seed=SEED, verbose=0)
    counter = QueryCounter()

    epochs_run = 0
    for epoch in range(MAX_EPOCHS):
        model.learn(total_timesteps=N_FLOWS, callback=counter,
                    reset_num_timesteps=False)
        epochs_run = epoch + 1
        pct = 100.0 * len(counter.solved) / N_FLOWS
        print(f"[*] epoch {epochs_run:>2}: {counter.queries} queries, "
              f"{len(counter.solved)}/{N_FLOWS} flows valid ({pct:.1f}%)")
        if pct >= TARGET * 100:
            print(f"[*] reached {TARGET:.0%} at {counter.queries} queries")
            break

    models_dir = REPO / "models"
    models_dir.mkdir(exist_ok=True)
    model.save(models_dir / "ppo_hidden_defender")

    result = {
        "method": "ppo",
        "queries": counter.queries,
        "evaded": len(counter.solved),
        "n_flows": N_FLOWS,
        "evasion_pct": round(100.0 * len(counter.solved) / N_FLOWS, 1),
        "epochs": epochs_run,
        "semantics_breaks": counter.sem_break,
    }
    out = REPORTS / "ppo_hidden_defender.json"
    out.write_text(json.dumps(result, indent=2))
    print(f"[*] ppo: {result['queries']} queries, {result['evasion_pct']}%, "
          f"{result['epochs']} epochs")
    print(f"[+] {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
