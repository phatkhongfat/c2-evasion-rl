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
N_FLOWS = 256
MAX_EPOCHS = 200


class BatchEnv(gym.Env):
    """Present n_flows one-step decisions as a single n_flows-step episode."""

    metadata = {"render_modes": []}

    def __init__(self, split="train", seed=SEED, real_snort=False,
                 capture=None, ownership="client", corpus=None,
                 diversity_coef: float = 0.0):
        self.inner = HiddenDefenderEnv(split=split, seed=seed,
                                      real_snort=real_snort, capture=capture,
                                      ownership=ownership, corpus=corpus)
        self.action_space = self.inner.action_space
        self.observation_space = self.inner.observation_space
        self.n = len(self.inner._flows)
        self._i = 0
        # P4 frequency-penalty shaping state (per-episode = per-epoch).
        self.diversity_coef = diversity_coef
        self._valid_counts: dict = {}
        self._valid_total = 0

    def reset(self, *, seed=None, options=None):
        self._i = 0
        self._valid_counts = {}
        self._valid_total = 0
        obs, _ = self.inner.reset()
        return obs, {}

    def step(self, action):
        obs, reward, terminated, _trunc, info = self.inner.step(action)
        # Frequency-penalty shaping (P4): penalise REPEATED use of the same
        # winning mechanism within the episode so reward ties (e.g. split16 vs
        # split_slow both net 9.50 on dns) break toward under-used actions.
        # Gated on a REAL valid evasion: alerted / semantics-broken steps keep
        # their exact reward, so shaping can never fake an evasion.  lam=0.0
        # (default) leaves every reward bit-identical to P3.
        if self.diversity_coef > 0.0 and info.get("evaded") and info.get("semantics_ok"):
            reward -= frequency_penalty(self._valid_counts, self._valid_total,
                                        info["action"], self.diversity_coef)
            self._valid_counts[info["action"]] = \
                self._valid_counts.get(info["action"], 0) + 1
            self._valid_total += 1
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


def frequency_penalty(counts: dict, total: int, mech: str, lam: float) -> float:
    """Count-based exploration penalty (Bellemare et al. 2016, bandit analog).

    Returns lam * usage_share(mech), where usage_share is the fraction of this
    episode's VALID EVASIONS that already used `mech`.  The first use of an
    action is free (count=0).  Applied ONLY to valid-evasion steps by
    BatchEnv.step, so it can never manufacture an evasion; lam must stay
    << REWARD_EVADE (10.0) -- the pass bar caps it at 0.6.
    """
    if lam <= 0.0 or total <= 0:
        return 0.0
    return lam * (counts.get(mech, 0) / total)


class QueryCounter(BaseCallback):
    """Count distinct flows solved, not raw steps (PPO revisits flows).

    Epochs are tracked separately from the run.  Now that the train split is
    reshuffled every epoch, a cumulative ``solved`` set grows past ``n_flows``
    and ``len(solved) / n_flows`` stops being a rate (it reported 105.9%).
    The early-stop must therefore be judged on the CURRENT epoch's rollout,
    and the cumulative figure is kept only as a clearly-named diagnostic.
    """

    def __init__(self):
        super().__init__()
        self.queries = 0
        self.solved = set()          # cumulative, across all epochs
        self.sem_break = 0           # cumulative
        self.epoch_solved = set()    # current epoch only
        self.epoch_queries = 0
        self.epoch_sem_break = 0

    def new_epoch(self):
        """Reset the per-epoch counters.  Cumulative ones are untouched."""
        self.epoch_solved = set()
        self.epoch_queries = 0
        self.epoch_sem_break = 0

    def _on_step(self):
        self.queries += 1
        self.epoch_queries += 1
        info = self.locals.get("infos", [{}])[0]
        if not info:
            return True
        if info.get("evaded") and info.get("semantics_ok"):
            self.solved.add(info["flow_id"])
            self.epoch_solved.add(info["flow_id"])
        if info.get("evaded") and not info.get("semantics_ok"):
            self.sem_break += 1
            self.epoch_sem_break += 1
        return True


def main() -> int:
    import argparse

    global N_FLOWS, MAX_EPOCHS, SEED, TARGET

    ap = argparse.ArgumentParser()
    ap.add_argument("--real-snort", action="store_true",
                    help="score every training step with the real Snort binary "
                         "instead of the RealRulesReplica surrogate (~1.3 s/flow)")
    ap.add_argument("--n-flows", type=int, default=N_FLOWS)
    ap.add_argument("--max-epochs", type=int, default=MAX_EPOCHS)
    ap.add_argument("--seed", type=int, default=SEED)
    ap.add_argument("--out", default=None)
    ap.add_argument("--split", default="train",
                    choices=("train", "test", "all"),
                    help="corpus split to train on")
    ap.add_argument("--capture", default=None,
                    help="restrict training flows to one capture id")
    ap.add_argument("--model-out",
                    default=str(REPO / "models/ppo_hidden_defender.zip"),
                    help="destination .zip for the trained model")
    ap.add_argument("--ownership", default="client",
                    choices=("client", "both"),
                    help="apply mechanisms to 'client' packets only (default) or 'both' endpoints (two-sided ceiling)")
    ap.add_argument("--corpus", default=None,
                    help="corpus pickle override (default: the checked-in v1 corpus)")
    ap.add_argument("--diversity-coef", type=float, default=0.0,
                    help="frequency-penalty coefficient lambda (0.0 = off, "
                         "bit-identical to P3; recommended probe values 0.3/0.6)")
    args = ap.parse_args()

    N_FLOWS, MAX_EPOCHS, SEED = args.n_flows, args.max_epochs, args.seed

    REPORTS.mkdir(parents=True, exist_ok=True)
    # Two scorers. The surrogate (RealRulesReplica) parses the real 21,374-rule
    # ET Open C2 file and reproduces the 3 sids that fire per capture, but it
    # silently drops the 4,394 rules (20.6%) it cannot implement -- anything using
    # pcre / byte_test / byte_extract / byte_jump. Real Snort is the actual
    # defender, and the two have already been caught disagreeing on this project,
    # so scoring must be selectable, not hardcoded to the surrogate.
    env = BatchEnv(split=args.split, seed=SEED,
                   real_snort=args.real_snort, capture=args.capture,
                   ownership=args.ownership, corpus=args.corpus,
                   diversity_coef=args.diversity_coef)
    scorer = "real_snort" if args.real_snort else "replica"
    print(f"[*] training with scorer={scorer}")
    model = MaskablePPO("MlpPolicy", env, n_steps=N_FLOWS, batch_size=N_FLOWS,
                        n_epochs=10, learning_rate=3e-4, ent_coef=0.0151,
                        gamma=0.0, seed=SEED, verbose=0)
    counter = QueryCounter()

    epochs_run = 0
    for epoch in range(MAX_EPOCHS):
        counter.new_epoch()
        model.learn(total_timesteps=N_FLOWS, callback=counter,
                    reset_num_timesteps=False)
        epochs_run = epoch + 1
        # Rate is over THIS epoch's rollout: with a reshuffled corpus the
        # cumulative set spans different flows and cannot be a percentage.
        pct = 100.0 * len(counter.epoch_solved) / N_FLOWS
        print(f"[*] epoch {epochs_run:>2}: {counter.queries} queries, "
              f"{len(counter.epoch_solved)}/{N_FLOWS} flows valid this epoch "
              f"({pct:.1f}%)")
        if pct >= TARGET * 100:
            print(f"[*] reached {TARGET:.0%} at {counter.queries} queries")
            break

    out_model = Path(args.model_out)
    out_model.parent.mkdir(parents=True, exist_ok=True)
    model.save(str(out_model).removesuffix(".zip"))

    result = {
        "method": "ppo",
        "diversity_coef": args.diversity_coef,
        "queries": counter.queries,
        # PER-EPOCH evaded count.  `counter.solved` is cumulative across every
        # epoch and, with the corpus reshuffled each epoch, grows past n_flows
        # by design (an RS64 run wrote 638 while n_flows=64).  Reporting that
        # here made `evaded` violate `evaded <= n_flows`, so the cross-check
        # verifier went red.  The cumulative figure lives under its own key
        # below; the rate is per-epoch and must divide by n_flows.
        "evaded": len(counter.epoch_solved),
        "n_flows": N_FLOWS,
        "evasion_pct": round(100.0 * len(counter.epoch_solved) / N_FLOWS, 1),
        "epochs": epochs_run,
        "semantics_breaks": counter.sem_break,
        # Cumulative distinct flows ever solved, across all epochs.  NOT a
        # rate: with the corpus reshuffled each epoch this exceeds n_flows by
        # design, so it must never be divided by n_flows.
        "distinct_flows_solved_cumulative": len(counter.solved),
    }
    out = Path(args.out) if args.out else REPORTS / "ppo_hidden_defender.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    result["scorer"] = scorer
    out.write_text(json.dumps(result, indent=2))
    print(f"[*] ppo: {result['queries']} queries, {result['evasion_pct']}%, "
          f"{result['epochs']} epochs, scorer={scorer}")
    print(f"[+] {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
