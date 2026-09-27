#!/usr/bin/env python3
"""Non-RL baselines for the hidden-defender problem.

All three share one query budget accounting rule so the comparison is fair:
a query is one (flow, mechanism) scored against the defender, and a method
stops as soon as 90% of the train flows have a valid evasion.

  random_sweep     tries mechanisms in random order, per flow
  greedy           reuses the mechanism that worked on the nearest previous
                   flow (8-D euclidean), falls back to random on failure
  supervised_tree  CHEATING ceiling: exhaustively probes every flow to build
                   oracle labels, fits a depth-3 tree, then deploys at 1 query
                   per flow.  Reported with train and deploy counts separated
                   because hiding the oracle cost would flatter it.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
from sklearn.tree import DecisionTreeClassifier

REPO = Path("/root/.hermes/c2-evasion-rl")
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))

from hidden_defender_env import (  # noqa: E402
    ACTION_NAMES, HiddenDefenderEnv, load_corpus,
)

REPORTS = REPO / "snort_validation/reports"
TARGET = 0.90
SEED = 42


def _valid(info) -> bool:
    return bool(info["evaded"] and info["semantics_ok"])


def random_sweep(seed: int = SEED):
    """No memory: random mechanism order per flow, retry until valid."""
    rng = np.random.default_rng(seed)
    flows = load_corpus("train")
    env = HiddenDefenderEnv(split="train", seed=seed)
    queries = 0
    solved = 0
    action_log = []
    for idx in range(len(flows)):
        env.reset()
        env._idx = idx
        order = list(range(env.action_space.n))
        rng.shuffle(order)
        for a in order:
            env._idx = idx
            _o, reward, _t, _tr, info = env.step(a)
            queries += 1
            if _valid(info):
                solved += 1
                action_log.append(info["action"])
                break
        if solved / len(flows) >= TARGET:
            break
    return {
        "method": "random_sweep", "queries": queries, "evaded": solved,
        "n_flows": len(flows), "evasion_pct": round(100.0 * solved / len(flows), 1),
        "actions_used": action_log,
    }


def greedy(seed: int = SEED, epsilon: float = 0.3):
    """Reuse the mechanism that worked on the nearest previous flow."""
    rng = np.random.default_rng(seed)
    flows = load_corpus("train")
    env = HiddenDefenderEnv(split="train", seed=seed)
    queries = 0
    solved = 0
    history = []          # (obs, action_index)
    eps = epsilon
    for idx in range(len(flows)):
        obs = np.asarray(flows[idx]["obs"], dtype=np.float32)
        if history and rng.random() >= eps:
            dists = [float(np.linalg.norm(obs - h[0])) for h in history]
            first = history[int(np.argmin(dists))][1]
            order = [first] + [a for a in range(env.action_space.n) if a != first]
        else:
            order = list(range(env.action_space.n))
            rng.shuffle(order)
        for a in order:
            env._idx = idx
            _o, _r, _t, _tr, info = env.step(a)
            queries += 1
            if _valid(info):
                solved += 1
                history.append((obs, a))
                break
        eps = max(0.05, eps * 0.99)
        if solved / len(flows) >= TARGET:
            break
    return {
        "method": "greedy", "queries": queries, "evaded": solved,
        "n_flows": len(flows), "evasion_pct": round(100.0 * solved / len(flows), 1),
        "final_epsilon": round(eps, 3),
    }


def supervised_tree(seed: int = SEED, depth: int = 3):
    """Oracle-labelled ceiling.  Train queries and deploy queries kept apart."""
    flows = load_corpus("train")
    env = HiddenDefenderEnv(split="train", seed=seed)
    X, y = [], []
    oracle_queries = 0
    for idx in range(len(flows)):
        obs = np.asarray(flows[idx]["obs"], dtype=np.float32)
        labelled = False
        for a in range(env.action_space.n):
            env._idx = idx
            _o, _r, _t, _tr, info = env.step(a)
            oracle_queries += 1
            if _valid(info):
                X.append(obs)
                y.append(a)
                labelled = True
                break
        if not labelled:
            X.append(obs)
            y.append(ACTION_NAMES.index("noop"))
    tree = DecisionTreeClassifier(max_depth=depth, random_state=seed)
    tree.fit(np.asarray(X), np.asarray(y))

    deploy_queries = 0
    solved = 0
    for idx in range(len(flows)):
        obs = np.asarray(flows[idx]["obs"], dtype=np.float32)
        action = int(tree.predict([obs])[0])
        env._idx = idx
        _o, _r, _t, _tr, info = env.step(action)
        deploy_queries += 1
        if _valid(info):
            solved += 1
    return {
        "method": "supervised_tree",
        "queries": deploy_queries,          # deployment cost only
        "oracle_queries": oracle_queries,   # cost of building the labels
        "evaded": solved, "n_flows": len(flows),
        "evasion_pct": round(100.0 * solved / len(flows), 1),
        "depth": depth, "note": "sees oracle labels; not achievable in practice",
    }


def main() -> int:
    REPORTS.mkdir(parents=True, exist_ok=True)
    results = {}
    for name, fn in (("random_sweep", random_sweep),
                     ("greedy", greedy),
                     ("supervised_tree", supervised_tree)):
        r = fn()
        results[name] = r
        out = REPORTS / f"baseline_{name}.json"
        out.write_text(json.dumps(r, indent=2))
        extra = f" (+{r['oracle_queries']} oracle)" if "oracle_queries" in r else ""
        print(f"[*] {name:>16}: {r['queries']} queries, {r['evasion_pct']}%{extra}")
        print(f"[+] {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
