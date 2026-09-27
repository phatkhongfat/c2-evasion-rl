#!/usr/bin/env python3
"""Re-run every method on the held-out test set with the REAL Snort binary.

The train-set numbers came from RealRulesReplica for speed, but the replica
agrees with snort on only 9/16 test flows, so a replica-only table would be
measuring the surrogate instead of the defender.  This is the table for the
writeup: identical policies, identical query accounting, every verdict from the
real binary.

Strategy: score all 16 x 12 (flow, mechanism) pairs up front in batched snort
invocations, then replay each policy's decision order against that matrix and
count CACHE MISSES as queries.  A miss is exactly one probe a method would have
spent on the defender, so the accounting stays honest while the wall-clock cost
drops from ~30 min of sequential probing to a few minutes of batched calls.
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

import numpy as np
from sklearn.tree import DecisionTreeClassifier
from stable_baselines3 import PPO

REPO = Path("/root/.hermes/c2-evasion-rl")
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))

from hidden_defender_env import (  # noqa: E402
    ACTION_NAMES, HiddenDefenderEnv, apply_mech, load_corpus, payloads_of,
    semantics_intact,
)
from snort_batch_service import SnortBatchService  # noqa: E402

REPORTS = REPO / "snort_validation/reports"
MODEL = REPO / "models/ppo_hidden_defender.zip"
SEED = 42


def score_matrix(flows, batch_size=32):
    """{(flow_idx, mech): (evaded, semantics_ok)} from the real snort binary."""
    combos = [(i, m) for i in range(len(flows)) for m in ACTION_NAMES]
    svc = SnortBatchService(batch_size=batch_size)
    matrix = {}
    for start in range(0, len(combos), batch_size):
        chunk = combos[start:start + batch_size]
        items = []
        for k, (i, mech) in enumerate(chunk):
            mut = apply_mech(flows[i]["packets"], mech)
            items.append((mut, k))
        verdicts = svc.verdicts(items)
        for k, (i, mech) in enumerate(chunk):
            orig = payloads_of(flows[i]["packets"])
            mut = apply_mech(flows[i]["packets"], mech)
            sem = semantics_intact(orig, mut)
            alert = verdicts.get(k, True)
            matrix[(i, mech)] = (not alert, sem)
        print(f"    scored {start + len(chunk)}/{len(combos)}")
    print(f"[*] snort stats: {svc.stats()}")
    return matrix


class QueryCounter:
    """Count distinct (flow, mechanism) probes -- one defender query each."""

    def __init__(self, matrix):
        self.matrix = matrix
        self.seen = set()
        self.queries = 0

    def valid(self, i, mech):
        if (i, mech) not in self.seen:
            self.seen.add((i, mech))
            self.queries += 1
        ev, sem = self.matrix[(i, mech)]
        return bool(ev and sem)


def train_tree():
    """Depth-3 tree fitted on replica-labelled TRAIN split (as trained)."""
    train = load_corpus("train")
    env = HiddenDefenderEnv(split="train", real_snort=False)
    X, y = [], []
    for idx, f in enumerate(train):
        lab = None
        for a in range(len(ACTION_NAMES)):
            env._idx = idx
            _o, _r, _t, _tr, info = env.step(a)
            if info["evaded"] and info["semantics_ok"]:
                lab = a
                break
        X.append(f["obs"])
        y.append(lab if lab is not None else ACTION_NAMES.index("noop"))
    return DecisionTreeClassifier(max_depth=3, random_state=SEED).fit(
        np.asarray(X), np.asarray(y))


def main() -> int:
    flows = load_corpus("test")
    n = len(flows)
    print(f"[*] scoring {n * len(ACTION_NAMES)} (flow, mechanism) pairs "
          f"with the real snort binary ...")
    M = score_matrix(flows)
    print("[+] matrix done\n")

    rows = {}
    rng = np.random.default_rng(SEED)

    # -- random_sweep: no memory, random order, retry until valid
    q = QueryCounter(M)
    solved = 0
    for i in range(n):
        order = list(range(len(ACTION_NAMES)))
        rng.shuffle(order)
        for a in order:
            if q.valid(i, ACTION_NAMES[a]):
                solved += 1
                break
    rows["random_sweep"] = {"queries": q.queries, "evaded": solved}

    # -- greedy: reuse the mechanism that worked on the nearest flow
    q = QueryCounter(M)
    solved = 0
    history = []
    eps = 0.3
    for i in range(n):
        obs = np.asarray(flows[i]["obs"], dtype=np.float32)
        if history and rng.random() >= eps:
            d = [float(np.linalg.norm(obs - h[0])) for h in history]
            first = history[int(np.argmin(d))][1]
            order = [first] + [a for a in range(len(ACTION_NAMES)) if a != first]
        else:
            order = list(range(len(ACTION_NAMES)))
            rng.shuffle(order)
        for a in order:
            if q.valid(i, ACTION_NAMES[a]):
                solved += 1
                history.append((obs, a))
                break
        eps = max(0.05, eps * 0.99)
    rows["greedy"] = {"queries": q.queries, "evaded": solved}

    # -- supervised_tree: oracle-labelled ceiling
    q = QueryCounter(M)
    tree = train_tree()
    solved = 0
    for i in range(n):
        a = int(tree.predict([np.asarray(flows[i]["obs"], dtype=np.float32)])[0])
        if q.valid(i, ACTION_NAMES[a]):
            solved += 1
    rows["supervised_tree"] = {"queries": q.queries, "evaded": solved}

    # -- ppo
    q = QueryCounter(M)
    model = PPO.load(MODEL, device="cpu")
    solved = 0
    chosen = Counter()
    for i in range(n):
        a, _ = model.predict(np.asarray(flows[i]["obs"], dtype=np.float32),
                             deterministic=True)
        mech = ACTION_NAMES[int(a)]
        chosen[mech] += 1
        if q.valid(i, mech):
            solved += 1
    rows["ppo"] = {"queries": q.queries, "evaded": solved,
                   "actions_chosen": dict(chosen)}

    for name, r in rows.items():
        r["n_flows"] = n
        r["evasion_pct"] = round(100.0 * r["evaded"] / n, 1)

    out = REPORTS / "hidden_defender_real_snort_test.json"
    out.write_text(json.dumps(rows, indent=2))

    print(f"[*] held-out test set ({n} flows), REAL Snort verdict per query\n")
    print(f"{'method':>18} {'queries':>8} {'evaded':>9} {'pct':>7}")
    print("-" * 46)
    for name in ("random_sweep", "greedy", "supervised_tree", "ppo"):
        r = rows[name]
        print(f"{name:>18} {r['queries']:>8} {r['evaded']:>6}/{n} "
              f"{r['evasion_pct']:>6}%")
    print(f"\n[*] PPO actions: {rows['ppo']['actions_chosen']}")
    print(f"[+] {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
