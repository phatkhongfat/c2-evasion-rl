#!/usr/bin/env python3
"""Verify PPO's learned policy against the REAL Snort binary.

Training used RealRulesReplica for speed (0.33 ms/flow).  This re-scores the
PPO policy on the held-out 16 flows with the actual `snort` binary (1340 ms/flow
measured) so the headline number is not resting on the surrogate.
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

import numpy as np
from stable_baselines3 import PPO

REPO = Path("/root/.hermes/c2-evasion-rl")
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))

from hidden_defender_env import ACTION_NAMES, HiddenDefenderEnv, load_corpus  # noqa: E402

REPORTS = REPO / "snort_validation/reports"
MODEL = REPO / "models/ppo_hidden_defender.zip"


def main() -> int:
    model = PPO.load(MODEL, device="cpu")
    flows = load_corpus("test")
    # Two envs on purpose: `real_env` scores with the snort binary, `rep_env`
    # scores the identical mutation with the replica.  Using one env for both
    # would compare snort against snort and report a meaningless 16/16.
    real_env = HiddenDefenderEnv(split="test", real_snort=True)
    rep_env = HiddenDefenderEnv(split="test", real_snort=False)

    evaded = 0
    n = 0
    chosen = Counter()
    replica_agree = 0
    for idx in range(len(flows)):
        obs = np.asarray(flows[idx]["obs"], dtype=np.float32)
        action, _ = model.predict(obs, deterministic=True)
        mech = ACTION_NAMES[int(action)]
        real_env._idx = idx
        _o, reward, _t, _tr, info = real_env.step(int(action))
        ev, sem, _alert = rep_env.score(flows[idx], mech)
        n += 1
        chosen[mech] += 1
        if info["evaded"] and info["semantics_ok"]:
            evaded += 1
        if (ev and sem) == (info["evaded"] and info["semantics_ok"]):
            replica_agree += 1

    result = {
        "method": "ppo_real_snort",
        "split": "test",
        "n_flows": n,
        "evaded": evaded,
        "evasion_pct": round(100.0 * evaded / n, 1) if n else 0.0,
        "actions_chosen": dict(chosen),
        "replica_agreement": f"{replica_agree}/{n}",
    }
    out = REPORTS / "ppo_hidden_defender_test.json"
    out.write_text(json.dumps(result, indent=2))
    print(f"[*] PPO on held-out test set, REAL Snort: {evaded}/{n} "
          f"({result['evasion_pct']}%)")
    print(f"[*] replica agreement: {replica_agree}/{n}")
    print(f"[*] actions chosen: {dict(chosen)}")
    print(f"[+] {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
