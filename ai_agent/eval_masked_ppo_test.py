#!/usr/bin/env python3
"""Evaluate the saved MaskablePPO policy on the held-out TEST split under REAL Snort.

The training number (95.3% on train/replica) is a surrogate-scored claim.  This
script is the integrity check: it re-evaluates the SAVED model deterministically
on the 16 held-out flows with real Snort as the detector, batch_size=1, and
reports the semantics bar separately so a "detected" is never confused with
"evaded but broke the C2 command".
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

import numpy as np
from sb3_contrib import MaskablePPO

REPO = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO.parent / "snort_validation"))

from hidden_defender_env import HiddenDefenderEnv  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default=str(REPO.parent / "models/ppo_hidden_defender.zip"))
    ap.add_argument("--split", default="test")
    ap.add_argument("--real-snort", action="store_true",
                    help="score with the real Snort binary (slow, ~10s/flow)")
    ap.add_argument("--out", default=str(REPO.parent / "snort_validation/reports/ppo_masked_test.json"))
    args = ap.parse_args()

    env = HiddenDefenderEnv(split=args.split, seed=42, real_snort=args.real_snort)
    model = MaskablePPO.load(args.model, env=env)

    obs, _ = env.reset(seed=42)
    per_flow, actions, masked_used = [], Counter(), 0
    for _ in range(len(env._flows)):
        mask = env.action_masks()
        action, _ = model.predict(obs, action_masks=mask, deterministic=True)
        if not mask[int(action)]:
            masked_used += 1
        obs, reward, term, _trunc, info = env.step(int(action))
        actions[info["action"]] += 1
        per_flow.append({
            "flow_id": info["flow_id"],
            "framing": env._flows[env._idx - 1].get("framing", "?"),
            "action": info["action"],
            "alert": info["alert"],
            "evaded": info["evaded"],
            "semantics_ok": info["semantics_ok"],
            "reward": round(reward, 3),
        })

    n = len(per_flow)
    evaded = sum(f["evaded"] for f in per_flow)
    valid = sum(f["evaded"] and f["semantics_ok"] for f in per_flow)
    alerted = sum(f["alert"] for f in per_flow)

    result = {
        "method": "maskable_ppo",
        "scorer": "real_snort" if args.real_snort else "replica",
        "split": args.split,
        "n_flows": n,
        "alerted": alerted,
        "evaded": evaded,
        "valid_evasion": valid,
        "valid_evasion_pct": round(100.0 * valid / n, 1),
        "masked_actions_used": masked_used,
        "actions_chosen": dict(actions),
        "per_flow": per_flow,
    }
    Path(args.out).write_text(json.dumps(result, indent=2))
    print(f"[*] scorer={result['scorer']} split={args.split} n={n}")
    print(f"[*] valid evasion {valid}/{n} = {result['valid_evasion_pct']}%  "
          f"(alerted {alerted}, evaded-but-broken {evaded - valid})")
    print(f"[*] actions: {dict(actions)}")
    print(f"[*] masked actions used by policy: {masked_used}")
    print(f"[+] {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
