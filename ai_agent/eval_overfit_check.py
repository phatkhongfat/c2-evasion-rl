#!/usr/bin/env python3
"""Overfit check: score a TRAIN-split sample with the SAME fixed pipeline.

If the policy only memorised the training flows, its held-out (test) evasion
should be well below its train-split evasion under identical scoring.  A random
seeded sample is used because train is 1153 flows and the first N would be
dominated by one capture.
"""
from __future__ import annotations

import argparse
import json
import random
import sys
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))

from hidden_defender_env import HiddenDefenderEnv  # noqa: E402
from eval_pipeline import client_ip_of, score_flow_real  # noqa: E402
from eval_fixed_pipeline import model_decisions  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default=str(REPO / "models/ppo_hidden_defender.zip"))
    ap.add_argument("--sample", type=int, default=20)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--out", default=str(REPO / "snort_validation/reports/overfit_check_FIXED.json"))
    args = ap.parse_args()

    from sb3_contrib import MaskablePPO

    env = HiddenDefenderEnv(split="train", seed=42, real_snort=False)
    model = MaskablePPO.load(args.model, env=env)
    by_id = {f["flow_id"]: f for f in env._flows}

    decisions = model_decisions(env, model)
    rng = random.Random(args.seed)
    sample = rng.sample(decisions, min(args.sample, len(decisions)))

    rows = []
    for i, (fid, mech) in enumerate(sample):
        f = by_id[fid]
        cip = client_ip_of(fid)
        base = score_flow_real(f["packets"], cip, attempt_id=i, mech=None)
        act = score_flow_real(f["packets"], cip, attempt_id=500 + i, mech=mech)
        rows.append({
            "flow_id": fid, "framing": f.get("framing", "?"), "action": mech,
            "baseline_alert": base["alert"], "alert": act["alert"],
            "evaded": act["evaded"], "semantics_ok": act["semantics_ok"],
            "valid_evasion": act["valid_evasion"],
        })
        print(f"[{i + 1}/{len(sample)}] {fid[:44]:44s} {mech:8s} "
              f"-> {'ALERT' if act['alert'] else 'EVADED'}")

    n = len(rows)
    result = {
        "method": "maskable_ppo", "scorer": "real_snort",
        "pipeline": "fixed_6_fixes", "split": "train",
        "sample_size": n, "sample_seed": args.seed,
        "valid_evasion": sum(r["valid_evasion"] for r in rows),
        "valid_evasion_pct": round(100.0 * sum(r["valid_evasion"] for r in rows) / n, 1),
        "baseline_alerted": sum(1 for r in rows if r["baseline_alert"]),
        "actions_chosen": dict(Counter(r["action"] for r in rows)),
        "per_flow": rows,
    }
    Path(args.out).write_text(json.dumps(result, indent=2))
    print(f"[*] TRAIN sample valid evasion {result['valid_evasion']}/{n} = "
          f"{result['valid_evasion_pct']}%  (baseline alerted "
          f"{result['baseline_alerted']}/{n})")
    print(f"[+] {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
