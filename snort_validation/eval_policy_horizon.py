#!/usr/bin/env python3
"""Score a trained policy's REAL Snort evasion as a function of mutation horizon.

Why this exists
---------------
`run_evaluation.py` + `validate_with_snort.py` (the plan's Task 5 harness) roll
each episode until the *default* env terminates — i.e. until the XGBoost judge
says "evaded".  A policy trained with `--snort-direct` was trained in an MDP
that instead terminates the moment the *Snort replica* says "evaded".  Those are
different horizons, so the Task 5 harness can report a detection rate that
reflects the harness's horizon rather than the policy's behaviour.

This script removes that confound: it runs the SAME seeded flows for a fixed
number of mutation steps (H = 0, 1, 2, 3, 5, 10), reconstructs a pcap for each
mutated flow and asks the REAL Snort binary for a verdict.  H=0 is the
no-mutation control (what the flow looks like with zero agent action).

Usage:
    /tmp/jev-poc/venv/bin/python snort_validation/eval_policy_horizon.py \
        --agent-model models/ppo_c2_evasion_agent_snortaware_direct_10.0.zip \
        --seed 42 --num-episodes 80

Output: prints the table and writes
    snort_validation/reports/horizon_sweep<suffix>.json
"""
import sys
import json
import argparse
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))

import numpy as np
from stable_baselines3 import PPO

from c2_evasion_env import C2EvasionEnv
from pool_loader import load_malicious_pool
from validate_with_snort import SnortValidator


def _features(env):
    """Current (possibly mutated) flow features, in validate_with_snort's shape."""
    s = env.current_sample
    return {
        'dur': float(s['dur']),
        'tot_pkts': int(s['tot_pkts']),
        'tot_bytes': int(s['tot_bytes']),
        'src_bytes': int(s['src_bytes']),
        'proto': str(env.current_proto),
        'state': str(env.current_state),
    }


def _make_env(pool, **kw):
    return C2EvasionEnv(
        malicious_data_pool=pool,
        model_path=str(REPO / "data/surrogate_ids_ctu13.pkl"),
        proto_encoder_path=str(REPO / "data/label_encoder_proto.pkl"),
        state_encoder_path=str(REPO / "data/label_encoder_state.pkl"),
        max_steps=10,
        **kw,
    )


def parse_args():
    ap = argparse.ArgumentParser()
    ap.add_argument("--agent-model",
                    default="models/ppo_c2_evasion_agent_snortaware_direct_10.0.zip")
    ap.add_argument("--num-episodes", type=int, default=80)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--horizons", type=int, nargs="+", default=[0, 1, 2, 3, 5, 10])
    ap.add_argument("--suffix", default="")
    return ap.parse_args()


def main():
    args = parse_args()
    model_path = REPO / args.agent_model
    if not model_path.exists():
        print(f"ERROR: model not found: {model_path}")
        sys.exit(1)

    pool = load_malicious_pool(verbose=True)
    validator = SnortValidator(REPO / "snort_validation/rules/snort.conf",
                               REPO / "snort_validation/pcaps")

    env = _make_env(pool)
    model = PPO.load(str(model_path), env=env, device="cpu")

    rows = []
    for H in args.horizons:
        eps = []
        for i in range(args.num_episodes):
            obs, _ = env.reset(seed=args.seed + i)
            for _ in range(H):
                action, _ = model.predict(obs, deterministic=True)
                obs, _r, done, trunc, _info = env.step(action)
                if done or trunc:
                    break
            f = _features(env)
            eps.append({'episode_id': i,
                        'original_features': f,
                        'mutated_features': f})
        res = validator.validate_episodes(eps)
        rows.append({
            'horizon': H,
            'detected': res['total_detected'],
            'total': res['total_flows'],
            'detection_rate': res['overall_detection_rate'],
            'evasion_rate': 1 - res['overall_detection_rate'],
        })
        print(f"  H={H:<3d} detected {res['total_detected']}/{res['total_flows']} "
              f"= {res['overall_detection_rate']*100:5.1f}%  "
              f"evasion {100*(1-res['overall_detection_rate']):5.1f}%")

    # The policy's own MDP: stop as soon as the Snort replica says "evaded"
    env2 = _make_env(pool, snort_direct=True, snort_direct_mode="replica")
    model2 = PPO.load(str(model_path), env=env2, device="cpu")
    eps = []
    lengths = []
    for i in range(args.num_episodes):
        obs, _ = env2.reset(seed=args.seed + i)
        done = trunc = False
        steps = 0
        while not done and not trunc:
            action, _ = model2.predict(obs, deterministic=True)
            obs, _r, done, trunc, _info = env2.step(action)
            steps += 1
        lengths.append(steps)
        f = _features(env2)
        eps.append({'episode_id': i, 'original_features': f, 'mutated_features': f})
    res = validator.validate_episodes(eps)
    own = {
        'detected': res['total_detected'],
        'total': res['total_flows'],
        'detection_rate': res['overall_detection_rate'],
        'evasion_rate': 1 - res['overall_detection_rate'],
        'episode_length_mean': float(np.mean(lengths)),
        'episode_length_max': int(max(lengths)),
        'frac_ran_to_max_steps': float(np.mean([1 if L >= 10 else 0 for L in lengths])),
    }

    report = {
        'agent_model': args.agent_model,
        'num_episodes': args.num_episodes,
        'seed': args.seed,
        'horizons': rows,
        'own_mdp_early_stop': own,
    }
    out = (REPO / "snort_validation/reports" /
           f"horizon_sweep{args.suffix}.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, 'w') as fh:
        json.dump(report, fh, indent=2)

    print()
    print(f"own MDP (early stop on replica): detected {own['detected']}/{own['total']} "
          f"= {own['detection_rate']*100:.1f}%  evasion {own['evasion_rate']*100:.1f}%")
    print(f"  episode length mean={own['episode_length_mean']:.2f} "
          f"max={own['episode_length_max']} "
          f"ran-to-10={own['frac_ran_to_max_steps']*100:.0f}%")
    print(f"\nReport: {out}")


if __name__ == "__main__":
    main()
