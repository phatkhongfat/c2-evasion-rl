"""Per-action reward spread: which actions give PPO a gradient to climb?

Reachability alone does not decide whether an action belongs in the action
space.  An action earns its place if, on at least some flows, it is the ONLY
one that reaches +10.  Three outcomes make an action dead weight:

  dead_masked    never selectable (masked on 100% of flows)
  dead_zero      selectable, but reward never rises above the noop baseline
  dead_twin      selectable and can score, but does so on exactly the same
                 flows as another action, so the policy cannot tell them apart
                 and the extra head only dilutes the gradient

We measure all three over the 40 test flows.  Reward comes from env.step(),
i.e. the reward path itself, not a re-implementation.
"""
import collections
import json
import pathlib
import sys

import numpy as np

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "ai_agent"), str(ROOT / "snort_validation")]

from hidden_defender_env import ACTION_NAMES, HiddenDefenderEnv  # noqa: E402


def main() -> None:
    env = HiddenDefenderEnv(split="test", seed=42, real_snort=False)
    flows = list(env._flows)
    n = len(flows)

    # reward[action][flow]
    reward = np.full((len(ACTION_NAMES), n), np.nan, dtype=np.float64)
    masked = np.zeros((len(ACTION_NAMES), n), dtype=bool)

    for fi, flow in enumerate(flows):
        for ai, name in enumerate(ACTION_NAMES):
            env._idx = fi
            m = env._compute_action_mask()
            masked[ai, fi] = not m[ai]
            if not m[ai]:
                continue
            env._idx = fi
            # clone state so a probe step cannot drift the episode
            env._idx = fi
            obs = env._obs()
            try:
                _, reward_val, term, trunc, _ = env.step(ai)
            except Exception as exc:  # a broken action is itself a finding
                reward[ai, fi] = np.nan
                print(f"  !! {name} raised on flow {fi}: {exc}")
                continue
            reward[ai, fi] = reward_val
            env._idx = fi  # step() advances _idx; restore for the next action
            del obs, term, trunc

    baseline = reward[ACTION_NAMES.index("noop")]
    top = reward.max(axis=0)

    rows = []
    for ai, name in enumerate(ACTION_NAMES):
        r = reward[ai]
        sel = ~masked[ai]
        r_sel = r[sel]
        # wins: reachable AND strictly better than noop on this flow
        wins = sel & (r > baseline + 1e-9)
        wins_where_best = sel & np.isclose(r, top, rtol=0, atol=1e-9) & (top > baseline + 1e-9)
        rows.append({
            "action": name,
            "selectable": int(sel.sum()),
            "mean_reward": float(np.nanmean(r_sel)) if sel.any() else None,
            "max_reward": float(np.nanmax(r_sel)) if sel.any() else None,
            "beats_noop": int(wins.sum()),
            "ties_best": int(wins_where_best.sum()),
            "reward_vector": [None if np.isnan(v) else round(float(v), 3) for v in r],
        })

    # dead-weight classification
    for row in rows:
        if row["selectable"] == 0:
            row["verdict"] = "dead_masked"
        elif row["beats_noop"] == 0:
            row["verdict"] = "dead_zero"
        else:
            row["verdict"] = "live"

    # twins: live actions whose per-flow reward vector is identical, so the
    # policy cannot distinguish them and one is pure gradient dilution.
    def win_set(row):
        return {i for i, v in enumerate(row["reward_vector"])
                if v is not None and v > baseline[i] + 1e-9}

    live = [r for r in rows if r["verdict"] == "live"]
    for idx, r in enumerate(live):
        r["wins_set"] = sorted(win_set(r))
        r["twins"] = [o["action"] for j, o in enumerate(live)
                      if j > idx and win_set(o) == win_set(r)]

    print(f"{'action':22s} {'select':>7s} {'meanR':>7s} {'maxR':>7s} "
          f"{'beats_noop':>11s} {'twin':>28s}  verdict")
    for r in rows:
        mr = "n/a" if r["mean_reward"] is None else f"{r['mean_reward']:+.2f}"
        xr = "n/a" if r["max_reward"] is None else f"{r['max_reward']:+.2f}"
        tw = ",".join(r.get("twins", [])[:2]) or "-"
        print(f"{r['action']:22s} {r['selectable']:>7d} {mr:>7s} {xr:>7s} "
              f"{r['beats_noop']:>11d} {tw:>28s}  {r['verdict']}")

    print()
    print("noop baseline: mean %+.3f, max %+.3f" % (
        np.nanmean(baseline), np.nanmax(baseline)))
    best_per_flow = top
    print("Best achievable per flow (max over reachable actions): mean %+.3f, "
          "max %+.3f, flows where noop is already best: %d/%d"
          % (np.nanmean(best_per_flow), np.nanmax(best_per_flow),
             int(np.sum(np.isclose(best_per_flow, baseline, atol=1e-9))), n))

    dead = [r for r in rows if r["verdict"] != "live"]
    print()
    print(f"Dead actions: {len(dead)}/{len(rows)}")
    for r in dead:
        print(f"  {r['action']:22s} {r['verdict']}")

    out = ROOT / "snort_validation/reports/p17_ppo_action_reward_spread.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({
        "n_flows": n,
        "noop_mean": float(np.nanmean(baseline)),
        "best_per_flow_mean": float(np.nanmean(best_per_flow)),
        "actions": rows,
        "dead": [r["action"] for r in dead],
    }, indent=2))
    print(f"\n-> {out.relative_to(ROOT)}")


if __name__ == "__main__":
    main()