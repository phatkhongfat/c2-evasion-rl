"""Which ACTION_NAMES can the PPO mask even pick, and which are worth picking?

The action space is not uniform.  Two things decide an action's fate:

  1. Reachability.  `action_masks()` masks out actions that do not apply to the
     flow's protocol.  A masked action is not "wrong", it is unreachable --
     the policy gets no gradient signal either way.  We count how often each
     action is UNMASKED, i.e. actually selectable.

  2. Worth.  Among reachable actions, which ones can end in +10 rather than
     a semantics-break (-10)?  This is the reward surface question, and it is
     the one that decides whether PPO has anything to climb toward.

We report both, per action, over the same 40 test flows the oracle sweep
used, so the numbers line up with the Snort table already on disk.
"""
import collections
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "ai_agent"), str(ROOT / "snort_validation")]

from hidden_defender_env import (  # noqa: E402
    ACTION_NAMES,
    ACTION_COSTS,
    REWARD_BREAK_SEMANTICS,
    REWARD_EVADE,
    HiddenDefenderEnv,
    apply_mech,
    mech_applicable,
    payloads_of,
)
from c2_semantics import semantics_ok_reward  # noqa: E402


def main() -> None:
    env = HiddenDefenderEnv(split="test", seed=42, real_snort=False)
    flows = list(env._flows)

    reachable = collections.Counter()
    applies = collections.Counter()
    broke = collections.Counter()
    cost = {}
    n = len(flows)

    for flow in flows:
        pkts = list(flow["packets"])
        cid = flow["flow_id"]
        masks = env.action_masks()
        for i, name in enumerate(ACTION_NAMES):
            if not masks[i]:
                continue
            reachable[name] += 1
            cost[name] = ACTION_COSTS.get(i, ACTION_COSTS.get(name))
            if not mech_applicable(payloads_of(pkts), name):
                continue
            applies[name] += 1
            try:
                out = apply_mech(pkts, name, client_ip=cid)
            except Exception:
                continue
            ok = semantics_ok_reward(pkts, out, cid)
            if not ok:
                broke[name] += 1

    out_path = ROOT / "snort_validation/reports/p17_ppo_action_reachability.json"
    rows = []
    print(f"{'#':>2}  {'action':22s} {'unmasked':>9s} {'applies':>8s} {'rewards':>8s} "
          f"{'breaks':>7s} {'cost':>7s}")
    for i, name in enumerate(ACTION_NAMES):
        r = reachable[name]
        a = applies[name]
        # keeps its semantics gate: applies minus breaks
        rewards = a - broke[name]
        b = broke[name]
        rows.append({
            "action": name,
            "unmasked": r,
            "applies": a,
            "rewards_semantics_ok": rewards,
            "breaks_semantics": b,
            "cost": cost.get(name),
        })
        print(f"{i:>2}  {name:22s} {r:>9d} {a:>8d} {rewards:>8d} {b:>7d} "
              f"{str(cost.get(name)):>7s}")

    never = [r["action"] for r in rows if r["unmasked"] == 0]
    always_break = [r["action"] for r in rows if r["applies"] > 0
                    and r["rewards_semantics_ok"] == 0]
    dead = [r["action"] for r in rows if r["applies"] > 0
            and r["rewards_semantics_ok"] == 0 and r["unmasked"] < r["applies"]]

    print()
    print(f"Tổng flow: {n}")
    print(f"Action KHÔNG BAO GIỜ được chọn (masked 100%): {len(never)} {never}")
    print(f"Action luôn phá semantics khi áp dụng: {len(always_break)} {always_break}")
    print()
    print("Bảng đầy đủ:")
    for r in rows:
        print(f"  {r['action']:22s} unmasked={r['unmasked']:2d}/{n} "
              f"applies={r['applies']:2d} ok={r['rewards_semantics_ok']:2d} "
              f"breaks={r['breaks_semantics']:2d}")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps({
        "n_flows": n,
        "reward_evade": REWARD_EVADE,
        "reward_break_semantics": REWARD_BREAK_SEMANTICS,
        "actions": rows,
        "never_masked_off": never,
        "always_breaks": always_break,
    }, indent=2))
    print()
    print(f"-> {out_path.relative_to(ROOT)}")


if __name__ == "__main__":
    main()