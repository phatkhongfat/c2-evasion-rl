"""What reward surface does PPO actually see?

Uses env.score() -- the authoritative path -- and then applies the exact
formula from HiddenDefenderEnv.step() (:707-729) rather than re-deriving it:

    evade & sem       -> +REWARD_EVADE
    evade & !sem      -> +REWARD_BREAK_SEMANTICS
    detected          -> +REWARD_ALERTED
    then -ACTION_COSTS[i]
    then +PROTOCOL_MATCH_BONUS if evaded & sem & mech is protocol-appropriate

The question is not "what looks good" but where the surface is flat: an
action that always returns the same reward gives PPO nothing to climb.
"""
import collections
import pathlib
import sys

ROOT = pathlib.Path("/root/.hermes/c2-evasion-rl")
sys.path[:0] = [str(ROOT), str(ROOT / "ai_agent"), str(ROOT / "snort_validation")]

from hidden_defender_env import (HiddenDefenderEnv, ACTION_NAMES,  # noqa: E402
                                ACTION_COSTS, PROTOCOL_APPROPRIATE,
                                PROTOCOL_MATCH_BONUS, REWARD_EVADE,
                                REWARD_ALERTED, REWARD_BREAK_SEMANTICS)

TIMEOUT = 60.0
env = HiddenDefenderEnv(split="test", seed=42, real_snort=False,
                        reassemble=True, replica_frag3_timeout=TIMEOUT)
flows = env._flows
n = len(flows)


def reward_of(flow, idx, mech):
    """Verbatim transcription of step()'s reward block."""
    evaded, sem, alert, _ = env.score(flow, mech)
    if evaded and sem:
        reward = REWARD_EVADE
    elif evaded and not sem:
        reward = REWARD_BREAK_SEMANTICS
    else:
        reward = REWARD_ALERTED
    reward -= ACTION_COSTS[idx]
    if evaded and sem:
        if mech in PROTOCOL_APPROPRIATE.get(flow.get("framing", "unknown"), ()):
            reward += PROTOCOL_MATCH_BONUS
    return reward, bool(evaded and sem), bool(evaded)


rewards = collections.defaultdict(list)
reachable = collections.Counter()
undetected = collections.Counter()
for flow in flows:
    for idx, mech in enumerate(ACTION_NAMES):
        r, good, ev = reward_of(flow, idx, mech)
        rewards[mech].append(r)
        reachable[mech] += int(good)
        undetected[mech] += int(ev)

print(f"flows={n}  frag3_timeout={TIMEOUT}s\n")
print(f"{'mech':22s} {'evade_ok':>9s} {'undet':>7s} {'mean_r':>8s} "
      f"{'min':>7s} {'max':>7s} {'distinct':>9s}")
flat = []
for m in ACTION_NAMES:
    rs = rewards[m]
    print(f"{m:22s} {reachable[m]:9d} {undetected[m]:7d} "
          f"{sum(rs)/len(rs):8.3f} {min(rs):7.2f} {max(rs):7.2f} "
          f"{len(set(rs)):9d}")
    if len(set(rs)) == 1:
        flat.append(m)

print(f"\nFLAT (constant reward on every flow): {len(flat)}/{len(ACTION_NAMES)}")
for m in flat:
    print(f"  {m:22s} reward={rewards[m][0]:+.2f}  evade_ok={reachable[m]}/{n}")

best = max(ACTION_NAMES, key=lambda m: sum(rewards[m]) / len(rewards[m]))
worst = min(ACTION_NAMES, key=lambda m: sum(rewards[m]) / len(rewards[m]))
print(f"\nhighest mean reward : {best} ({sum(rewards[best])/n:+.3f})")
print(f"lowest  mean reward : {worst} ({sum(rewards[worst])/n:+.3f})")
print(f"spread              : {sum(rewards[worst])/n:+.2f} .. "
      f"{sum(rewards[best])/n:+.2f}")
print(f"actions reaching the evade floor (+{REWARD_EVADE}): "
      f"{[m for m in ACTION_NAMES if reachable[m]]}")
print(f"\nnoop reward = {rewards['noop'][0]:+.2f} on every flow -- "
      f"{'a floor the policy must beat' if not reachable['noop'] else 'not a floor'}")