"""Does the reward gate hand +10 to flows that are NOT byte-preserving?

env.score (:606) gates the reward on semantics_ok_reward -- the lenient D8
gate (byte OR D7 OR D5). Every honest number in this project has been
measured with semantics_intact, the strict byte-equality check.

If the lenient gate accepts a mutation the strict one rejects, the reward
pays REWARD_EVADE for a stream whose bytes changed -- credit for an evasion
that did not happen. This measures the gap mechanism by mechanism.
"""
import collections
import pathlib
import sys

ROOT = pathlib.Path("/root/.hermes/c2-evasion-rl")
sys.path[:0] = [str(ROOT), str(ROOT / "ai_agent"), str(ROOT / "snort_validation")]

from hidden_defender_env import (HiddenDefenderEnv, ACTION_NAMES,  # noqa: E402
                                apply_mech, semantics_intact,
                                semantics_ok_reward)
from c2_semantics import client_ip_of  # noqa: E402

TIMEOUT = 60.0
env = HiddenDefenderEnv(split="test", seed=42, real_snort=False,
                        reassemble=True, replica_frag3_timeout=TIMEOUT)
flows = env._flows
n = len(flows)

print(f"flows={n}   reward gate=lenient D8   audit gate=strict byte-equality\n")
print(f"{'mech':22s} {'lenient_ok':>11s} {'strict_ok':>10s} {'GAP':>5s} "
      f"{'silent':>7s}")
gaps = collections.Counter()
examples = {}
for mech in ACTION_NAMES:
    lenient = strict = 0
    silent = 0
    for flow in flows:
        pkts = flow["packets"]
        cip = client_ip_of(flow.get("flow_id"))
        mut = apply_mech(pkts, mech, cip, ownership=env.ownership)
        if semantics_ok_reward(pkts, mut, cip):
            lenient += 1
        if semantics_intact(pkts, mut, cip):
            strict += 1
        else:
            if semantics_ok_reward(pkts, mut, cip):
                silent += 1
                examples.setdefault(mech, flow["flow_id"])
    gaps[mech] = lenient - strict
    flag = "  <== " if silent else ""
    print(f"{mech:22s} {lenient:11d} {strict:10d} {lenient-strict:5d} "
          f"{silent:7d}{flag}")

print("\nsilent failures = reward gate says OK, strict byte-equality says BROKEN")
print("these are the flows that collect REWARD_EVADE without being an evasion\n")
for m, c in gaps.items():
    if c:
        print(f"  {m:22s} {c:3d} flow(s) credited but not byte-preserving"
              + (f"   e.g. {examples[m]}" if m in examples else ""))