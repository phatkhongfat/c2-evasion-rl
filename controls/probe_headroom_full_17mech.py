"""DECISIVE for direction 1: oracle vs best-single headroom under the FULL
21374-rule set, with home_ip=None (the mode the env actually scores in).

CORRECTION (2026-10-14): the earlier 0.35 pp figure and the "455/1153 flows
have no detection" claim were both artifacts of passing home_ip into
firing_rules. Measured properly: 0 flows lack detection under either ruleset.
Shipped replicas expose 6 SIDs; the full set exposes 29.
"""
import collections
import json
import pathlib
import sys
import time

ROOT = pathlib.Path("/root/.hermes/c2-evasion-rl")
sys.path[:0] = [str(ROOT), str(ROOT / "ai_agent"), str(ROOT / "snort_validation")]

from hidden_defender_env import (HiddenDefenderEnv, ACTION_NAMES,  # noqa: E402
                                apply_mech)
from c2_semantics import client_ip_of  # noqa: E402
from real_rules_replica import RealRulesReplica, parse_ruleset, RULES  # noqa: E402

MECHS = ["noop", "split8", "split16", "split24", "pad16", "reorder", "ttl",
         "http_header_case", "query_param_prepend"]

env = HiddenDefenderEnv(split="train", seed=42, real_snort=False)
full = parse_ruleset(RULES)
rep = RealRulesReplica(full)
flows = env._flows

evaded = collections.Counter()
oracle = 0
n = len(flows)
t0 = time.time()

for i, f in enumerate(flows):
    pkts = list(f["packets"])
    hits = []
    cid = client_ip_of(f.get("flow_id"))
    for m in MECHS:
        cand = pkts if m == "noop" else apply_mech(pkts, m, cid,
                                                   ownership="client")
        ev = not rep.verdict(cand)          # home_ip=None, as the env scores
        evaded[m] += ev
        if ev:
            hits.append(m)
    if hits:
        oracle += 1
    if (i + 1) % 100 == 0:
        print(f"  {i+1}/{n} {time.time()-t0:.0f}s", flush=True)

best = max(evaded[m] for m in MECHS if m != "noop")
out = {"n_flows": n, "evaded": dict(evaded), "oracle": oracle,
       "best_single": best,
       "headroom_pp": round(100 * (oracle - best) / n, 3)}
print(json.dumps(out, indent=1))
pathlib.Path("/tmp/headroom_full_rules.json").write_text(json.dumps(out, indent=1))