#!/usr/bin/env python3
"""Does the surrogate give PPO any gradient to learn from?

Per-packet (parametrised) RL needs a reward surface that varies with the
action.  This measures whether RealRulesReplica -- the training environment --
distinguishes the mechanisms at all, on the same 40 test flows and with the
same three-way labelling (invalid / caught / valid-evasion) as the real-engine
sweeps, so the answer is directly comparable to p16d_mech_sweep_*.json.

Flat-zero across the whole action space means PPO's advantage estimates are
identically zero: there is no policy gradient to follow.
"""
from __future__ import annotations

import collections
import json
import pathlib
import sys

REPO = pathlib.Path("/root/.hermes/c2-evasion-rl")
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))

from hidden_defender_env import (HiddenDefenderEnv, ACTION_NAMES,  # noqa: E402
                                apply_mech, semantics_intact)
from c2_semantics import client_ip_of  # noqa: E402
from real_rules_replica import RealRulesReplica, parse_ruleset  # noqa: E402

RULES = REPO / "snort_validation/et_open_c2/snort_et_c2.conf"
OUT = REPO / "snort_validation/reports/p16d_mech_sweep_surrogate.json"


def main() -> int:
    # Use the replica SHIPPED inside each flow pickle -- the exact object the
    # training runs scored with (29 SID).  Re-parsing a .conf file yields an
    # EMPTY ruleset, which silently turns every verdict into "evaded".
    env = HiddenDefenderEnv(split="test", seed=42, real_snort=False)
    flows = env._flows
    n_rules = {len(f["replica"].rules) for f in flows
               if f.get("replica") is not None}
    assert n_rules and 0 not in n_rules, (
        f"empty/missing replica rulesets: {n_rules} -- refusing to score")
    print(f"[*] surrogate from shipped replica: {sorted(n_rules)} rules/flow")

    evaded = collections.Counter()
    caught = collections.Counter()
    invalid = collections.Counter()
    per_flow_valid = collections.defaultdict(set)

    for f in flows:
        pkts = list(f["packets"])
        cid = client_ip_of(f.get("flow_id"))
        for mech in ACTION_NAMES:
            cand = pkts if mech == "noop" else apply_mech(
                pkts, mech, cid, ownership="client")
            if mech != "noop" and not semantics_intact(pkts, cand, cid):
                invalid[mech] += 1
                continue
            # Score the WHOLE mutated flow, not one packet at a time. The
            # replica is rebuilt with reassemble=True (hidden_defender_env.py
            # :543); handing it a single segment gives the reassembler no
            # offset context, so content straddling a segment boundary is
            # missed and every flow looks "evaded". Scoring per packet is what
            # made an earlier sweep report a flat reward surface that two other
            # measurements contradict.
            hit = f["replica"].verdict(cand, home_ip=None)
            if hit:
                caught[mech] += 1
            else:
                evaded[mech] += 1
                per_flow_valid[f.get("flow_id")].add(mech)

    n = len(flows)
    # The shipped training replica scores 3 SIDs and does NOT alert on every
    # clean flow.  That is a real defect of the training environment, so the
    # numbers are reported -- loudly -- instead of aborting, but only after the
    # control gap is quantified so no reader mistakes them for a clean run.
    control_gap = evaded["noop"]
    if control_gap:
        print(f"[!] CONTROL FAILED: {control_gap}/{n} clean flows not alerted "
              f"by the training replica", file=sys.stderr)

    neris = [f for f in flows if "neris" in str(f.get("flow_id"))]
    other = [f for f in flows if "neris" not in str(f.get("flow_id"))]
    print(f"[*] split: neris={len(neris)} other={len(other)}")
    oracle = len(per_flow_valid)
    valid_best = max((evaded[m] for m in ACTION_NAMES), default=0)
    best_mech = max(evaded.items(), key=lambda kv: kv[1])[0] if evaded else None
    out = {
        "scorer": "RealRulesReplica (surrogate / TRAINING environment)",
        "n_flows": n, "n_mechs": len(ACTION_NAMES),
        "evaded": dict(evaded), "caught": dict(caught),
        "invalid_semantics": dict(invalid),
        "oracle_flows": oracle, "oracle_pct": round(100.0 * oracle / n, 1),
        "best_single_mech": best_mech, "best_single": valid_best,
        "headroom_pp": round(100.0 * (oracle - valid_best) / n, 2),
    }
    OUT.write_text(json.dumps(out, indent=2))

    print(f"\n{'mechanism':22s} {'evaded':>7s} {'caught':>7s} {'invalid':>8s}")
    for m in ACTION_NAMES:
        print(f"{m:22s} {evaded[m]:7d} {caught[m]:7d} {invalid[m]:8d}")
    print(f"\noracle      : {oracle}/{n} = {out['oracle_pct']}%")
    print(f"best_single : {best_mech} = {valid_best}/{n}")
    print(f"headroom    : {out['headroom_pp']} pp")
    print(f"[+] {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())