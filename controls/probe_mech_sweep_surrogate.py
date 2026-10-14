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

import argparse
import collections
import json
import pathlib
import sys

REPO = pathlib.Path("/root/.hermes/c2-evasion-rl")
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))

from hidden_defender_env import (HiddenDefenderEnv, ACTION_NAMES,  # noqa: E402
                                apply_mech, semantics_intact)
from c2_semantics import client_ip_of, semantics_ok_reward  # noqa: E402
from real_rules_replica import RealRulesReplica, parse_ruleset  # noqa: E402

# D8 is the reward gate (hidden_defender_env.py:606); `strict` stays so the
# difference remains reproducible instead of being silently forgotten.
GATES = {"d8": semantics_ok_reward, "strict": semantics_intact}

RULES = REPO / "snort_validation/et_open_c2/et_open_c2.rules"
OUT = REPO / "snort_validation/reports/p16d_mech_sweep_surrogate.json"
REAL_SNORT = REPO / "snort_validation/reports/p17_mech_sweep_real_snort_d8.json"


_FULL_RULESET = None


def _full_ruleset():
    """Parse the whole ET Open C2 conf once, not once per flow."""
    global _FULL_RULESET
    if _FULL_RULESET is None:
        rules = parse_ruleset(RULES)
        assert rules, "parsed zero rules from the conf -- refusing to score"
        _FULL_RULESET = rules
    return _FULL_RULESET


def _scorer(flow, args, timeout):
    """Pick the replica to score this flow with.

    `frag3_timeout=None` keeps the shipped object untouched so a run without
    --frag3-timeout is bit-for-bit the training-time behaviour.
    """
    base = flow["replica"]
    if args.ruleset == "full":
        base = RealRulesReplica(_full_ruleset(), reassemble=True)
    if timeout is None and args.ruleset == "shipped":
        return flow["replica"]
    return RealRulesReplica(base.rules, reassemble=True,
                            frag3_timeout=timeout)


def _fragment_count(packets) -> int:
    """How many of these packets are IPv4 fragments.

    A mechanism that never fragments cannot be helped by anything about
    reassembly lifetime, so this is what separates the mechanisms a frag3
    timeout can possibly favour from the ones it can never touch.
    """
    from scapy.all import IP
    n = 0
    for p in packets:
        if IP in p:
            off = (p[IP].frag & 0x1FFF) * 8
            if bool(p[IP].flags) or off > 0:
                n += 1
    return n


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--frag3-timeout", type=float, default=None,
                    help="model a reassembly session lifetime, in seconds")
    ap.add_argument("--gate", choices=sorted(GATES), default="d8",
                    help="semantics gate: 'd8' matches the reward, 'strict' "
                         "is byte-equality")
    ap.add_argument("--ruleset", choices=("shipped", "full"), default="shipped",
                    help="'shipped' = the 3-SID replica inside each flow "
                         "pickle, which is what training scored with; 'full' "
                         "= all rules parsed from snort_et_c2.conf, which is "
                         "what the real engine runs")
    ap.add_argument("--out", type=pathlib.Path, default=OUT)
    args = ap.parse_args()
    timeout = args.frag3_timeout
    OUT_PATH = args.out
    gate = GATES[args.gate]
    # Use the replica SHIPPED inside each flow pickle -- the exact object the
    # training runs scored with (29 SID).  Re-parsing a .conf file yields an
    # EMPTY ruleset, which silently turns every verdict into "evaded".
    env = HiddenDefenderEnv(split="test", seed=42, real_snort=False)
    flows = env._flows
    n_rules = {len(f["replica"].rules) for f in flows
               if f.get("replica") is not None}
    assert n_rules and 0 not in n_rules, (
        f"empty/missing replica rulesets: {n_rules} -- refusing to score")
    print(f"[*] surrogate ruleset={args.ruleset} "
          f"(flow pickle ships {sorted(n_rules)} rules/flow)")

    evaded = collections.Counter()
    caught = collections.Counter()
    invalid = collections.Counter()
    n_frags = collections.Counter()
    per_flow_valid = collections.defaultdict(set)

    for f in flows:
        pkts = list(f["packets"])
        cid = client_ip_of(f.get("flow_id"))
        for mech in ACTION_NAMES:
            cand = pkts if mech == "noop" else apply_mech(
                pkts, mech, cid, ownership="client")
            if mech != "noop" and not gate(pkts, cand, cid):
                invalid[mech] += 1
                continue
            # Score the WHOLE mutated flow: per-packet scoring gives the reassembler no
            # offset context, so a rule straddling a segment boundary is missed and every
            # flow looks "evaded" -- the flat surface two other measurements contradict.
            scorer = _scorer(f, args, timeout)
            hit = scorer.verdict(cand, home_ip=None)
            n_frags[mech] += _fragment_count(cand)
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
        "frag3_timeout_s": timeout,
        "gate": args.gate,
        "ruleset": args.ruleset,
        "n_flows": n, "n_mechs": len(ACTION_NAMES),
        "evaded": dict(evaded), "caught": dict(caught),
        "invalid_semantics": dict(invalid),
        "frag_packets_per_mech": dict(n_frags),
        "oracle_flows": oracle, "oracle_pct": round(100.0 * oracle / n, 1),
        "best_single_mech": best_mech, "best_single": valid_best,
        "headroom_pp": round(100.0 * (oracle - valid_best) / n, 2),
    }
    OUT_PATH.write_text(json.dumps(out, indent=2))

    print(f"\n{'mechanism':22s} {'evaded':>7s} {'caught':>7s} {'invalid':>8s} "
              f"{'frags':>7s} {'snort':>7s} {'delta':>7s}")
    real = {}
    if REAL_SNORT.exists():
        real = json.loads(REAL_SNORT.read_text()).get("evaded", {})
    for m in ACTION_NAMES:
        sn = real.get(m, 0)
        print(f"{m:22s} {evaded[m]:7d} {caught[m]:7d} {invalid[m]:8d} "
              f"{n_frags[m]:7d} {sn:7d} {evaded[m] - sn:+7d}")
    print(f"\noracle      : {oracle}/{n} = {out['oracle_pct']}%")
    print(f"best_single : {best_mech} = {valid_best}/{n}")
    print(f"headroom    : {out['headroom_pp']} pp")
    print(f"[+] {OUT_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())