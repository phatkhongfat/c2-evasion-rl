#!/usr/bin/env python3
"""Why the training replica misses 16/40 clean flows, and would the FULL
implementable ruleset catch them?

The shipped replica carries 3 SIDs.  This loads the full ET Open C2 ruleset,
counts what parses, and reports which SIDs actually fire per capture -- in
particular whether any rule fires on the 20110811-neris flows that the 3-SID
subset never alerts on.

Diagnostic only: it decides whether "reload the full ruleset into the
replica" is a real fix or a no-op before any of that work is done.
"""
from __future__ import annotations

import collections
import pathlib
import sys

REPO = pathlib.Path("/root/.hermes/c2-evasion-rl")
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))

from hidden_defender_env import HiddenDefenderEnv  # noqa: E402
from real_rules_replica import RealRulesReplica, parse_ruleset  # noqa: E402

RULES = REPO / "snort_validation/et_open_c2/et_open_c2.rules"


def main() -> int:
    rules = parse_ruleset(RULES)
    rep = RealRulesReplica(rules, reassemble=True)
    n_total = sum(1 for _ in RULES.open(errors="ignore")
                  if _.strip() and not _.lstrip().startswith("#"))
    print(f"[*] parsed {len(rep.rules)} rules from {n_total} rule lines "
          f"({100.0*(1-len(rep.rules)/n_total):.1f}% dropped as unimplementable)")

    env = HiddenDefenderEnv(split="test", seed=42, real_snort=False)
    flows = env._flows

    fired = collections.defaultdict(set)
    missed, shipped_missed = [], []
    for f in flows:
        fid = str(f.get("flow_id"))
        capture = fid.split("-capture-")[1].split("|")[0] if "-capture-" in fid else "?"
        pk = list(f["packets"])
        rep.firing_rules = []
        for p in pk:
            if rep.verdict(p, home_ip=None):
                break
        sids = {r.sid for r in (rep.firing_rules or [])}
        if sids:
            fired[capture] |= sids
        else:
            missed.append(capture)
        if not any(f["replica"].verdict(p, home_ip=None) for p in pk):
            shipped_missed.append(capture)

    print(f"\nfull ruleset: {len(flows) - len(missed)}/{len(flows)} clean flows "
          f"detected; still missed: {sorted(set(missed))}")
    print(f"shipped 3-SID: {len(flows) - len(shipped_missed)}/{len(flows)} "
          f"detected; missed: {sorted(set(shipped_missed))}")

    print("\nSID fired per capture (full ruleset):")
    all_sids = set()
    for cap, sids in sorted(fired.items()):
        all_sids |= sids
        print(f"  {cap:14s} {sorted(sids)}")
    print(f"\ntotal distinct SIDs fired: {len(all_sids)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())