#!/usr/bin/env python3
"""P15.6 — calibrate the direction-fixed replica against committed real-Snort.

No Snort is run.  Two committed real-Snort experiments are reproduced
IN-PROCESS with the RealRulesReplica, once with the direction fix (``home_ip``)
and once legacy (``home_ip=None``):

  (a) noop on all 40 test flows      vs control_noop_real_snort.json
  (b) per-flow actions from ppo_masked_test.json (split8 neris / split24 http),
      applied CLIENT-ONLY              vs ppo_masked_test.json
  (b') the SAME actions applied with ownership="both" -- the ownership the
      committed ppo_masked_test.json was ACTUALLY produced with (old apply_mech
      mutated every Raw packet; client-only arrived later, commit 40fffdf).
  (c) split8 on all 40 vs oracle_split8_test.json -- the only committed report
      that is a genuine CLIENT-ONLY real-Snort run.

The replica needs ``direction`` populated, but the shipped corpus pickle embeds
``Rule`` objects pickled BEFORE that field existed (getattr -> default 'any'),
so ``fresh`` replicas are re-parsed from the ruleset with the flow's own SIDs.
That is exactly what a corpus rebuild would hand the env.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))

from hidden_defender_env import apply_mech, load_corpus  # noqa: E402
from c2_semantics import client_ip_of  # noqa: E402
from real_rules_replica import (  # noqa: E402
    RULES, RealRulesReplica, parse_ruleset,
)

REPORTS = REPO / "snort_validation/reports"
OUT = REPORTS / "surrogate_calibration_p15.json"


def _fresh(flow) -> RealRulesReplica:
    """Replica with ``direction`` parsed (the shipped pickle predates it)."""
    sids = {r.sid for r in flow["replica"].rules}
    return RealRulesReplica(parse_ruleset(RULES, sid_filter=sids))


def _agreement(rows, key_real, key_after, key_before):
    n = len(rows)
    after = sum(1 for r in rows if r[key_after] == r[key_real])
    before = sum(1 for r in rows if r[key_before] == r[key_real])
    return after, before, n


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", default="test")
    ap.add_argument("--out", default=str(OUT))
    args = ap.parse_args()

    flows = load_corpus(args.split)
    noop = json.loads((REPORTS / "control_noop_real_snort.json").read_text())
    noop_real = {r["flow_id"]: r["alert"] for r in noop["rows"]}
    ppo = json.loads((REPORTS / "ppo_masked_test.json").read_text())
    ppo_real = {r["flow_id"]: r["alert"] for r in ppo["per_flow"]}
    ppo_act = {r["flow_id"]: r["action"] for r in ppo["per_flow"]}
    oracle_path = REPORTS / "oracle_split8_test.json"
    oracle_real = ({r["flow_id"]: r["alert"] for r in
                    json.loads(oracle_path.read_text())["per_flow"]}
                   if oracle_path.exists() else None)

    fresh = {f["flow_id"]: _fresh(f) for f in flows}

    detail = []
    for f in flows:
        fid = f["flow_id"]
        cip = client_ip_of(fid)
        pkts = f["packets"]
        rep_new, rep_old = fresh[fid], f["replica"]
        row = {
            "flow_id": fid,
            "framing": f.get("framing"),
            "action": ppo_act.get(fid),
            # (a) noop
            "noop_real": noop_real.get(fid),
            "noop_after": rep_new.verdict(pkts, home_ip=cip),
            "noop_before": rep_old.verdict(pkts),
            # (b) per-flow action, client-only
            "split_real": ppo_real.get(fid),
        }
        mech = ppo_act.get(fid)
        for tag, own in (("split", "client"), ("split_both", "both")):
            mut = apply_mech(pkts, mech, cip, ownership=own)
            row[f"{tag}_after"] = rep_new.verdict(mut, home_ip=cip)
            row[f"{tag}_before"] = rep_old.verdict(mut)
        if oracle_real is not None:
            mut8 = apply_mech(pkts, "split8", cip)
            row["oracle_real"] = oracle_real.get(fid)
            row["oracle_after"] = rep_new.verdict(mut8, home_ip=cip)
            row["oracle_before"] = rep_old.verdict(mut8)
        detail.append(row)

    noop_after, noop_before, n = _agreement(detail, "noop_real", "noop_after", "noop_before")
    split_after, split_before, _ = _agreement(detail, "split_real", "split_after", "split_before")
    sb_after, sb_before, _ = _agreement(detail, "split_real", "split_both_after", "split_both_before")
    o_after = o_before = None
    if oracle_real is not None:
        o_after, o_before, _ = _agreement(detail, "oracle_real", "oracle_after", "oracle_before")

    result = {
        "n_flows": n,
        "noop_agreement_after": noop_after,
        "noop_agreement_before": noop_before,
        "split_agreement_after": split_after,
        "split_agreement_before": split_before,
        "split_both_agreement_after": sb_after,
        "split_both_agreement_before": sb_before,
        "oracle_split8_agreement_after": o_after,
        "oracle_split8_agreement_before": o_before,
        "framing": dict(Counter(r["framing"] for r in detail)),
        "detail": detail,
    }
    Path(args.out).write_text(json.dumps(result, indent=2))

    print("=" * 72)
    print("SURROGATE DIRECTION CALIBRATION vs committed real-Snort (no Snort run)")
    print("=" * 72)
    print(f"n_flows = {n}")
    print()
    print("(a) noop            vs control_noop_real_snort.json")
    print(f"    agreement  before(legacy) {noop_before}/{n}   after(home_ip) {noop_after}/{n}"
          f"   -> {'WORSE' if noop_after < noop_before else 'same/better'}")
    print("(b) per-flow action vs ppo_masked_test.json  [applied CLIENT-ONLY]")
    print(f"    agreement  before(legacy) {split_before}/{n}   after(home_ip) {split_after}/{n}")
    print("(b') same action, ownership=both (how ppo_masked_test was generated)")
    print(f"    agreement  before(legacy) {sb_before}/{n}   after(home_ip) {sb_after}/{n}")
    if o_after is not None:
        print("(c) split8          vs oracle_split8_test.json (TRUE client-only real Snort)")
        print(f"    agreement  before(legacy) {o_before}/{n}   after(home_ip) {o_after}/{n}"
              f"   -> {'WORSE' if o_after < o_before else 'same/better'}")
    print()
    print(f"[+] {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
