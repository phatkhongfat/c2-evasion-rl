#!/usr/bin/env python3
"""Compositional headroom: can a *set* of mechanisms evade where none does alone?

`rl_headroom.py` only ever tries one mechanism at a time, so it structurally
cannot see a set cover. This closes that hole.

Following the MTO formulation (IEEE 2025, ledger source [5]): a naive evade that
a single strategy defeats leaves no room for composition, but as a rule set grows
the winner becomes a *coordination* of strategies. The measurable form of that:
for each flow, let

    cover[mech] = baseline_sids \\ residual_sids(mech)

be the SIDs mechanism `mech` would clear. If some single mechanism already clears
the bar, the flow is not compositional -- a set would be strictly worse. Only
when the singleton cover fails and a *greedy* set cover succeeds does the
environment genuinely have something to choose, and that gap is the headroom the
RL policy could earn.

Pure function over an already-measured report; no Snort.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from sid_diversity import P2P_DEFAULT


def greedy_cover(sids, cover):
    """Smallest subset of mechanisms covering `sids`, or None if impossible.

    Selection order is the greedy order (largest remaining coverage wins, ties
    broken by the caller's dict order), which keeps the output deterministic.
    """
    remaining = set(sids)
    if not remaining:
        return []
    chosen = []
    while remaining:
        best = max(cover.items(),
                   key=lambda kv: len(set(kv[1]) & remaining))
        if not (set(best[1]) & remaining):
            return None
        chosen.append(best[0])
        remaining -= set(best[1])
    return chosen


def composite_headroom(cells, bar="valid_evasion_endpoint",
                       p2p_sids=P2P_DEFAULT) -> dict:
    """Count flows where a set of mechanisms evades but no single one does."""
    by_flow = defaultdict(list)
    for c in cells:
        by_flow[c["flow_id"]].append(c)

    per_flow = {}
    compositional, near_miss, considered = [], [], 0

    for fid, fcs in sorted(by_flow.items()):
        if not fcs[0].get("baseline_alert", False):
            continue

        baseline = set()
        for c in fcs:
            baseline |= set(c.get("baseline_sids") or [])
        baseline -= set(p2p_sids)
        if not baseline:
            continue  # outside the threat model (P2P-only baseline)
        considered += 1

        cover, winners = {}, []
        for c in fcs:
            mech = c.get("mech")
            cover[mech] = baseline - set(c.get("sids") or [])
            if c.get(bar, False):
                winners.append(mech)

        if winners:
            per_flow[fid] = {"compositional": False, "reason": "single wins",
                             "winning_mechanisms": sorted(winners),
                             "cover": sorted(winners)}
            continue

        chosen = greedy_cover(baseline, cover)
        if chosen is not None:
            compositional.append(fid)
            per_flow[fid] = {"compositional": True, "reason": "set cover",
                             "cover": chosen, "winning_mechanisms": [],
                             "singletons_that_miss": sorted(cover)}
        else:
            near_miss.append(fid)
            per_flow[fid] = {"compositional": False,
                             "reason": "no full cover",
                             "cover": [], "winning_mechanisms": []}

    return {
        "bar": bar,
        "flows_evaluated": considered,
        "compositional_flows": compositional,
        "composite_headroom": len(compositional),
        "near_miss_flows": near_miss,
        "per_flow": per_flow,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("report")
    ap.add_argument("--out", required=True)
    ap.add_argument("--bars", nargs="+",
                    default=["valid_evasion", "valid_evasion_endpoint"])
    a = ap.parse_args()

    doc = json.load(open(a.report))
    cells = doc["cells"] if isinstance(doc, dict) else doc
    out = {"report": str(a.report),
           "conf": doc.get("conf") if isinstance(doc, dict) else None,
           "by_bar": {b: composite_headroom(cells, bar=b) for b in a.bars}}
    Path(a.out).write_text(json.dumps(out, indent=2))

    for b, r in out["by_bar"].items():
        print(f"[{b}] flows={r['flows_evaluated']} "
              f"composite_headroom={r['composite_headroom']} "
              f"near_miss={len(r['near_miss_flows'])}")
    print(f"wrote {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())