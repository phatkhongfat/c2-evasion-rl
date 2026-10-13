#!/usr/bin/env python3
"""Gate S2: which mechanisms clear which baseline SIDs, per flow.

Reads a sweep report (list of cells with ``flow_id``, ``mech``, ``baseline_sids``,
``sids``, and the bar flags) and answers the question ``rl_headroom.py`` cannot:
for a flow carrying two in-threat-model SIDs, is there *any* choice to make?

S2 passes when the per-SID winning-mechanism sets differ. That is a structural
property of measured data -- it does not depend on tuning thresholds.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from sid_diversity import P2P_DEFAULT, summarize

BARS = ("valid_evasion", "valid_evasion_endpoint")


def _baseline_sids_by_flow(cells) -> dict:
    """Baseline SIDs per flow, preferring the ``noop`` cell (unmutated truth)."""
    per = defaultdict(set)
    noop = {
        c["flow_id"]: set(c.get("baseline_sids") or [])
        for c in cells
        if c.get("mech") == "noop"
    }
    for c in cells:
        fid = c["flow_id"]
        if fid in noop:
            per[fid] |= noop[fid]
        else:
            per[fid] |= set(c.get("baseline_sids") or [])
    return dict(per)


def flow_headroom_from_cells(cells, p2p_sids=P2P_DEFAULT) -> dict:
    """Decide headroom for ONE flow from all its mechanism cells."""
    cells = list(cells)
    if not cells or not cells[0].get("baseline_alert", True):
        return {"headroom": 0, "reason": "no baseline alert",
                "per_sid_actions": {}, "skipped_no_baseline": True}

    baseline = set()
    for c in cells:
        baseline |= set(c.get("baseline_sids") or [])
    baseline -= set(p2p_sids)

    per_sid: dict = {sid: set() for sid in baseline}
    winners: set = set()
    for c in cells:
        mech = c.get("mech")
        if c.get("evaded", False) or c.get("valid_evasion", False):
            winners.add(mech)

    if len(winners) <= 1:
        return {"headroom": 0, "reason": "single mechanism",
                "per_sid_actions": {str(k): [] for k in per_sid},
                "winning_mechanisms": sorted(winners)}

    for c in cells:
        mech, sid_now = c.get("mech"), set(c.get("sids") or [])
        cleared = baseline - sid_now
        for sid in cleared:
            if sid in per_sid:
                per_sid[sid].add(mech)

    sig = {frozenset(v) for v in per_sid.values()}
    if len(sig) <= 1:
        return {"headroom": 0, "reason": "identical action sets",
                "per_sid_actions": {str(k): sorted(v) for k, v in per_sid.items()},
                "winning_mechanisms": sorted(winners)}

    return {"headroom": 1, "reason": "disjoint per-SID action sets",
            "per_sid_actions": {str(k): sorted(v) for k, v in per_sid.items()},
            "winning_mechanisms": sorted(winners),
            "skipped_no_baseline": False}


def build_matrix(cells, bar="valid_evasion_endpoint", p2p_sids=P2P_DEFAULT) -> dict:
    """Gate S1 + S2 over a whole report."""
    by_flow = defaultdict(list)
    for c in cells:
        by_flow[c["flow_id"]].append(c)

    baseline = _baseline_sids_by_flow(cells)
    s1 = summarize(baseline, p2p_sids)

    alerting = [c for c in cells if c.get("baseline_alert", False)]
    best_single = 0
    per_flow = {}
    s2_pass = 0

    for fid, fcs in by_flow.items():
        if not fcs[0].get("baseline_alert", False):
            continue
        per_mech = {c["mech"]: bool(c.get(bar, False)) for c in fcs}
        if any(per_mech.values()):
            best_single += 1
        out = flow_headroom_from_cells(fcs, p2p_sids)
        # restrict the S2 verdict to mechanisms that actually clear THIS bar
        if out.get("headroom"):
            kept = [c for c in fcs if c.get(bar, False)]
            out = flow_headroom_from_cells(kept, p2p_sids) or out
            if not out.get("skipped_no_baseline") and len(
                {c["mech"] for c in kept}) <= 1:
                out = {"headroom": 0, "reason": "single mechanism"}
        if out.get("headroom"):
            s2_pass += 1
        per_flow[fid] = out

    return {
        "bar": bar,
        "n_flows": len(by_flow),
        "flows_with_baseline_alert": len(alerting) and len(
            {c["flow_id"] for c in alerting}),
        "best_single": best_single,
        "headroom": s2_pass,
        "gate_s1_pass": s1["gate_s1_pass"],
        "gate_s2_pass": s2_pass > 0,
        "sids_seen": s1["sids_seen"],
        "sids_per_flow_distribution": s1["sids_per_flow_distribution"],
        "flows_multi_sid": s1["flows_multi_sid"],
        "max_sids_per_flow": s1["max_sids_per_flow"],
        "threat_model_denominator": s1["threat_model_denominator"],
        "excluded_p2p_sids": s1["excluded_p2p_sids"],
        "per_flow": per_flow,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("report")
    ap.add_argument("--out", required=True)
    ap.add_argument("--bars", nargs="+", default=list(BARS), choices=BARS)
    a = ap.parse_args()

    doc = json.load(open(a.report))
    cells = doc["cells"] if isinstance(doc, dict) else doc
    out = {"report": str(a.report),
           "conf": doc.get("conf") if isinstance(doc, dict) else None,
           "by_bar": {b: build_matrix(cells, bar=b) for b in a.bars}}
    Path(a.out).write_text(json.dumps(out, indent=2))

    for b, m in out["by_bar"].items():
        print(f"[{b}] flows={m['n_flows']} best_single={m['best_single']} "
              f"S1={m['gate_s1_pass']} S2={m['gate_s2_pass']} "
              f"headroom={m['headroom']} sids={m['sids_seen']}")
    print(f"wrote {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())