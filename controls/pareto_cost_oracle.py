#!/usr/bin/env python3
"""Cost-aware Pareto headroom on a measured dualbar sweep report.

Evasion headroom is 0 (a single fixed mech covers every flow).  Second axis:
wire cost (added bytes/packets from the mutation) -- something a real attacker
cares about.  A per-flow policy that picks the cheapest *valid* mechanism can
strictly dominate every fixed mechanism at equal evasion.  Costs are computed
by applying the mutations in-memory (no Snort); validity comes from the report.

Usage: .venv/bin/python controls/pareto_cost_oracle.py [--report <dualbar.json>]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ai_agent"))
sys.path.insert(0, str(ROOT / "snort_validation"))

from hidden_defender_env import HiddenDefenderEnv  # noqa: E402
from eval_pipeline import client_ip_of, mutate_client_only  # noqa: E402

DEFAULT_REPORT = ROOT / "snort_validation" / "reports" / "ceiling_v6_case_fullrules_dualbar.json"


def wire_cost(packets) -> tuple[int, int]:
    """(total wire bytes, packet count) of a packet list."""
    b = 0
    for p in packets:
        try:
            b += len(bytes(p))
        except Exception:
            b += len(p)
    return b, len(packets)


def pareto_for_bar(ids, cost, mechs, valid, label):
    """Per-flow cheapest-valid-mech oracle under one validity bar."""
    tot_b = tot_p = 0
    used: dict[str, int] = {}
    uncovered = []
    for fid in ids:
        cands = [m for m in mechs
                 if valid.get((fid, m)) and cost[fid].get(m) is not None]
        if not cands:
            uncovered.append(fid)
            continue
        best = min(cands, key=lambda m: (cost[fid][m][0], cost[fid][m][1]))
        tot_b += cost[fid][best][0]
        tot_p += cost[fid][best][1]
        used[best] = used.get(best, 0) + 1
    ev_or = len(ids) - len(uncovered)
    print(f"\n[{label}] per-flow oracle: evaded {ev_or}/{len(ids)}  "
          f"+bytes {tot_b}  +pkts {tot_p}  uncovered {len(uncovered)}")
    print(f"[{label}] mech usage: {used}  distinct={len(used)}")
    fixed = {m: (sum(1 for fid in ids if valid.get((fid, m))),
                 sum((cost[fid][m] or (0, 0))[0] for fid in ids),
                 sum((cost[fid][m] or (0, 0))[1] for fid in ids)) for m in mechs}
    dominated = [m for m, (ev, cb, cp) in fixed.items()
                 if ev >= ev_or and cb <= tot_b and cp <= tot_p
                 and (cb, cp) != (tot_b, tot_p)]
    tie = [m for m, (ev, cb, cp) in fixed.items()
           if ev >= ev_or and cb == tot_b and cp == tot_p]
    print(f"[{label}] strictly dominating fixed: {dominated or 'NONE'}")
    print(f"[{label}] equal-cost fixed: {tie or 'NONE'}")
    if not dominated and not tie:
        print(f"[{label}] => per-flow policy STRICTLY Pareto-better than every fixed mech")
    return ev_or, tot_b, tot_p, used


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--report", default=str(DEFAULT_REPORT),
                    help="dualbar sweep report JSON with per-cell validity")
    ap.add_argument("--corpus", default=None,
                    help="corpus pickle matching the report (default: checked-in)")
    ap.add_argument("--exclude", default="",
                    help="comma-separated mechs to drop from BOTH the fixed "
                         "baseline and the oracle (same-constraint comparison, "
                         "e.g. split8,split16,split24,split_slow for a "
                         "fragmentation-blocked regime)")
    args = ap.parse_args()
    excluded = {m.strip() for m in args.exclude.split(",") if m.strip()}
    rep = json.loads(Path(args.report).read_text())
    print(f"report: {args.report}  conf: {rep.get('conf')}")
    cells = rep["cells"]
    # validity maps keyed by (flow_id, mech)
    valid_ep = {(c["flow_id"], c["mech"]): c["valid_evasion_endpoint"] for c in cells}
    valid_by = {(c["flow_id"], c["mech"]): c["valid_evasion"] for c in cells}
    baseline_alert = {}
    for c in cells:
        baseline_alert.setdefault(c["flow_id"], c["baseline_alert"])
    flows_alert = {f for f, a in baseline_alert.items() if a}
    print(f"flows in report: {len(baseline_alert)}  with baseline alert: {len(flows_alert)}")

    env = HiddenDefenderEnv(split="test", seed=42, real_snort=False,
                            corpus=args.corpus)
    flows = env._flows
    print(f"env test flows: {len(flows)}")

    # mechs = those actually measured in the report (http_header_case is not in
    # ACTION_NAMES -- it is a 16th mechanism added for the P12 case-sensitivity
    # probe), minus any excluded by --exclude (same-constraint comparison:
    # both the fixed baseline and the oracle lose them).
    mechs = sorted({c["mech"] for c in cells} - excluded)
    print(f"measured mechs: {mechs}"
          + (f"  (excluded: {sorted(excluded)})" if excluded else ""))

    # cost[flow_id][mech] = (added_bytes, added_pkts); also 'orig'
    cost: dict[str, dict[str, tuple[int, int]]] = {}
    for f in flows:
        fid = f["flow_id"]
        cip = client_ip_of(fid)
        ob, op = wire_cost(f["packets"])
        per = {"__orig__": (ob, op)}
        for mech in mechs:
            try:
                mut = mutate_client_only(f["packets"], mech, cip, ownership="both")
            except Exception as e:  # keep going; note as unusable
                per[mech] = None
                continue
            mb, mp = wire_cost(mut)
            per[mech] = (mb - ob, mp - op)
        cost[fid] = per

    # ---- fixed mechanisms: evasion (endpoint bar, alert flows only) + total cost
    ids = sorted(flows_alert & set(cost))
    print(f"scored flows: {len(ids)}")
    fixed = {}
    for mech in mechs:
        ev = sum(1 for fid in ids if valid_ep.get((fid, mech)))
        cb = sum((cost[fid][mech] or (0, 0))[0] for fid in ids)
        cp = sum((cost[fid][mech] or (0, 0))[1] for fid in ids)
        fixed[mech] = (ev, cb, cp)
    print("\nfixed mechs (endpoint bar):  mech  evaded  +bytes  +pkts")
    for mech, (ev, cb, cp) in sorted(fixed.items(), key=lambda kv: (-kv[1][0], kv[1][1])):
        print(f"  {mech:<18} {ev:>3}/{len(ids)}  {cb:>+9}  {cp:>+5}")

    pareto_for_bar(ids, cost, mechs, valid_ep, "endpoint bar")
    pareto_for_bar(ids, cost, mechs, valid_by, "byte bar")


if __name__ == "__main__":
    main()
