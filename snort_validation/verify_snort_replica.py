#!/usr/bin/env python3
"""Score the snort_query_service replica against real Snort verdicts.

Ground truth is the REAL Snort binary, not another model.  Two evidence sets:

1. ``seeded`` -- every episode of the three existing seeded 80-episode runs
   (blind / lambda=10 / enhanced-lambda=10) already has a real Snort verdict
   recorded in ``reports/*_snort_validation_seeded_*.json``.  240 flows.
2. ``probe``  -- freshly synthesized flows that were labelled by running the
   real Snort CLI here (holdout + discriminating sets in
   ``reports/replica_probe_labels.json``).  107 flows.

The replica is only allowed to be used as the training reward if it reproduces
real Snort on BOTH sets.  A sliding-window threshold model scores 345/347 and
is therefore rejected in favour of the measured anchored-window model.

Run:  /tmp/jev-poc/venv/bin/python snort_validation/verify_snort_replica.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from snort_query_service import (  # noqa: E402
    packet_plan, replica_snort_verdict, mock_snort_verdict, RULES,
)

REPORTS = HERE / "reports"
DATASETS = {
    "blind": ("agent_evaluation_seeded_blind.json",
              "agent_snort_validation_seeded_blind.json"),
    "l10": ("agent_evaluation_seeded_l10.json",
            "agent_snort_validation_seeded_l10.json"),
    "enh10": ("agent_evaluation_seeded_enh10.json",
              "agent_snort_validation_seeded_enh10.json"),
}


def load_seeded_flows():
    flows = []
    for name, (evf, snf) in DATASETS.items():
        ev = json.load(open(REPORTS / evf))
        sn = json.load(open(REPORTS / snf))
        verd = {e["episode"]: e["detected"] for e in sn["episode_results"]}
        for ep in ev["episodes"]:
            flows.append({
                "ds": name,
                "eid": ep["episode_id"],
                "feat": ep["mutated_features"],
                "real": bool(verd[ep["episode_id"]]),
            })
        print(f"[*] {name:6s}: {len(ev['episodes'])} real-labeled episodes")
    return flows


def load_probe_flows():
    p = REPORTS / "replica_probe_labels.json"
    if not p.exists():
        print("[!] no probe labels found; run snort_validation/probe_replica_holdout.py")
        return []
    rows = json.load(open(p))
    print(f"[*] probe : {len(rows)} real-labeled probe flows")
    return [{"ds": r.get("set", "probe"), "eid": r["i"],
             "feat": r["feat"], "real": bool(r["real"])} for r in rows]


# --- window models under test (documented selection evidence) -------------
def w_sliding(times, count, seconds):
    if count <= 1:
        return len(times) >= 1
    ts = sorted(times)
    for i in range(len(ts)):
        j = i
        while j + 1 < len(ts) and (ts[j + 1] - ts[i]) < seconds:
            j += 1
        if j - i + 1 >= count:
            return True
    return False


def _verdict_with_window(feat, window):
    proto, pkts, est, n_hs = _flow_ctx(feat)
    if proto not in ("tcp", "udp") or not pkts:
        return False
    for _sid, rproto, lo, hi, count, seconds, need_est, track in RULES:
        if rproto != proto:
            continue
        if need_est and not est:
            continue
        countable = pkts if not need_est else pkts[max(n_hs - 1, 0):]
        matches = [(d, t) for d, s, t in countable
                   if (lo is None or s > lo) and (hi is None or s < hi)]
        if not matches:
            continue
        if track is None:
            return True
        groups = {}
        for d, t in matches:
            if track == "by_src":
                key = "client" if d == "src" else "server"
            else:
                key = "server" if d == "src" else "client"
            groups.setdefault(key, []).append(t)
        for times in groups.values():
            if window(times, count, seconds):
                return True
    return False


def _flow_ctx(feat):
    proto = str(feat.get("proto", "tcp")).lower()
    pkts = packet_plan(feat)
    n_hs = 0
    for _d, s, _t in pkts[:3]:
        if s == 0:
            n_hs += 1
        else:
            break
    return proto, pkts, n_hs >= 3, n_hs


def report(name, flows, predictor):
    preds = [(predictor(f["feat"]), f["real"]) for f in flows]
    ok = sum(1 for p, r in preds if p == r)
    tp = sum(1 for p, r in preds if r and p)
    fp = sum(1 for p, r in preds if not r and p)
    fn = sum(1 for p, r in preds if r and not p)
    tn = sum(1 for p, r in preds if not r and not p)
    print(f"\n=== {name} vs real Snort ({len(flows)} flows) ===")
    print(f"  accuracy          {ok / len(flows):.4f}")
    print(f"  real detection    {sum(r for _p, r in preds) / len(flows):.4f}")
    print(f"  pred detection    {sum(p for p, _r in preds) / len(flows):.4f}")
    print(f"  tp={tp} fp={fp} fn={fn} tn={tn}")
    misses = [f for f, (p, r) in zip(flows, preds) if p != r]
    for f in misses[:8]:
        print(f"    MISS [{f['ds']}] real={f['real']} "
              f"pred={predictor(f['feat'])} {f['feat']}")
    if len(misses) > 8:
        print(f"    ... and {len(misses) - 8} more misses")
    return ok / len(flows)


def main():
    flows = load_seeded_flows() + load_probe_flows()
    if not flows:
        raise SystemExit("no labelled flows")
    print(f"\nTotal real Snort labelings available: {len(flows)}")

    acc_mock = report("mock (tot_pkts>50)", flows, mock_snort_verdict)
    acc_slide = report("sliding-window (rejected)",
                       flows, lambda f: _verdict_with_window(f, w_sliding))
    acc_rep = report("replica (anchored window)", flows, replica_snort_verdict)

    # per-dataset breakdown for the chosen replica
    print("\n=== replica per-dataset accuracy ===")
    for ds in sorted({f["ds"] for f in flows}):
        sub = [f for f in flows if f["ds"] == ds]
        a = sum(1 for f in sub if replica_snort_verdict(f["feat"]) == f["real"])
        print(f"  {ds:14s} {a}/{len(sub)} = {a / len(sub):.4f}")

    print(f"\n[SUMMARY] mock={acc_mock:.4f} sliding={acc_slide:.4f} "
          f"replica={acc_rep:.4f}")
    if acc_rep < 0.99:
        raise SystemExit("[FAIL] replica does not reproduce real Snort reliably")
    print("[OK] replica reproduces real Snort verdicts")


if __name__ == "__main__":
    main()
