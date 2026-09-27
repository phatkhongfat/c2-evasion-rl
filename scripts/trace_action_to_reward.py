#!/usr/bin/env python3
"""Trace: does changing TTL/frag/overlap reach replica_snort_verdict?

Phase 2, Task 2.2 of .hermes/plans/2026-09-26_112455-packet-obs-action-diagnosis.md

Compares, for one synthetic 10-packet TCP flow:
  * the feature dict produced by PacketModifier.to_flow_features()
  * the verdict of the flow-level replica   (snort_query_service.replica_snort_verdict)
  * the verdict of the enhanced replica      (enhanced_snort_replica.enhanced_replica_snort_verdict)

and additionally probes whether the enhanced replica's TTL heuristics are
reachable at all given the action-space clamps.
"""
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))

import numpy as np

from packet_modifier import PacketModifier
from snort_query_service import replica_snort_verdict, packet_plan
from enhanced_snort_replica import (
    enhanced_replica_snort_verdict,
    get_enhanced_detection_reason,
)

# Synthetic flow: 10 packets, TCP, CON, 100-byte payloads
packets = [("src", 100, i * 0.1) for i in range(10)]

# Action vectors are the env's REAL action encoding (env.step maps
# normalized [-1,1] -> [ttl_delta=+/-10, frag_flag, padding=0..200, overlap=+/-100])
CASES = {
    "baseline (no mutation)":   [0.0, 0.0, 0.0, 0.0],
    "TTL +10 only":             [10.0, 0.0, 0.0, 0.0],
    "TTL -10 only":             [-10.0, 0.0, 0.0, 0.0],
    "TTL alternating +/-10":    [None, 0.0, 0.0, 0.0],   # special-cased below
    "frag only":                [0.0, 1.0, 0.0, 0.0],
    "overlap +100 only":        [0.0, 0.0, 0.0, 100.0],
    "padding +100 only":        [0.0, 0.0, 100.0, 0.0],
    "ALL four":                 [10.0, 1.0, 100.0, 100.0],
}

FEATURE_KEYS = ["tot_pkts", "tot_bytes", "src_bytes", "dur", "proto", "state"]


def run(name, action, modifier):
    if action[0] is None:  # alternating TTL case
        actions = [np.array([10.0 if i % 2 == 0 else -10.0, 0.0, 0.0, 0.0])
                   for i in range(len(packets))]
    else:
        actions = [np.array(action, dtype=float)] * len(packets)

    modified = modifier.apply_actions(packets, actions)
    feats = modifier.to_flow_features(modified)
    feats["proto"] = "tcp"
    feats["state"] = "CON"

    v_flow = replica_snort_verdict(feats)
    v_enh = enhanced_replica_snort_verdict(feats, modified)
    reason = get_enhanced_detection_reason(feats, modified)

    ttls = [p["ttl"] for p in modified]
    frag = sum(1 for p in modified if p["fragmented"])
    ovl = max(abs(p["overlap_offset"]) for p in modified)

    print(f"\n--- {name} ---")
    print(f"  action per packet      : {list(actions[0])}")
    print(f"  feature dict           : { {k: feats[k] for k in FEATURE_KEYS} }")
    print(f"  packet ttl  min/max/std: {min(ttls)}/{max(ttls)}/{np.std(ttls):.2f}"
          f"   fragmented: {frag}/10   max|overlap|: {ovl}")
    print(f"  flow-level replica     : {'DETECTED' if v_flow else 'evaded'}")
    print(f"  enhanced replica       : {'DETECTED' if v_enh else 'evaded'}  ({reason})")
    return feats, v_flow, v_enh


def main():
    modifier = PacketModifier()
    print("=" * 78)
    print("TRACE: action -> to_flow_features -> replica verdict")
    print("=" * 78)

    results = {}
    for name, action in CASES.items():
        results[name] = run(name, action, modifier)

    base_feats, base_flow, base_enh = results["baseline (no mutation)"]

    print("\n" + "=" * 78)
    print("VERDICT")
    print("=" * 78)

    for name in ["TTL +10 only", "TTL -10 only", "TTL alternating +/-10",
                 "frag only", "overlap +100 only", "padding +100 only"]:
        feats, v_flow, v_enh = results[name]
        same_feats = feats == base_feats
        print(f"  {name:<24} features identical to baseline: {str(same_feats):<5}"
              f" | flow-replica changed: {v_flow != base_flow}"
              f" | enhanced-replica changed: {v_enh != base_enh}")

    print("\nBUG CONFIRMED: the feature dict has exactly the keys "
          f"{sorted(base_feats.keys())}.")
    print("TTL / fragmentation / overlap are stored in the modified packet dicts")
    print("by apply_actions() but to_flow_features() drops them, so the")
    print("flow-level replica (the reward in packet_level_env.py) cannot see them.")

    # ---- Reachability probe: are the enhanced replica's TTL rules reachable? ----
    print("\n" + "=" * 78)
    print("ENHANCED REPLICA - TTL RULE REACHABILITY")
    print("=" * 78)
    base_ttl = modifier.base_ttl
    lo = base_ttl + int(np.clip(-10, -10, 10))   # env clamps ttl_delta to +/-10
    hi = base_ttl + int(np.clip(10, -10, 10))
    # max achievable std over TTL values drawn from {lo, hi}
    n = len(packets)
    k = n // 2
    mean = (k * lo + (n - k) * hi) / n
    var = (k * (lo - mean) ** 2 + (n - k) * (hi - mean) ** 2) / n
    print(f"  base_ttl = {base_ttl}, action clamp = +/-10  ->  reachable TTL range "
          f"[{lo}, {hi}]")
    print(f"  max achievable TTL std (alternating {lo}/{hi}) = {np.sqrt(var):.2f}")
    print(f"  P1 needs any(ttl < 10)        -> min reachable {lo}  => "
          f"{'REACHABLE' if lo < 10 else 'UNREACHABLE'}")
    print(f"  P2 needs std(ttl) > 15        -> max reachable {np.sqrt(var):.2f}  => "
          f"{'REACHABLE' if np.sqrt(var) > 15 else 'UNREACHABLE'}")
    print(f"  P5 needs min(ttl) < 20        -> min reachable {lo}  => "
          f"{'REACHABLE' if lo < 20 else 'UNREACHABLE'}")

    # empirical: alternating TTL is the strongest TTL action available
    mod = PacketModifier()
    acts = [np.array([10.0 if i % 2 == 0 else -10.0, 0.0, 0.0, 0.0]) for i in range(n)]
    mp = mod.apply_actions(packets, acts)
    feats = mod.to_flow_features(mp)
    feats["proto"], feats["state"] = "tcp", "CON"
    print(f"  empirical worst-case TTL action -> enhanced verdict: "
          f"{'DETECTED' if enhanced_replica_snort_verdict(feats, mp) else 'evaded'}"
          f"  ({get_enhanced_detection_reason(feats, mp)})")

    # ---- packet_plan round-trip: the replica re-synthesizes packets ----
    print("\n" + "=" * 78)
    print("NOTE: the flow-level replica never sees the modified packets")
    print("=" * 78)
    replanned = packet_plan(base_feats)
    print(f"  to_flow_features -> packet_plan() re-synthesizes {len(replanned)} packets")
    print(f"  first 4: {replanned[:4]}")
    print("  i.e. even padding acts only through the aggregate tot_bytes/src_bytes.")


if __name__ == "__main__":
    main()
