#!/usr/bin/env python3
"""Summarise per-flow baseline SID lists into the Gate S1 decision.

Pure function over an already-measured ``{flow_id: [sid, ...]}`` mapping so it
can be unit-tested without Snort.

BitTorrent DHT SIDs are removed *before* counting: P11.6 established they sit
outside the C2 threat model, and leaving them in makes every flow look
multi-SID. The 2026-10-13 measurement is exactly that failure mode -- 24 of 40
flows alert only on DHT and 16 alert only on the FakeAV C2 rule, so the
threat-model denominator is 16, not 40.
"""
from __future__ import annotations

P2P_DEFAULT = frozenset({2008581, 2008583, 2008585})


def summarize(per_flow: dict, p2p_sids=P2P_DEFAULT) -> dict:
    """Return alerting/multi-SID counts and the Gate S1 verdict."""
    alerting = 0
    multi = 0
    max_sids = 0
    seen_p2p: set = set()
    distribution: dict = {}
    sids_seen: set = set()

    for sids in per_flow.values():
        kept = {s for s in sids if s not in p2p_sids}
        seen_p2p |= {s for s in sids if s in p2p_sids}
        sids_seen |= kept
        n = len(kept)
        distribution[n] = distribution.get(n, 0) + 1
        if kept:
            alerting += 1
        if n > 1:
            multi += 1
        max_sids = max(max_sids, n)

    return {
        "n_flows": len(per_flow),
        "flows_alerting": alerting,
        "flows_multi_sid": multi,
        "max_sids_per_flow": max_sids,
        "sids_per_flow_distribution": dict(sorted(distribution.items())),
        "sids_seen": sorted(sids_seen),
        "excluded_p2p_sids": sorted(seen_p2p),
        "threat_model_denominator": alerting,
        "gate_s1_pass": multi > 0,
    }