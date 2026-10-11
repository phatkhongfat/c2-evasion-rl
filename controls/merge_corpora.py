#!/usr/bin/env python3
"""Merge corpus v2 (FakeAV + DHT) with corpus v3 (multi-family, extra-SID).

v2 is kept verbatim so every previously reported number stays reproducible.
v3 flows get their framing corrected (UDP/53 is never http) and a RealRulesReplica
so the RL surrogate can score them like v2 flows.

Output: a NEW pickle. Neither input is modified.
"""
from __future__ import annotations

import argparse
import pickle
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "snort_validation"), str(ROOT / "ai_agent")]


def corrected_framing(flow: dict) -> str:
    """A UDP/53 flow is DNS, not HTTP -- detect_framing defaults to http."""
    proto, dport = flow["key"][4], flow["key"][3]
    if proto == "udp" and dport == 53:
        return "dns"
    return flow.get("framing", "unknown")


def attach_replica(flow: dict) -> bool:
    if flow.get("replica") is not None:
        return False
    from real_rules_replica import RealRulesReplica
    sids = flow.get("baseline_sids")
    if not sids:
        return False
    flow["replica"] = RealRulesReplica.for_sids(set(sids))
    return True


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--v2", default=str(ROOT / "snort_validation/reports/hidden_defender_corpus.pkl"))
    ap.add_argument("--v3", default=str(ROOT / "snort_validation/reports/hidden_defender_corpus_v3.pkl"))
    ap.add_argument("--out", default=str(ROOT / "snort_validation/reports/hidden_defender_corpus_mixed.pkl"))
    ap.add_argument("--n-test", type=int, default=40)
    ap.add_argument("--v3-only", action="store_true",
                    help="emit v3 flows only (framing fixed, replica attached), no v2 mix")
    a = ap.parse_args()

    v2 = pickle.load(open(a.v2, "rb"))
    v3 = pickle.load(open(a.v3, "rb"))
    if a.v3_only:
        for f in v3["train"] + v3["test"]:
            f["framing"] = corrected_framing(f)
            attach_replica(f)
        pickle.dump(v3, open(a.out, "wb"))
        import collections
        print(f"[+] v3-only train={len(v3['train'])} test={len(v3['test'])} -> {a.out}")
        print("[+] test framing:", dict(collections.Counter(f["framing"] for f in v3["test"])))
        return 0

    n_fixed = n_repl = 0
    v3_flows = []
    for f in v3["train"] + v3["test"]:
        new = corrected_framing(f)
        if new != f.get("framing"):
            f["framing"] = new
            n_fixed += 1
        n_repl += attach_replica(f)
        v3_flows.append(f)

    test = list(v2["test"])  # keep the 40 baseline flows intact
    ids = {f["flow_id"] for f in test}
    train = list(v2["train"])
    for f in v3_flows:
        if f["flow_id"] in ids:
            continue
        test.append(f) if len(test) < a.n_test else train.append(f)
    train = [f for f in train if f["flow_id"] not in ids]

    pickle.dump({"train": train, "test": test}, open(a.out, "wb"))
    print(f"[+] framing fixed={n_fixed} replica attached={n_repl}")
    print(f"[+] train={len(train)} test={len(test)} -> {a.out}")
    import collections
    print("[+] test:", dict(collections.Counter(f["capture"] for f in test)))
    print("[+] test framing:", dict(collections.Counter(f["framing"] for f in test)))
    print("[+] train framing:", dict(collections.Counter(f["framing"] for f in train)))
    missing = [f["flow_id"] for f in test + train if f.get("replica") is None]
    print(f"[+] flows without replica: {len(missing)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())