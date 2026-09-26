"""Oracle labels: which single packet, if corrupted, evades each flow?

The frontier solver proved every evadable flow evades at k=1. This module turns
that into reusable supervision: for each flow, the FULL SET of packet indices
that achieve evasion on their own.

Storing the whole valid set rather than one arbitrary argmin matters: ties are
real (most 20110811 flows have 2 payload packets and both work), and training on
a single tie-break would teach the policy an arbitrary distinction it cannot
generalise from.
"""
import sys
import json
import argparse
import numpy as np
from scapy.all import Raw

sys.path.insert(0, "ai_agent")
sys.path.insert(0, "snort_validation")

from snort_bandit import apply_corrupt_mask, score, ACTION_MAX_PACKETS
from snort_resident_service import ResidentSnortService
from real_packet_env import RealPacketEnv

CHUNK = 3000


def payload_indices(pk):
    return [i for i, p in enumerate(pk) if Raw in p and i < ACTION_MAX_PACKETS]


def build(dataset, capture, out_path, n_flows=24):
    svc = ResidentSnortService()
    if not svc.start():
        print("SNORT UNAVAILABLE:", svc.error)
        return 1
    flows = RealPacketEnv(n_flows=n_flows, capture=capture,
                          dataset=dataset, batch_size=64).flows
    n = len(flows)
    pay = [payload_indices(pk) for _k, pk in flows]

    # candidate order is fixed and explicit: cand[i] == (flow fi, packet j)
    cand, items = [], []
    for fi in range(n):
        for j in pay[fi]:
            m = np.zeros(ACTION_MAX_PACKETS, dtype=np.float32)
            m[j] = 1.0
            items.append(apply_corrupt_mask(flows[fi][1], m))
            cand.append((fi, j))

    print(f"{capture}: {n} flows, {len(items)} single-packet candidates", flush=True)
    valid = {}
    for c in range(0, len(items), CHUNK):
        part = items[c:c + CHUNK]
        pid = [c + i + 10_000_000 for i in range(len(part))]
        res = score(svc, list(zip(part, pid)), "oracle")
        for cid, v in res.items():
            if v == 0:
                fi, j = cand[cid - 10_000_000]
                valid.setdefault(fi, []).append(j)

    labels = {str(fi): sorted(v) for fi, v in sorted(valid.items())}
    unevadable = [fi for fi in range(n) if fi not in valid]
    zero_payload = [fi for fi in range(n) if not pay[fi]]

    payload = {
        "capture": capture,
        "dataset": dataset,
        "n_flows": n,
        "valid_single_packets": labels,
        "unevadable": unevadable,
        "zero_payload_flows": zero_payload,
        "payload_per_flow": [len(p) for p in pay],
    }
    with open(out_path, "w") as fh:
        json.dump(payload, fh, indent=2)

    solved = len(labels)
    print(f"flows with >=1 valid single packet: {solved}/{n}")
    print(f"unevadable: {unevadable}")
    print(f"wrote {out_path}")
    svc.stop()
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", required=True)
    ap.add_argument("--capture", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--flows", type=int, default=24)
    a = ap.parse_args()
    return build(a.dataset, a.capture, a.out, a.flows)


if __name__ == "__main__":
    sys.exit(main())
