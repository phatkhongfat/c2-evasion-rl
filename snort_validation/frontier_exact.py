"""FRONTIER: can any sparse plan match the corrupt-all control on this capture?

Because `score()` judges each flow independently, evasion is a per-flow verdict
with NO coupling between flows. So the globally minimal corruption count for a
given evasion target is just the SUM of the per-flow minima -- no search over
joint plans is needed. We solve each flow exactly by progressive deepening:
test every k-subset of the flow's reachable payload packets, smallest k first,
and stop at the first k that evades.

This is exact for every flow solved at or below the search cap; unsolved flows
are reported as lower bounds, never as solved.
"""
import sys
import json
import os
import math
import time
import itertools
import numpy as np
from scapy.all import Raw

sys.path.insert(0, "ai_agent")
sys.path.insert(0, "snort_validation")

from snort_bandit import apply_corrupt_mask, corrupt_targets, score, ACTION_MAX_PACKETS
from snort_resident_service import ResidentSnortService
from real_packet_env import RealPacketEnv

DATASET = sys.argv[1]
CAPTURE = sys.argv[2]
MAX_K = int(sys.argv[3]) if len(sys.argv) > 3 else 6
ITEM_CAP = int(sys.argv[4]) if len(sys.argv) > 4 else 120000
CHUNK = 3000


def mask_of(idxs):
    m = np.zeros(ACTION_MAX_PACKETS, dtype=np.float32)
    for i in idxs:
        m[i] = 1.0
    return m


def main():
    t0 = time.time()
    svc = ResidentSnortService()
    if not svc.start():
        print("SNORT UNAVAILABLE:", svc.error)
        return 1

    flows = RealPacketEnv(n_flows=24, capture=CAPTURE,
                          dataset=DATASET, batch_size=64).flows
    n = len(flows)
    pay = [[i for i, p in enumerate(pk) if Raw in p and i < ACTION_MAX_PACKETS]
           for _k, pk in flows]
    print(f"capture={CAPTURE} flows={n} reachable_payload={sum(len(p) for p in pay)}", flush=True)

    empty = np.zeros(ACTION_MAX_PACKETS, dtype=np.float32)
    ones = np.ones(ACTION_MAX_PACKETS, dtype=np.float32)

    # Control: corrupt everything reachable.
    ca = score(svc, [(apply_corrupt_mask(pk, ones), i) for i, (_k, pk) in enumerate(flows)], "ca")
    ca_ev = [i for i, v in ca.items() if v == 0]
    ca_nc = sum(len(corrupt_targets(pk, ones)) for _k, pk in flows) / n
    print(f"CONTROL corrupt-all: {len(ca_ev)}/{n} evaded @ mean_corrupt={ca_nc:.2f}", flush=True)
    unevadable = sorted(set(range(n)) - set(ca_ev))
    print(f"unevadable even when everything is corrupted: {unevadable}", flush=True)

    # Sanity: untouched flows should be detected, else the harness is broken.
    base = score(svc, [(apply_corrupt_mask(pk, empty), i) for i, (_k, pk) in enumerate(flows)], "b0")
    det = sum(1 for v in base.values() if v > 0)
    print(f"sanity k=0 (uncorrupted): {det}/{n} detected", flush=True)

    min_k = {}          # flow -> smallest k that evades
    OPTIMAL_MASK = {}   # flow -> the exact packet indices that achieved it
    for k in range(1, MAX_K + 1):
        todo = [i for i in range(n) if i not in min_k]
        # The unevadable flow cannot be saved by any k, so do not waste search on it.
        todo = [i for i in todo if i not in unevadable]
        if not todo:
            break

        items, owner, masks = [], [], []
        for fi in todo:
            m = len(pay[fi])
            if k > m:
                continue
            for combo in itertools.combinations(pay[fi], k):
                items.append(apply_corrupt_mask(flows[fi][1], mask_of(combo)))
                owner.append(fi)
                masks.append(list(combo))
        if not items:
            print(f"k={k}: no candidates left (solved or k>m)", flush=True)
            break
        if len(items) > ITEM_CAP:
            print(f"k={k}: {len(items)} candidates EXCEEDS cap {ITEM_CAP} -> "
                  f"treating this flow as unsolved (lower bound only)", flush=True)
            break

        print(f"k={k}: scoring {len(items)} candidates over {len(todo)} flows ...", flush=True)
        t1 = time.time()
        found = {}
        best_mask = {}
        next_id = 10_000_000 + k * 1_000_000
        for c in range(0, len(items), CHUNK):
            chunk_items = items[c:c + CHUNK]
            chunk_owner = owner[c:c + CHUNK]
            chunk_masks = masks[c:c + CHUNK]
            base = next_id
            ids = list(range(base, base + len(chunk_items)))
            next_id += len(chunk_items)
            res = score(svc, list(zip(chunk_items, ids)), f"k{k}c{c}")
            for cid, v in res.items():
                if v == 0:
                    fi = chunk_owner[cid - base]
                    if fi not in found:
                        found[fi] = k
                        best_mask[fi] = chunk_masks[cid - base]
        for fi in found:
            min_k[fi] = k
            OPTIMAL_MASK[fi] = best_mask[fi]
        print(f"  -> {len(found)} flow(s) solved at k={k}  [{time.time()-t1:.0f}s]", flush=True)

    solved = sorted(min_k)
    unsolved = [i for i in range(n) if i not in min_k and i not in unevadable]
    # A flow the control evades but we could not solve under k<=MAX_K is a bound.
    exact = sum(min_k.values())
    print("\n--- per-flow exact minimum corruption to evade ---")
    for i in solved:
        print(f"  flow {i:2d}: k={min_k[i]}  (payload available={len(pay[i])})")
    for i in unevadable:
        print(f"  flow {i:2d}: UNEVADABLE even with all {len(pay[i])} corrupted")
    for i in unsolved:
        print(f"  flow {i:2d}: not solved for k<={MAX_K} (needs > {MAX_K}); "
              f"control solved it using {len(pay[i])}")

    if not unsolved:
        total = exact
        print(f"\nEXACT global minimum to match control ({len(ca_ev)}/{n} evaded): "
              f"{total} corruptions total, mean {total/n:.2f} vs control {ca_nc:.2f}")
        if total < ca_nc * n:
            print(f"  -> CONTROL IS BEATABLE: {ca_nc - total/n:.2f} fewer corruptions/flow "
                  f"({100*(1-(total/n)/ca_nc):.1f}% saving) at equal evasion")
        else:
            print("  -> control NOT beatable: it is already the sparsest evading plan")
    else:
        print(f"\nPARTIAL: solved {len(solved)}/{n} flows, {len(unsolved)} need k>{MAX_K}.")
        print(f"  lower bound so far: mean >= {exact/n:.2f} (incomplete)")

    out = {"capture": CAPTURE, "n_flows": n,
           "control_mean_corrupt": round(ca_nc, 4),
           "control_evaded": len(ca_ev), "unevadable": unevadable,
           "optimal_mask": {str(fi): OPTIMAL_MASK[fi] for fi in sorted(OPTIMAL_MASK)},
           "min_k": {str(fi): min_k[fi] for fi in sorted(min_k)}}
    os.makedirs("labels", exist_ok=True)
    lpath = f"labels/oracle_{CAPTURE}.json"
    with open(lpath, "w") as fh:
        json.dump(out, fh, indent=1)
    print(f"wrote {len(OPTIMAL_MASK)} supervision labels -> {lpath}")

    print(f"\nelapsed {time.time()-t0:.0f}s")
    svc.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
