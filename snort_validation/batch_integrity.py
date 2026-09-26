"""DIAGNOSTIC: is score() trustworthy when a batch holds many candidates?

The oracle labelled ALL payload packets valid on 20110819-bot, but a one-candidate
-at-a-time re-check found ZERO valid. The difference between the two runs was
batch size (252 in one call vs 1 per call), so batch size is the suspect.

This compares the same 252 candidates measured three ways: one big batch,
chunks of 24, and chunks of 4. If verdicts disagree, the large-batch path is
untrustworthy and every result computed with it must be discarded.
"""
import sys
import numpy as np
from scapy.all import Raw

sys.path.insert(0, "ai_agent")
sys.path.insert(0, "snort_validation")

from snort_bandit import apply_corrupt_mask, score, ACTION_MAX_PACKETS
from snort_resident_service import ResidentSnortService
from real_packet_env import RealPacketEnv

svc = ResidentSnortService()
if not svc.start():
    print("SNORT UNAVAILABLE:", svc.error)
    sys.exit(1)

flows = RealPacketEnv(n_flows=24, capture="botnet-capture-20110819-bot",
                      dataset="ctu13", batch_size=64).flows

cand, items = [], []
for fi in range(24):
    pk = flows[fi][1]
    for j in [i for i, p in enumerate(pk) if Raw in p and i < ACTION_MAX_PACKETS]:
        m = np.zeros(ACTION_MAX_PACKETS, dtype=np.float32)
        m[j] = 1.0
        items.append(apply_corrupt_mask(pk, m))
        cand.append((fi, j))
print(f"total candidates: {len(items)}", flush=True)


def run_chunked(size, tag):
    out = {}
    for c in range(0, len(items), size):
        idxs = list(range(c, min(c + size, len(items))))
        sub = [items[i] for i in idxs]
        ids = [2_000_000 + i for i in idxs]
        r = score(svc, list(zip(sub, ids)), tag)
        for t, i in enumerate(idxs):
            out[i] = r.get(ids[t], "MISSING")
    return out


big = run_chunked(len(items), "big")
print(f"ONE batch of {len(items)}: evaded(zeros)="
      f"{sum(1 for v in big.values() if v == 0)}  "
      f"detected={sum(1 for v in big.values() if isinstance(v, int) and v > 0)}  "
      f"missing={sum(1 for v in big.values() if v == 'MISSING')}", flush=True)

small = run_chunked(4, "small")
print(f"chunks of 4        : evaded(zeros)="
      f"{sum(1 for v in small.values() if v == 0)}  "
      f"detected={sum(1 for v in small.values() if isinstance(v, int) and v > 0)}  "
      f"missing={sum(1 for v in small.values() if v == 'MISSING')}", flush=True)

mid = run_chunked(24, "mid")
print(f"chunks of 24       : evaded(zeros)="
      f"{sum(1 for v in mid.values() if v == 0)}  "
      f"detected={sum(1 for v in mid.values() if isinstance(v, int) and v > 0)}  "
      f"missing={sum(1 for v in mid.values() if v == 'MISSING')}", flush=True)

print("\ndisagreements vs chunks-of-4:")
for name, res in (("one-big-batch", big), ("chunks-of-24", mid)):
    mm = [i for i in range(len(items)) if res[i] != small[i]]
    print(f"  {name}: {len(mm)}/{len(items)} disagree")
    for i in mm[:8]:
        print(f"    flow={cand[i][0]:2d} pkt={cand[i][1]:2d}  "
              f"{name}={res[i]}  chunks4={small[i]}")

svc.stop()
print("done")
