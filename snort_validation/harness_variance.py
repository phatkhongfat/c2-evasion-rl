"""Is the scoring harness deterministic run-to-run?

The cloned policy evaded 12/24 on 20110819-bot while the control measured 24/24
in that same run, but the frontier solver had measured the control at 23/24
with flow 15 unevadable. A verdict that moves between runs invalidates every
comparison built on it, so measure the spread before trusting any number.

Runs the identical corrupt-all plan N times in independent service instances.
"""
import sys

import numpy as np

sys.path.insert(0, "ai_agent")
sys.path.insert(0, "snort_validation")

from real_packet_env import RealPacketEnv                        # noqa: E402
from snort_bandit import apply_corrupt_mask, score, ACTION_MAX_PACKETS  # noqa: E402
from snort_resident_service import ResidentSnortService          # noqa: E402

REPEATS = 5
CAPTURES = [("stratosphere", "botnet-capture-20110811-neris"),
            ("ctu13", "botnet-capture-20110819-bot")]


def main():
    for ds, cap in CAPTURES:
        flows = RealPacketEnv(n_flows=24, capture=cap, dataset=ds,
                              batch_size=64).flows
        ones = np.ones(ACTION_MAX_PACKETS, dtype=np.float32)
        plan = [(apply_corrupt_mask(pk, ones), i) for i, (_k, pk) in enumerate(flows)]
        counts, per_flow = [], []
        for r in range(REPEATS):
            svc = ResidentSnortService()
            if not svc.start():
                print("SNORT UNAVAILABLE:", svc.error)
                return 1
            try:
                res = score(svc, plan, f"rep{r}")
                ev = {i for i, v in res.items() if v == 0}
                counts.append(len(ev))
                per_flow.append({i: (0 if i in ev else 1) for i in range(len(flows))})
            finally:
                svc.stop()
        unstable = [i for i in range(len(flows))
                    if len({pw[i] for pw in per_flow}) > 1]
        print(f"\n=== {cap} ===")
        print(f"  corrupt-all evaded per run : {counts}")
        print(f"  spread                     : {max(counts) - min(counts)} flow(s)")
        print(f"  flows whose verdict moved   : {unstable}")
        if unstable:
            for i in unstable:
                got = [pw[i] for pw in per_flow]
                print(f"    flow {i:2d}: 0=evaded -> {got}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
