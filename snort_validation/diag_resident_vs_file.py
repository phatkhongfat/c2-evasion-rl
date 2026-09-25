#!/usr/bin/env python3
"""
Diagnose: resident (lo replay) vs one-shot (file) Snort verdicts on the same flows.

The resident service is the speedup that makes a 200-flow sweep affordable, but
it replays frames onto ``lo`` instead of reading a pcap, so its verdicts are
only trustworthy if they MATCH the one-shot service on identical input.  This
script is that comparison, per capture, with the SIDs that fired in each mode.

A capture where file mode detects flows but resident mode detects none is a
resident-service defect, not an evasion result -- and it silently reads as
"100% evasion for every policy including random", which is exactly the
impossible number the repo has hit before.

    python snort_validation/diag_resident_vs_file.py --capture <stem> [--flows 24]
"""
import argparse
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--capture", default="botnet-capture-20110811-neris")
    ap.add_argument("--dataset", default="stratosphere")
    ap.add_argument("--flows", type=int, default=24)
    args = ap.parse_args()

    from real_packet_env import RealPacketEnv
    from snort_batch_service import SnortBatchService
    from snort_resident_service import ResidentSnortService

    env = RealPacketEnv(n_flows=args.flows, batch_size=args.flows,
                        capture=args.capture, dataset=args.dataset)
    flows = env.flows
    print(f"[*] {args.capture}: {len(flows)} flows, "
          f"packets/flow min/med/max = "
          f"{min(len(p) for _k, p in flows)}/"
          f"{sorted(len(p) for _k, p in flows)[len(flows)//2]}/"
          f"{max(len(p) for _k, p in flows)}")

    items = [(pkts, i) for i, (_k, pkts) in enumerate(flows)]

    batch = SnortBatchService(batch_size=len(items))
    file_counts = batch.alert_counts_chunked(items)
    print(f"[file]     detected {sum(1 for v in file_counts.values() if v)}"
          f"/{len(items)}  total alerts {sum(file_counts.values())}")

    svc = ResidentSnortService()
    if not svc.start():
        print(f"[!] resident unavailable: {svc.error}")
        return 2
    res_counts = svc.alert_counts_chunked(items)
    print(f"[resident] detected {sum(1 for v in res_counts.values() if v)}"
          f"/{len(items)}  total alerts {sum(res_counts.values())}")
    print(f"[resident] stats {svc.stats()}")
    svc.stop()

    agree = sum(1 for i in range(len(items))
                if bool(file_counts.get(i)) == bool(res_counts.get(i)))
    print(f"[*] agreement {agree}/{len(items)}")
    for i in range(len(items)):
        f, r = file_counts.get(i, 0), res_counts.get(i, 0)
        if bool(f) != bool(r):
            print(f"    flow {i}: file={f} resident={r} "
                  f"({len(items[i][0])} pkts)")
    return 0 if agree == len(items) else 1


if __name__ == "__main__":
    sys.exit(main())
