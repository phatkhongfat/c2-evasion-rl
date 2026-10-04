#!/usr/bin/env python3
"""
How many usable flows does each labelled capture actually yield?

``--flows N`` is a REQUEST, not a guarantee: the env keeps only flows it can
find with >=4 packets in the pcap, so a capture can hold hundreds of
Snort-alerted rows and still supply far fewer flows.  The corrupt-cost sweep
and the flow scale-up both need to know the real ceiling per capture before
choosing their configurations, otherwise they silently measure a smaller pool
than the report claims.

    python snort_validation/capture_pool_sizes.py --dataset stratosphere
"""
import argparse
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default="stratosphere")
    ap.add_argument("--table", default=None,
                    help="labelled parquet; defaults per --dataset")
    ap.add_argument("--min-flows", type=int, default=1)
    args = ap.parse_args()

    import pandas as pd
    from real_packet_env import MCFP_LABELED, LABELED, RealPacketEnv

    table = Path(args.table) if args.table else (
        MCFP_LABELED if args.dataset == "stratosphere" else LABELED)
    df = pd.read_parquet(table)
    df = df[(df["snort_alert"] == 1) & (df["tot_pkts"] >= 4)]
    counts = df.groupby("capture").size().sort_values(ascending=False)

    rows = []
    for capture, n_rows in counts.items():
        if n_rows < args.min_flows:
            continue
        try:
            env = RealPacketEnv(n_flows=None, batch_size=1, capture=capture,
                                dataset=args.dataset)
            n = env.n_loaded
            pk = sorted(len(p) for _k, p in env.flows)
        except Exception as exc:  # noqa: BLE001
            print(f"[-] {capture}: {exc}", file=sys.stderr)
            continue
        rows.append({"capture": capture, "alerted_rows": int(n_rows),
                     "usable_flows": n, "min_pkts": pk[0],
                     "max_pkts": pk[-1]})

    rows.sort(key=lambda r: -r["usable_flows"])
    print(f"{'capture':<34}{'alerted_rows':>13}{'usable_flows':>13}"
          f"{'min_pkts':>10}{'max_pkts':>10}")
    for r in rows:
        print(f"{r['capture']:<34}{r['alerted_rows']:>13}"
              f"{r['usable_flows']:>13}{r['min_pkts']:>10}{r['max_pkts']:>10}")
    print(f"\ntotal usable flows: {sum(r['usable_flows'] for r in rows)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
