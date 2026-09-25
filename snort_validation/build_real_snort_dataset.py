#!/usr/bin/env python3
"""
Build a Snort-labeled training set from all measured CTU-13 captures.

Runs real Snort (ET Open C2 rules) over each capture, joins the alert verdicts
to the measured per-flow features by 5-tuple, and writes one parquet with a
``snort_alert`` column.  This is the training data for the real-feature
surrogate.

USAGE
-----
    python snort_validation/build_real_snort_dataset.py \
        --root data/stratosphere/CTU-13-Dataset \
        --features data/ctu13_real_features.parquet \
        --out data/ctu13_snort_labeled.parquet
"""

import argparse
import sys
import tempfile
from pathlib import Path

import pandas as pd

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "snort_validation"))

from label_real_flows_with_snort import (  # noqa: E402
    run_snort_over_capture, parse_alerts,
)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default="data/stratosphere/CTU-13-Dataset")
    ap.add_argument("--features", default="data/ctu13_real_features.parquet")
    ap.add_argument("--out", default="data/ctu13_snort_labeled.parquet")
    ap.add_argument("--pattern", default="*/botnet-capture-*.pcap",
                    help="glob for the pcaps under --root; widen it for MCFP "
                         "captures, whose pcaps are not all 'botnet-capture-*'.")
    args = ap.parse_args()

    df = pd.read_parquet(args.features)
    root = Path(args.root)
    captures = sorted(root.glob(args.pattern))
    if not captures:
        print(f"[-] no captures under {root}", file=sys.stderr)
        return 1

    workdir = Path(tempfile.mkdtemp(prefix="snortds_"))
    all_parts = []
    for pcap in captures:
        stem = pcap.stem
        part = df[df["capture"] == stem].copy()
        if part.empty:
            print(f"[-] no feature rows for {stem}, skipping")
            continue
        print(f"[*] {stem}: {len(part):,} flows")
        alert_path = run_snort_over_capture(pcap, workdir / stem)
        alerted, sid_counts, messages, n_lines = parse_alerts(alert_path)
        print(f"    {n_lines:,} alert lines, {len(sid_counts)} distinct rules")

        def verdict(row):
            k1 = (row["src"], int(row["sport"]), row["dst"], int(row["dport"]), row["proto"])
            k2 = (row["dst"], int(row["dport"]), row["src"], int(row["sport"]), row["proto"])
            return int(k1 in alerted or k2 in alerted)

        part["snort_alert"] = part.apply(verdict, axis=1)
        n_alert = int(part["snort_alert"].sum())
        print(f"    -> {n_alert:,}/{len(part):,} flows alerted "
              f"({100.0 * n_alert / len(part):.2f}%)")
        all_parts.append(part)

    if not all_parts:
        print("[-] nothing labeled", file=sys.stderr)
        return 1

    out_df = pd.concat(all_parts, ignore_index=True)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out_df.to_parquet(out, index=False)
    n_alert = int(out_df["snort_alert"].sum())
    print(f"\n[+] wrote {out}")
    print(f"[+] {len(out_df):,} flows, {n_alert:,} alerted "
          f"({100.0 * n_alert / len(out_df):.2f}%)")
    print(f"[+] per-capture alert rate:")
    for stem, grp in out_df.groupby("capture"):
        print(f"      {stem:<40} {int(grp['snort_alert'].sum()):>5}/"
              f"{len(grp):<6} ({100.0 * grp['snort_alert'].mean():.2f}%)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
