#!/usr/bin/env python3
"""
Build a Snort-labeled flow table for Stratosphere / MCFP captures.

WHY THIS EXISTS
---------------
``RealPacketEnv`` draws its flows from ``data/ctu13_snort_labeled.parquet``:
measured per-flow features joined to REAL Snort (ET Open C2) verdicts by
5-tuple.  That table only ever covered CTU-13, so every "cross-capture" run was
really a re-slice of one dataset.  This script produces the same table for any
Stratosphere Malware Capture Facility capture, which is what makes a genuine
cross-capture comparison possible.

The method is the project's established one (see
``label_real_flows_with_snort.py``): run Snort ONCE over the whole pcap, read
the alerts back, and join the alerted 5-tuples against the measured feature
rows.  Reconstructing pcaps from flow statistics cannot work -- the ET Open C2
rules are content signatures, and a reconstruction carries no original payload.

LABELS
------
CTU-13 ships a ``.binetflow`` per capture and MCFP ships
``detailed-bidirectional-flow-labels/<stem>.binetflow``.  A capture whose
labels cannot be fetched is still usable: MCFP public pcaps are *botnet-only*
by construction (the full-traffic capture is withheld as private), so every
flow in them is malicious by construction and the label is recorded as
``flow=From-Botnet (unlabelled-capture)``.  ``label_source`` on each row says
which of the two paths produced it, so nothing silently claims a label it
does not have.

USAGE
-----
    python snort_validation/build_mcfp_snort_dataset.py \
        --captures botnet-capture-20110810-neris botnet-capture-20110815-rbot-dos \
        --out data/mcfp_snort_labeled.parquet
"""
import argparse
import json
import sys
import tempfile
import urllib.request
from pathlib import Path

import pandas as pd

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "snort_validation"))

from extract_ctu13_real_features import extract_pcap, load_labels  # noqa: E402
from label_real_flows_with_snort import (  # noqa: E402
    parse_alerts, run_snort_over_capture,
)

MCFP = "https://mcfp.felk.cvut.cz/publicDatasets"


def fetch_labels(dataset_dir: str, stem: str, dest: Path):
    """Try to fetch the capture's bidirectional flow labels. Returns path|None."""
    if dest.exists() and dest.stat().st_size > 0:
        return dest
    url = (f"{MCFP}/{dataset_dir}/detailed-bidirectional-flow-labels/"
           f"{stem}.binetflow")
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(url, timeout=120) as fh, \
                open(dest, "wb") as out:
            out.write(fh.read())
        return dest if dest.stat().st_size > 0 else None
    except Exception as exc:  # noqa: BLE001 - label file is optional
        print(f"    no labels ({exc})")
        return None


def label_one(pcap: Path, dataset_dir: str, workdir: Path, cache: Path,
              max_packets=None) -> pd.DataFrame:
    stem = pcap.stem
    print(f"[*] {stem} ({pcap.stat().st_size/1e6:.1f} MB)")

    lbl_path = fetch_labels(dataset_dir, stem, cache / f"{stem}.binetflow")
    if lbl_path:
        labels, n_rows, n_mal = load_labels(str(lbl_path))
        src = "binetflow"
        print(f"    labels: {n_rows:,} rows, {n_mal:,} malicious")
    else:
        labels, src = {}, "unlabelled-capture"
        print("    labels: none -- treating all flows as malicious "
              "(MCFP public pcaps are botnet-only)")

    rows = extract_pcap(pcap, labels, max_packets=max_packets)
    if not rows:
        print("    no flows extracted")
        return pd.DataFrame()

    if src == "unlabelled-capture":
        for r in rows:
            r["is_malicious"] = 1
            r["label_raw"] = "flow=From-Botnet"

    alert = run_snort_over_capture(pcap, workdir / stem, max_packets=max_packets)
    alerted, sid_counts, _msgs, n_lines = parse_alerts(alert)
    print(f"    {n_lines:,} alert lines, {len(sid_counts)} distinct rules")

    df = pd.DataFrame(rows)
    keys = list(zip(df["src"], df["sport"].astype(int), df["dst"],
                    df["dport"].astype(int), df["proto"]))
    df["snort_alert"] = [int(k in alerted) for k in keys]
    df["capture"] = stem
    df["dataset_dir"] = dataset_dir
    df["label_source"] = src
    n_alert = int(df["snort_alert"].sum())
    print(f"    -> {n_alert:,}/{len(df):,} flows alerted "
          f"({100.0 * n_alert / len(df):.2f}%), "
          f"{int(df['is_malicious'].sum()):,} malicious")
    return df


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default="data/stratosphere/mcfp")
    ap.add_argument("--captures", nargs="+", required=True,
                    help="capture stems, or 'all' for every local pcap")
    ap.add_argument("--out", default="data/mcfp_snort_labeled.parquet")
    ap.add_argument("--cache", default="data/stratosphere/mcfp_labels")
    ap.add_argument("--max-packets", type=int, default=None)
    ap.add_argument("--min-alerted", type=int, default=1,
                    help="skip captures with fewer Snort-alerted flows than "
                         "this (they cannot supply a training/eval pool)")
    args = ap.parse_args()

    root = Path(args.root)
    pcaps = sorted(root.glob("*/*.pcap"))
    if args.captures != ["all"]:
        wanted = set(args.captures)
        pcaps = [p for p in pcaps if p.stem in wanted]
    if not pcaps:
        print(f"[-] no pcaps matched under {root}", file=sys.stderr)
        return 1

    workdir = Path(tempfile.mkdtemp(prefix="mcfpds_"))
    cache = Path(args.cache)
    parts, skipped = [], []
    for pcap in pcaps:
        try:
            df = label_one(pcap, pcap.parent.name, workdir, cache,
                           max_packets=args.max_packets)
        except Exception as exc:  # noqa: BLE001 - one bad capture must not
            print(f"[!] {pcap.stem} failed: {exc}", file=sys.stderr)
            skipped.append(pcap.stem)
            continue
        if df.empty or int(df["snort_alert"].sum()) < args.min_alerted:
            skipped.append(pcap.stem)
            continue
        parts.append(df)

    if not parts:
        print("[-] nothing labelled", file=sys.stderr)
        return 1

    out_df = pd.concat(parts, ignore_index=True)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out_df.to_parquet(out, index=False)

    summary = {stem: {"flows": int(len(g)),
                      "alerted": int(g["snort_alert"].sum()),
                      "malicious": int(g["is_malicious"].sum()),
                      "label_source": str(g["label_source"].iloc[0])}
               for stem, g in out_df.groupby("capture")}
    print(f"\n[+] wrote {out}: {len(out_df):,} flows, "
          f"{int(out_df['snort_alert'].sum()):,} alerted")
    print(json.dumps({"captures": summary, "skipped": skipped}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
