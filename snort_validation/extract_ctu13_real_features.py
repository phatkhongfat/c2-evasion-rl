#!/usr/bin/env python3
"""
Extract flow records with REAL packet-derived features from CTU-13 pcaps.

WHY THIS EXISTS
---------------
Every feature the project used before this script was *derived* from six
flow-level aggregates (see ``ai_agent/flow_features.py``, whose docstring
admits it: "packet-size distribution and inter-arrival statistics cannot be
measured from this data").  A surrogate trained on reconstructions can only
ever learn the reconstruction model, not the IDS's actual decision boundary.

This script reads the raw Stratosphere IPS / CTU-13 captures and measures, per
flow, the quantities a signature-based IDS actually keys on: byte/packet
counts in each direction, real packet-size distribution, real inter-arrival
times, TCP flag counts and payload statistics.

LABELING
--------
CTU-13 ships ``.binetflow`` files: one row per flow with a ``Label`` column
(``flow=From-Botnet-...``, ``flow=Background-...``, ``flow=To-Botnet-...``).
Flows are matched to packets on the 5-tuple.  A flow is malicious iff its
label starts with ``flow=From-Botnet`` or ``flow=To-Botnet``.

USAGE
-----
    python snort_validation/extract_ctu13_real_features.py \
        --pcap data/stratosphere/CTU-13-Dataset/1/botnet-capture-20110810-neris.pcap \
        --binetflow data/stratosphere/CTU-13-Dataset/1/capture20110810.binetflow \
        --out data/ctu13_real_features.parquet \
        --max-flows 20000

    # all captures at once
    python snort_validation/extract_ctu13_real_features.py --all \
        --root data/stratosphere/CTU-13-Dataset \
        --out data/ctu13_real_features.parquet
"""

import argparse
import csv
import sys
import time
from collections import defaultdict
from pathlib import Path

import numpy as np
import pandas as pd
from scapy.all import PcapReader, IP, TCP, UDP, ICMP, Raw

# --------------------------------------------------------------------------
# Feature definition
# --------------------------------------------------------------------------
# These are MEASURED, not derived.  Every one of them can be computed from a
# single captured flow, which is what makes them usable as (a) surrogate
# inputs and (b) quantities the RL agent can actually move.
FEATURE_COLUMNS = [
    # directionality / volume
    "fwd_pkts", "bwd_pkts", "fwd_bytes", "bwd_bytes", "byte_ratio",
    # real packet-size distribution (payload+header, bytes on the wire)
    "pkt_size_mean", "pkt_size_std", "pkt_size_min", "pkt_size_max",
    "pkt_size_median", "pkt_size_iqr", "pkt_size_cv",
    # real inter-arrival timing (seconds)
    "iat_mean", "iat_std", "iat_min", "iat_max", "iat_cv",
    # rates
    "pkt_rate", "bytes_rate", "flow_duration",
    # TCP flags (real counts, not presence)
    "syn_count", "fin_count", "rst_count", "psh_count", "ack_count",
    "urg_count", "flags_variety",
    # payload / header split
    "payload_bytes", "payload_fraction", "hdr_bytes",
    # payload content statistics (what content-matching rules key on)
    "payload_mean_len", "payload_max_len", "payload_entropy",
    # protocol / ports
    "proto_id", "dst_port", "is_well_known_port",
    # synthetic-friendly, "how easy is this flow to fingerprint" summaries
    "n_distinct_pkt_sizes", "dominant_pkt_size_frac",
]

# Subset that the current 6-feature surrogate can also see, kept for a fair
# apples-to-apples comparison in the ablation report.
OVERLAP_FEATURES = ["pkt_size_mean", "pkt_rate", "bytes_rate"]

LABEL_MALICIOUS_PREFIXES = ("flow=From-Botnet", "flow=To-Botnet")


def _entropy(counts):
    """Shannon entropy (bits/byte) of a byte-value histogram."""
    total = counts.sum()
    if total <= 0:
        return 0.0
    p = counts[counts > 0] / total
    return float(-(p * np.log2(p)).sum())


def load_labels(binetflow_path):
    """Return {(src_ip, sport, dst_ip, dport, proto): is_malicious}.

    CTU-13 labels live at flow granularity.  Where the same 5-tuple appears in
    several rows (long-lived flows are split), a tuple is malicious if ANY of
    its rows is botnet-labelled -- erring toward labelling malicious, which is
    the conservative choice for a detection dataset.
    """
    labels = {}
    n_rows = n_mal = 0
    with open(binetflow_path, newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            n_rows += 1
            try:
                sport = int(row["Sport"])
                dport = int(row["Dport"])
            except (KeyError, TypeError, ValueError):
                continue
            proto = (row.get("Proto") or "").strip().lower()
            label = (row.get("Label") or "").strip()
            mal = label.startswith(LABEL_MALICIOUS_PREFIXES)
            if mal:
                n_mal += 1
            for key in (
                (row["SrcAddr"], sport, row["DstAddr"], dport, proto),
                (row["DstAddr"], dport, row["SrcAddr"], sport, proto),
            ):
                labels[key] = labels.get(key, False) or mal
    return labels, n_rows, n_mal


class FlowAccumulator:
    """Accumulate per-5-tuple packet statistics in one pass over a pcap."""

    __slots__ = ("times", "sizes", "fwd_pkts", "bwd_pkts", "fwd_bytes",
                 "bwd_bytes", "syn", "fin", "rst", "psh", "ack", "urg",
                 "payload_lens", "payload_bytes", "hdr_bytes", "byte_hist",
                 "src", "sport", "dst", "dport", "proto")

    def __init__(self, src, sport, dst, dport, proto):
        self.src, self.sport, self.dst, self.dport, self.proto = (
            src, sport, dst, dport, proto)
        self.times = []
        self.sizes = []
        self.fwd_pkts = self.bwd_pkts = 0
        self.fwd_bytes = self.bwd_bytes = 0
        self.syn = self.fin = self.rst = self.psh = self.ack = self.urg = 0
        self.payload_lens = []
        self.payload_bytes = 0
        self.hdr_bytes = 0
        self.byte_hist = np.zeros(256, dtype=np.int64)

    def add(self, ts, size, hdr, payload, flags, is_fwd):
        self.times.append(ts)
        self.sizes.append(size)
        self.hdr_bytes += hdr
        if is_fwd:
            self.fwd_pkts += 1
            self.fwd_bytes += size
        else:
            self.bwd_pkts += 1
            self.bwd_bytes += size
        if flags is not None:
            if flags & 0x02:
                self.syn += 1
            if flags & 0x01:
                self.fin += 1
            if flags & 0x04:
                self.rst += 1
            if flags & 0x08:
                self.psh += 1
            if flags & 0x10:
                self.ack += 1
            if flags & 0x20:
                self.urg += 1
        if payload:
            self.payload_lens.append(len(payload))
            self.payload_bytes += len(payload)
            b = np.frombuffer(payload[:512], dtype=np.uint8)
            self.byte_hist += np.bincount(b, minlength=256)


def finalize(acc, is_malicious, label_raw):
    """Turn a FlowAccumulator into a feature row (or None if degenerate)."""
    n = len(acc.sizes)
    if n == 0:
        return None
    sizes = np.asarray(acc.sizes, dtype=np.float64)
    times = np.asarray(acc.times, dtype=np.float64)

    dur = float(times[-1] - times[0]) if n > 1 else 0.0
    if n > 1:
        iats = np.diff(np.sort(times))
        iat_mean = float(iats.mean())
        iat_std = float(iats.std())
        iat_min = float(iats.min())
        iat_max = float(iats.max())
        iat_cv = iat_std / iat_mean if iat_mean > 0 else 0.0
    else:
        iat_mean = iat_std = iat_min = iat_max = iat_cv = 0.0

    pkt_mean = float(sizes.mean())
    pkt_std = float(sizes.std())
    pkt_min = float(sizes.min())
    pkt_max = float(sizes.max())
    pkt_median = float(np.median(sizes))
    pkt_iqr = float(np.percentile(sizes, 75) - np.percentile(sizes, 25))
    pkt_cv = pkt_std / pkt_mean if pkt_mean > 0 else 0.0

    # distinct packet sizes + how dominant the most common one is: a
    # fingerprinting-friendly summary (uniform padding => low variety).
    vals, counts = np.unique(sizes.astype(np.int64), return_counts=True)
    n_distinct = int(len(vals))
    dominant_frac = float(counts.max() / n)

    total_bytes = acc.fwd_bytes + acc.bwd_bytes
    payload_lens = acc.payload_lens
    payload_entropy = _entropy(acc.byte_hist) if acc.payload_bytes else 0.0

    flag_vals = (acc.syn, acc.fin, acc.rst, acc.psh, acc.ack, acc.urg)
    flags_variety = sum(1 for v in flag_vals if v > 0)

    row = {
        "src": acc.src, "sport": acc.sport,
        "dst": acc.dst, "dport": acc.dport, "proto": acc.proto,
        "fwd_pkts": acc.fwd_pkts, "bwd_pkts": acc.bwd_pkts,
        "fwd_bytes": acc.fwd_bytes, "bwd_bytes": acc.bwd_bytes,
        "byte_ratio": (acc.fwd_bytes / acc.bwd_bytes) if acc.bwd_bytes else 0.0,
        "pkt_size_mean": pkt_mean, "pkt_size_std": pkt_std,
        "pkt_size_min": pkt_min, "pkt_size_max": pkt_max,
        "pkt_size_median": pkt_median, "pkt_size_iqr": pkt_iqr,
        "pkt_size_cv": pkt_cv,
        "iat_mean": iat_mean, "iat_std": iat_std,
        "iat_min": iat_min, "iat_max": iat_max, "iat_cv": iat_cv,
        "pkt_rate": (n / dur) if dur > 0 else 0.0,
        "bytes_rate": (total_bytes / dur) if dur > 0 else 0.0,
        "flow_duration": dur,
        "syn_count": acc.syn, "fin_count": acc.fin, "rst_count": acc.rst,
        "psh_count": acc.psh, "ack_count": acc.ack, "urg_count": acc.urg,
        "flags_variety": flags_variety,
        "payload_bytes": acc.payload_bytes,
        "payload_fraction": (acc.payload_bytes / total_bytes) if total_bytes else 0.0,
        "hdr_bytes": acc.hdr_bytes,
        "payload_mean_len": float(np.mean(payload_lens)) if payload_lens else 0.0,
        "payload_max_len": float(np.max(payload_lens)) if payload_lens else 0.0,
        "payload_entropy": payload_entropy,
        "proto_id": {"tcp": 6, "udp": 17, "icmp": 1}.get(acc.proto, 0),
        "dst_port": acc.dport,
        "is_well_known_port": int(acc.dport < 1024),
        "n_distinct_pkt_sizes": n_distinct,
        "dominant_pkt_size_frac": dominant_frac,
        "tot_pkts": n, "tot_bytes": total_bytes,
        "is_malicious": int(is_malicious),
        "label_raw": label_raw,
    }
    return row


def extract_pcap(pcap_path, labels, max_flows=None, max_packets=None,
                 flush_every=200_000):
    """One pass over ``pcap_path``; yields feature rows.

    A flow is closed and emitted when it is evicted (bounded memory) or when
    the capture ends.  ``max_packets`` caps the work per capture.
    """
    flows = {}
    rows = []
    n_pkts = 0
    t0 = time.time()

    def emit(key, acc):
        src, sport, dst, dport, proto = key
        is_mal = labels.get((src, sport, dst, dport, proto))
        if is_mal is None:
            # Unlabelled tuple: CTU-13 background is the norm, so treat as benign.
            is_mal = False
            label_raw = "flow=Unlabelled"
        else:
            label_raw = "flow=From-Botnet" if is_mal else "flow=Background"
        r = finalize(acc, is_mal, label_raw)
        if r is not None:
            rows.append(r)

    with PcapReader(str(pcap_path)) as pr:
        for pkt in pr:
            n_pkts += 1
            if max_packets and n_pkts > max_packets:
                break
            try:
                if IP not in pkt:
                    continue
                ip = pkt[IP]
                ts = float(pkt.time)
                size = len(pkt)
                proto = "tcp" if TCP in pkt else "udp" if UDP in pkt else \
                        "icmp" if ICMP in pkt else "other"
                if TCP in pkt:
                    l4 = pkt[TCP]
                    sport, dport = int(l4.sport), int(l4.dport)
                    flags = int(l4.flags)
                    hdr = 40
                elif UDP in pkt:
                    l4 = pkt[UDP]
                    sport, dport = int(l4.sport), int(l4.dport)
                    flags = None
                    hdr = 28
                elif ICMP in pkt:
                    sport = dport = 0
                    flags = None
                    hdr = 28
                else:
                    continue
                payload = bytes(pkt[Raw].load) if Raw in pkt else b""
            except Exception:
                continue

            key = (ip.src, sport, ip.dst, dport, proto)
            rkey = (ip.dst, dport, ip.src, sport, proto)
            if key in flows:
                acc = flows[key]
                is_fwd = True
            elif rkey in flows:
                acc = flows[rkey]
                is_fwd = False
            else:
                acc = FlowAccumulator(ip.src, sport, ip.dst, dport, proto)
                flows[key] = acc
                is_fwd = True
            acc.add(ts, size, hdr, payload, flags, is_fwd)

            if len(flows) >= 200_000:
                # memory guard: flush half the table
                for k in list(flows)[:100_000]:
                    emit(k, flows.pop(k))

            if max_flows and len(rows) >= max_flows:
                break

            if n_pkts % flush_every == 0:
                print(f"    ... {n_pkts:,} packets, {len(rows):,} flows",
                      file=sys.stderr)

    for k, acc in flows.items():
        emit(k, acc)

    print(f"    {n_pkts:,} packets -> {len(rows):,} flows "
          f"in {time.time() - t0:.1f}s", file=sys.stderr)
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap")
    ap.add_argument("--binetflow")
    ap.add_argument("--all", action="store_true",
                    help="process every capture under --root")
    ap.add_argument("--root", default="data/stratosphere/CTU-13-Dataset")
    ap.add_argument("--out", default="data/ctu13_real_features.parquet")
    ap.add_argument("--max-flows", type=int, default=None)
    ap.add_argument("--max-packets", type=int, default=None)
    args = ap.parse_args()

    all_rows = []
    if args.all:
        root = Path(args.root)
        captures = sorted(root.glob("*/botnet-capture-*.pcap"))
        if not captures:
            print(f"[-] no captures under {root}", file=sys.stderr)
            return 1
        for pcap in captures:
            d = pcap.parent
            bfs = sorted(d.glob("*.binetflow"))
            print(f"[*] {pcap.name}", file=sys.stderr)
            labels, n_rows, n_mal = ({}, 0, 0)
            if bfs:
                labels, n_rows, n_mal = load_labels(bfs[0])
                print(f"    labels: {n_rows:,} rows, {n_mal:,} malicious",
                      file=sys.stderr)
            rows = extract_pcap(pcap, labels, max_flows=args.max_flows,
                                max_packets=args.max_packets)
            for r in rows:
                r["capture"] = pcap.stem
            all_rows.extend(rows)
    else:
        if not args.pcap:
            print("[-] --pcap or --all required", file=sys.stderr)
            return 1
        labels, n_rows, n_mal = ({}, 0, 0)
        if args.binetflow:
            labels, n_rows, n_mal = load_labels(args.binetflow)
            print(f"[*] labels: {n_rows:,} rows, {n_mal:,} malicious",
                  file=sys.stderr)
        rows = extract_pcap(args.pcap, labels, max_flows=args.max_flows,
                            max_packets=args.max_packets)
        all_rows = rows

    if not all_rows:
        print("[-] no flows extracted", file=sys.stderr)
        return 1

    df = pd.DataFrame(all_rows)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(out, index=False)
    n_mal = int(df["is_malicious"].sum())
    print(f"[+] wrote {out}: {len(df):,} flows, "
          f"{n_mal:,} malicious ({100.0 * n_mal / len(df):.1f}%)")
    print(f"[+] columns: {len(df.columns)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
