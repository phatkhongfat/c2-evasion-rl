#!/usr/bin/env python3
"""
Label real CTU-13 flows with REAL Snort (ET Open C2) verdicts, then rank the
measured features by how well they separate alerted from clean flows.

WHY THIS DESIGN
---------------
A first attempt rebuilt a pcap per flow from its measured *statistics* and ran
Snort on each.  That yields ~0 alerts, and the reason is fundamental: the
ET Open C2 rules are overwhelmingly **content signatures** (they match byte
strings in the payload, e.g. a malware User-Agent or a checkin token).  A pcap
reconstructed from packet-size and timing statistics carries no original
payload, so no content rule can ever fire.  Reconstructed traffic can only
ever test header/behaviour rules.

The correct method is the reverse direction:

    1. run Snort ONCE over the real capture (real payloads, real timing);
    2. read the alerts back and extract the 5-tuple of each alert;
    3. join those tuples against the measured per-flow feature table.

Every flow then carries a genuine, payload-informed Snort verdict *and* the
measured features, so feature-vs-verdict correlation is meaningful.

USAGE
-----
    python snort_validation/label_real_flows_with_snort.py \
        --pcap data/stratosphere/CTU-13-Dataset/1/botnet-capture-20110810-neris.pcap \
        --features data/ctu13_real_features.parquet \
        --out snort_validation/reports/real_feature_validation.json
"""

import argparse
import json
import re
import subprocess
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

import numpy as np
import pandas as pd

REPO = Path(__file__).resolve().parent.parent
SNORT_CONF = REPO / "snort_validation/et_open_c2/snort_et_c2.conf"

# "08/10-16:06:42.826290  [**] [1:2012533:6] ET TROJAN ... {TCP} 147.32.84.165:1044 -> 60.190.223.75:888"
ALERT_RE = re.compile(
    r"\[\*\*\]\s*\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s*"
    r"(?P<msg>.*?)\s*\[\*\*\].*?"
    r"\{(?P<proto>TCP|UDP|ICMP)\}\s*"
    r"(?P<src>[\d.]+):(?P<sport>\d+)\s*->\s*(?P<dst>[\d.]+):(?P<dport>\d+)"
)

TEST_FEATURES = [
    "fwd_pkts", "bwd_pkts", "fwd_bytes", "bwd_bytes", "byte_ratio",
    "pkt_size_mean", "pkt_size_std", "pkt_size_min", "pkt_size_max",
    "pkt_size_median", "pkt_size_iqr", "pkt_size_cv",
    "iat_mean", "iat_std", "iat_min", "iat_max", "iat_cv",
    "pkt_rate", "bytes_rate", "flow_duration",
    "syn_count", "fin_count", "rst_count", "psh_count", "ack_count",
    "urg_count", "flags_variety",
    "payload_bytes", "payload_fraction", "hdr_bytes",
    "payload_mean_len", "payload_max_len", "payload_entropy",
    "proto_id", "dst_port", "is_well_known_port",
    "n_distinct_pkt_sizes", "dominant_pkt_size_frac",
    "tot_pkts", "tot_bytes",
]


def run_snort_over_capture(pcap, workdir, max_packets=None):
    """One Snort pass over a real capture. Returns alert file path."""
    workdir.mkdir(parents=True, exist_ok=True)
    cmd = ["snort", "-c", str(SNORT_CONF), "-r", str(pcap),
           "-l", str(workdir), "-q", "-A", "fast"]
    print(f"[*] snort over {Path(pcap).name} ...")
    r = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if r.returncode != 0:
        print(f"    snort exit {r.returncode}: {r.stderr[-300:]}", file=sys.stderr)
    alert = workdir / "alert"
    return alert if alert.exists() else None


def parse_alerts(alert_path):
    """Return (set of alerted tuples, per-sid counts, message list)."""
    tuples = set()
    sid_counts = defaultdict(int)
    messages = {}
    n_lines = 0
    if not alert_path:
        return tuples, sid_counts, messages, 0
    with open(alert_path, errors="ignore") as fh:
        for line in fh:
            n_lines += 1
            m = ALERT_RE.search(line)
            if not m:
                continue
            d = m.groupdict()
            proto = d["proto"].lower()
            src, dst = d["src"], d["dst"]
            sport, dport = int(d["sport"]), int(d["dport"])
            sid = int(d["sid"])
            sid_counts[sid] += 1
            messages[sid] = d["msg"].strip()
            # store both directions so the join is orientation-independent
            tuples.add((src, sport, dst, dport, proto))
            tuples.add((dst, dport, src, sport, proto))
    return tuples, sid_counts, messages, n_lines


def auc_score(x, y):
    x = np.asarray(x, dtype=float)
    y = np.asarray(y, dtype=bool)
    n_pos, n_neg = int(y.sum()), int((~y).sum())
    if n_pos == 0 or n_neg == 0:
        return float("nan")
    order = np.argsort(x, kind="mergesort")
    ranks = np.empty(len(x), dtype=float)
    ranks[order] = np.arange(1, len(x) + 1)
    xs = x[order]
    i = 0
    while i < len(xs):
        j = i
        while j + 1 < len(xs) and xs[j + 1] == xs[i]:
            j += 1
        if j > i:
            ranks[order[i:j + 1]] = (i + j + 2) / 2.0
        i = j + 1
    return float((ranks[y].sum() - n_pos * (n_pos + 1) / 2.0) / (n_pos * n_neg))


def cohens_d(a, b):
    a, b = np.asarray(a, float), np.asarray(b, float)
    if len(a) < 2 or len(b) < 2:
        return 0.0
    va, vb = a.var(ddof=1), b.var(ddof=1)
    pooled = np.sqrt(((len(a) - 1) * va + (len(b) - 1) * vb) /
                     max(len(a) + len(b) - 2, 1))
    return float((a.mean() - b.mean()) / pooled) if pooled else 0.0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--features", default="data/ctu13_real_features.parquet")
    ap.add_argument("--out", default="snort_validation/reports/real_feature_validation.json")
    ap.add_argument("--capture", default=None,
                    help="filter feature rows to this capture stem")
    args = ap.parse_args()

    df = pd.read_parquet(args.features)
    capture_stem = args.capture or Path(args.pcap).stem
    if "capture" in df.columns:
        df = df[df["capture"] == capture_stem].copy()
    print(f"[*] {len(df):,} measured flows for capture '{capture_stem}'")

    workdir = Path(tempfile.mkdtemp(prefix="snortlabel_"))
    alert_path = run_snort_over_capture(args.pcap, workdir)
    alerted, sid_counts, messages, n_alert_lines = parse_alerts(alert_path)
    print(f"[*] {n_alert_lines:,} alert lines, {len(sid_counts)} distinct rules, "
          f"{len(alerted):,} oriented tuples")

    # --- join verdicts onto flows ----------------------------------------
    def verdict(row):
        k1 = (row["src"], int(row["sport"]), row["dst"], int(row["dport"]), row["proto"])
        k2 = (row["dst"], int(row["dport"]), row["src"], int(row["sport"]), row["proto"])
        return int(k1 in alerted or k2 in alerted)

    df["snort_alert"] = df.apply(verdict, axis=1)
    n_alert_flows = int(df["snort_alert"].sum())
    rate = n_alert_flows / max(len(df), 1)
    print(f"[*] flows with >=1 Snort alert: {n_alert_flows:,}/{len(df):,} "
          f"({100.0 * rate:.1f}%)")

    # --- per-feature separation ------------------------------------------
    y = df["snort_alert"].to_numpy().astype(bool)
    results = []
    for feat in TEST_FEATURES:
        if feat not in df.columns:
            continue
        x = df[feat].to_numpy(dtype=float)
        finite = np.isfinite(x)
        if finite.sum() < 20:
            continue
        xf, yf = x[finite], y[finite]
        if yf.sum() == 0 or (~yf).sum() == 0:
            continue
        a = auc_score(xf, yf)
        pos, neg = xf[yf], xf[~yf]
        results.append({
            "feature": feat,
            "auc": round(float(a), 4) if a == a else None,
            "auc_dist_from_random": round(abs(float(a) - 0.5), 4) if a == a else None,
            "cohens_d": round(cohens_d(pos, neg), 4),
            "mean_alerted": round(float(pos.mean()), 4),
            "mean_clean": round(float(neg.mean()), 4),
        })
    results.sort(key=lambda r: -(r["auc_dist_from_random"] or 0))

    top_rules = sorted(sid_counts.items(), key=lambda kv: -kv[1])[:25]

    report = {
        "capture": capture_stem,
        "pcap": str(args.pcap),
        "n_flows": int(len(df)),
        "n_alert_flows": n_alert_flows,
        "alert_flow_rate": round(rate, 4),
        "n_alert_lines": n_alert_lines,
        "n_distinct_rules_fired": len(sid_counts),
        "top_rules": [
            {"sid": s, "count": c, "msg": messages.get(s, "")}
            for s, c in top_rules
        ],
        "ruleset": "ET Open C2 subset (21,374 rules)",
        "snort_conf": str(SNORT_CONF),
        "feature_ranking": results,
        "note": (
            "Snort ran over the REAL capture (real payloads), and alerts were "
            "joined to measured per-flow features by 5-tuple. AUC is rank-based "
            "and symmetric: 0.5 = no information, 1.0/0.0 = perfect separation."
        ),
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w") as fh:
        json.dump(report, fh, indent=2)

    print(f"\n{'feature':<26} {'AUC':>7} {'|AUC-.5|':>9} {'d':>8}")
    print("-" * 54)
    for r in results[:22]:
        auc = f"{r['auc']:.3f}" if r["auc"] is not None else "n/a"
        dist = f"{r['auc_dist_from_random']:.3f}" if r["auc_dist_from_random"] is not None else "n/a"
        print(f"{r['feature']:<26} {auc:>7} {dist:>9} {r['cohens_d']:>8.3f}")

    print("\ntop rules that fired:")
    for s, c in top_rules[:8]:
        print(f"  {c:>5}x [{s}] {messages.get(s, '')[:70]}")
    print(f"\n[+] report written: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
