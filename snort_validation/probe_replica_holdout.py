#!/usr/bin/env python3
"""Label probe flows with the REAL Snort binary and persist them.

These flows are deliberately chosen to stress the replica where it could
plausibly be wrong (long-duration flows, threshold-boundary packet counts,
both protocols).  Output feeds verify_snort_replica.py.

Run:  /tmp/jev-poc/venv/bin/python snort_validation/probe_replica_holdout.py
"""
from __future__ import annotations

import json
import random
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from flow_to_pcap import synthesize_flow_pcap  # noqa: E402
from snort_query_service import replica_snort_verdict, SNORT_CONF  # noqa: E402

OUT = Path("/tmp/c2scratch/replica_probe")
OUT.mkdir(parents=True, exist_ok=True)
DEST = HERE / "reports" / "replica_probe_labels.json"


def real_verdict(feat, tag):
    pcap = OUT / f"{tag}.pcap"
    logdir = OUT / f"log_{tag}"
    logdir.mkdir(exist_ok=True)
    for stale in logdir.glob("alert*"):
        stale.unlink()
    synthesize_flow_pcap(feat, output_path=pcap)
    subprocess.run(["snort", "-c", str(SNORT_CONF), "-r", str(pcap),
                    "-l", str(logdir), "-q", "-A", "fast"],
                   capture_output=True, text=True, timeout=60)
    n = 0
    for af in logdir.glob("alert*"):
        n += len([ln for ln in open(af, errors="ignore")
                  if ln.strip() and not ln.startswith("#")])
    return n > 0


def build_cases():
    cases = []
    # (a) random broad sweep
    rng = random.Random(1234)
    states = ["CON", "S_", "S_RA", "FSPA_FSPA", "FIN", "INT", "UNK"]
    for _ in range(60):
        cases.append(("holdout", {
            "dur": round(rng.choice([0.0, 0.05, 0.3, 1.0, 5.0, 20.0, 90.0]), 3),
            "tot_pkts": rng.choice([2, 3, 5, 8, 9, 10, 11, 12, 20, 40, 60, 120, 300]),
            "tot_bytes": rng.choice([100, 300, 800, 2000, 5000, 20000, 90000]),
            "src_bytes": rng.choice([0, 50, 200, 900, 3000, 15000, 80000]),
            "proto": rng.choice(["tcp", "tcp", "udp", "udp", "icmp"]),
            "state": rng.choice(states),
        }))
    # (b) threshold-boundary + long-duration cases that discriminate window models
    for pk in [9, 10, 11, 12, 14, 16, 20]:
        for dur in [0.5, 30.0, 120.0, 600.0]:
            cases.append(("disc", {"dur": dur, "tot_pkts": pk, "tot_bytes": 300,
                                   "src_bytes": 0, "proto": "tcp", "state": "UNK"}))
    for pk in [7, 8, 9, 12, 20]:
        for dur in [0.5, 20.0, 60.0, 300.0]:
            cases.append(("disc", {"dur": dur, "tot_pkts": pk, "tot_bytes": 200,
                                   "src_bytes": 100, "proto": "udp", "state": "CON"}))
    # (c) FRESH unseen sweep (different seed) -- honest generalization number.
    # Deliberately includes server-heavy payloads so the by_dst/any-any rule
    # semantics are exercised.
    rng2 = random.Random(97531)
    for _ in range(80):
        cases.append(("fresh", {
            "dur": round(rng2.uniform(0.0, 150.0), 3),
            "tot_pkts": rng2.choice([2, 3, 4, 6, 7, 9, 11, 13, 17, 25, 50, 90]),
            "tot_bytes": rng2.choice([120, 400, 1200, 3000, 8000, 40000]),
            "src_bytes": rng2.choice([0, 40, 150, 700, 2500, 12000]),
            "proto": rng2.choice(["tcp", "udp", "udp"]),
            "state": rng2.choice(states),
        }))
    return cases


def main():
    rows = []
    for i, (tagset, feat) in enumerate(build_cases()):
        try:
            r = real_verdict(feat, f"p{i:04d}")
        except Exception as exc:  # pcap synthesis limit (payload > 65535)
            print(f"  {i:4d} SKIP {type(exc).__name__}: {feat}")
            continue
        rows.append({"i": i, "set": tagset, "feat": feat, "real": r,
                     "replica": replica_snort_verdict(feat)})
        if i % 20 == 0:
            print(f"  ... {i}/{len(build_cases())}")
    DEST.parent.mkdir(parents=True, exist_ok=True)
    json.dump(rows, open(DEST, "w"), indent=1)
    agree = sum(1 for r in rows if r["real"] == r["replica"])
    print(f"\n[+] wrote {DEST} ({len(rows)} flows)")
    print(f"[+] replica agreement on probe set: {agree}/{len(rows)} "
          f"= {agree / len(rows):.4f}")
    print(f"[+] real detection rate: "
          f"{sum(r['real'] for r in rows) / len(rows):.4f}")


if __name__ == "__main__":
    main()
