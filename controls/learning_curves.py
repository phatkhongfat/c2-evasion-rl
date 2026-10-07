#!/usr/bin/env python3
"""Parse PPO training logs -> CSV + bảng mean±std theo epoch (plan P3).

Line format (xác minh từ /tmp/trainb_s42.log):
  [*] epoch  12: 128 queries, 41/64 flows valid this epoch (64.1%)
"""
import argparse
import csv
import re
import sys
from pathlib import Path

EPOCH_RE = re.compile(
    r"\[\*\] epoch\s+(\d+):\s+(\d+) queries,\s+(\d+)/(\d+) flows valid this epoch \(([\d.]+)%\)")


def parse_train_log(text):
    """-> [{"epoch": int, "queries": int, "valid": int, "n": int, "pct": float}]"""
    return [
        {"epoch": int(m.group(1)), "queries": int(m.group(2)),
         "valid": int(m.group(3)), "n": int(m.group(4)), "pct": float(m.group(5))}
        for m in EPOCH_RE.finditer(text)
    ]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", default="7,1337,42")
    ap.add_argument("--v2", action="store_true", default=True,
                    help="read /tmp/trainb2_s*.log (fall back to trainb_s*)")
    ap.add_argument("--out", default="snort_validation/reports/learning_curves_v2.csv")
    args = ap.parse_args()

    rows = []
    for seed in args.seeds.split(","):
        for prefix in ("trainb2", "trainb"):
            p = Path(f"/tmp/{prefix}_s{seed}.log")
            if p.exists():
                break
        else:
            print(f"[skip] no log for seed {seed}", file=sys.stderr)
            continue
        for r in parse_train_log(p.read_text(errors="ignore")):
            rows.append({"seed": seed, **r})

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["seed", "epoch", "queries", "valid", "n", "pct"])
        w.writeheader()
        w.writerows(rows)

    # mean±std pct cross-seed theo epoch
    by_ep = {}
    for r in rows:
        by_ep.setdefault(r["epoch"], []).append(r["pct"])
    print("| epoch | mean pct | std | seeds |")
    print("|---|---|---|---|")
    for ep in sorted(by_ep):
        v = by_ep[ep]
        mean = sum(v) / len(v)
        std = (sum((x - mean) ** 2 for x in v) / max(len(v) - 1, 1)) ** 0.5
        print(f"| {ep} | {mean:.1f} | {std:.1f} | {len(v)} |")
    print(f"\nCSV -> {out} ({len(rows)} rows)")


if __name__ == "__main__":
    main()
