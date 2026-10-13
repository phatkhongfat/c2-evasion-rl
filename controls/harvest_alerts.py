#!/usr/bin/env python3
"""Harvest Snort -A fast alerts for every frozen P13 candidate capture.

Runs the given conf over each capture in build_corpus_v3.SOURCES and writes
one alert file per capture under --out. Re-running is what the P13 plan calls
the "reproduce byte-identical from pcap" requirement: /tmp/cov was never
guaranteed to survive a reboot, so anything measured from it is now derived
from the pcaps themselves.

All 15 captures are processed, including those that produced zero alerts under
the older C2-only ruleset -- a zero row is a reportable result, and skipping
them would bias the candidate set toward whatever already looks multi-SID.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "controls"))

from build_corpus_v3 import SOURCES

P2P = {2008581, 2008583, 2008585}
SID_RE = re.compile(r"\[1:(\d+):\d+\]")


def harvest(capture: str, pcap: Path, conf: Path, outdir: Path) -> dict:
    # Snort 2.9.20 has no --alert-output flag (it prints the usage text and
    # exits 1). `output alert_fast: alert` in the conf is relative to the LOG
    # DIRECTORY, not the cwd -- without -l, alerts are counted but never
    # written to disk and the capture dir stays empty.
    cdir = outdir / capture
    cdir.mkdir(parents=True, exist_ok=True)
    alert = cdir / "alert"
    if alert.exists():
        alert.unlink()
    cmd = ["snort", "-r", str(pcap.resolve()), "-c", str(conf.resolve()),
           "-A", "fast", "-l", str(cdir.resolve())]
    t0 = time.time()
    proc = subprocess.run(cmd, capture_output=True, text=True,
                          cwd=str(cdir), timeout=7200)
    dt = time.time() - t0

    sids = Counter()
    if alert.exists():
        for line in alert.read_text(errors="ignore").splitlines():
            m = SID_RE.search(line)
            if m:
                sids[int(m.group(1))] += 1

    in_model = sorted(s for s in sids if s not in P2P)
    tail = proc.stderr.strip().splitlines()[-1] if proc.stderr.strip() else ""
    return {
        "capture": capture,
        "rc": proc.returncode,
        "seconds": round(dt, 1),
        "alerts": sum(sids.values()),
        "n_sids": len(sids),
        "in_model_sids": in_model,
        "alert_bytes": alert.stat().st_size if alert.exists() else 0,
        "stderr_tail": tail,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--conf", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--only", nargs="*", help="restrict to these captures")
    a = ap.parse_args()

    conf, outdir = Path(a.conf), Path(a.out)
    rows = []
    for _ds, capture, rel in SOURCES:
        if a.only and capture not in a.only:
            continue
        pcap = ROOT / rel
        if not pcap.exists():
            print(f"[skip] {capture}: missing {rel}", flush=True)
            continue
        row = harvest(capture, pcap, conf, outdir)
        rows.append(row)
        print(f"[{row['seconds']:>7.1f}s] {capture:<34} "
              f"alerts={row['alerts']:<7} sids={row['n_sids']:<4} "
              f"in_model={row['in_model_sids']}", flush=True)

    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "harvest_summary.json").write_text(
        json.dumps({"conf": str(conf), "captures": rows}, indent=2))
    print(f"\nwrote {outdir/'harvest_summary.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())