#!/usr/bin/env python3
"""Ceiling sweep under the TWO-SIDED ownership model (ownership="both").

Scores every (action, test-flow) pair with real Snort where a mechanism may
rewrite BOTH endpoints' packets, under the two-stream byte-equality bar.
Writes per-cell rows + the per-framing best to a report JSON and prints the
ceiling.  Baseline (mech=None) is scored once per flow as a control.

Usage: .venv/bin/python controls/ownership_ceiling_sweep.py --split test
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ai_agent"))
sys.path.insert(0, str(ROOT / "snort_validation"))

from hidden_defender_env import ACTION_NAMES, HiddenDefenderEnv  # noqa: E402
from eval_pipeline import client_ip_of, score_flow_real  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", default="test")
    ap.add_argument("--out", default=str(
        ROOT / "snort_validation" / "reports" / "ceiling_ownership_both.json"))
    ap.add_argument("--conf", default=None,
                    help="snort conf path (default: ET Open full tier)")
    ap.add_argument("--corpus", default=None,
                    help="corpus pickle override (default: the checked-in corpus)")
    ap.add_argument("--mechs", default="",
                    help="comma-separated mechanisms to sweep instead of the "
                         "full ACTION_NAMES list (e.g. split_slow,noop). Lets "
                         "a mechanism be measured without changing the PPO "
                         "action space.")
    return ap


def resolve_mechs(mechs: str):
    """--mechs override, or the full ACTION_NAMES list when not given."""
    if not mechs:
        return list(ACTION_NAMES)
    return [m.strip() for m in mechs.split(",") if m.strip()]


def main() -> int:
    args = build_parser().parse_args()
    conf_kw = {"conf": Path(args.conf)} if args.conf else {}

    env = HiddenDefenderEnv(split=args.split, seed=42, real_snort=False,
                            corpus=args.corpus)
    flows = env._flows
    mechs = resolve_mechs(args.mechs)
    rows, t0 = [], time.time()
    for fi, f in enumerate(flows):
        fid = f["flow_id"]
        cip = client_ip_of(fid)
        base = score_flow_real(f["packets"], cip, attempt_id=fi, mech=None,
                               ownership="both", **conf_kw)
        # attempt_id must stay inside the Fix-5 /24 translation range
        # (MAX_ATTEMPTS=250); ids only need to be unique within one Snort
        # call's pcap, and every cell is its own subprocess, so modulo is safe.
        n_mech = len(mechs)
        for mi, mech in enumerate(mechs):
            r = score_flow_real(f["packets"], cip,
                                attempt_id=(fi * n_mech + mi) % 250,
                                mech=mech, ownership="both", **conf_kw)
            rows.append({"flow_id": fid, "framing": f.get("framing", "?"),
                         "mech": mech, "baseline_alert": base["alert"],
                         "evaded": r["evaded"], "semantics_ok": r["semantics_ok"],
                         "valid_evasion": r["valid_evasion"],
                         "sids": r.get("sids", []),
                         "baseline_sids": base.get("sids", [])})
        print(f"[{fi + 1}/{len(flows)}] {fid} done @ {time.time() - t0:.0f}s",
              flush=True)

    best: dict = {}
    for r in rows:
        k = (r["framing"], r["mech"])
        best[k] = best.get(k, 0) + (1 if r["valid_evasion"] else 0)
    per_framing: dict = {}
    for (fr, mech), n in best.items():
        if fr not in per_framing or n > per_framing[fr][1]:
            per_framing[fr] = (mech, n)
    ceiling = sum(n for _m, n in per_framing.values())
    n_by_framing = {fr: sum(1 for f in flows if f.get("framing") == fr)
                    for fr in per_framing}
    out = {"ownership": "both", "split": args.split, "scorer": "real_snort",
           "conf": args.conf or "default (ET Open full)",
           "bar": "two_stream_byte_equality",
           "cells": rows,
           "best_per_framing": {fr: {"mech": m, "evaded": n,
                                     "flows": n_by_framing.get(fr, 0)}
                                for fr, (m, n) in per_framing.items()},
           "ceiling_valid_evasion": ceiling, "n_flows": len(flows),
           "wall_s": round(time.time() - t0, 1)}
    Path(args.out).write_text(json.dumps(out, indent=1))
    print(json.dumps({k: out[k] for k in
                      ("ceiling_valid_evasion", "n_flows", "best_per_framing")},
                     indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
