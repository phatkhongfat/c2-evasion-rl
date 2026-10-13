#!/usr/bin/env python3
"""Score the extended-corpus HTTP flows with noop / http_header_case / split8.

Purpose: check whether the cost-axis Pareto win found on the old corpus
(controls/pareto_cost_oracle.py) survives on the extended corpus (8 captures,
52,454-rule conf).  Only the flows whose client payload opens with a real
HTTP request are candidates for http_header_case; everything else cannot
benefit, so we score just those (5 flows x 3 mechs = 15 Snort runs).

Writes a report in the ownership_ceiling_sweep cell format so
pareto_cost_oracle.py can consume it directly.
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

from hidden_defender_env import HiddenDefenderEnv  # noqa: E402
from eval_pipeline import client_ip_of, score_flow_real  # noqa: E402
from endpoint_model import is_http_request  # noqa: E402
from scapy.all import IP, Raw  # noqa: E402

MECHS = ["noop", "http_header_case", "split8"]


def has_http_request(flow, cip: str) -> bool:
    for p in flow["packets"]:
        if IP in p and Raw in p and p[IP].src == cip:
            if is_http_request(bytes(p[Raw].load)):
                return True
    return False


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default=str(
        ROOT / "snort_validation/reports/corpus_p13_extended.pkl"))
    ap.add_argument("--conf", default=str(
        ROOT / "rulesets/p13/snort_et3000.conf"))
    ap.add_argument("--ownership", default="both")
    ap.add_argument("--out", default=str(
        ROOT / "snort_validation/reports/p13_v8_case_extended.json"))
    args = ap.parse_args()

    env = HiddenDefenderEnv(split="test", seed=42, real_snort=False,
                            corpus=args.corpus)
    flows = [f for f in env._flows
             if has_http_request(f, client_ip_of(f["flow_id"]))]
    print(f"candidate HTTP flows: {len(flows)}", flush=True)

    rows, t0 = [], time.time()
    for fi, f in enumerate(flows):
        fid = f["flow_id"]
        cip = client_ip_of(fid)
        base = score_flow_real(f["packets"], cip, attempt_id=fi, mech=None,
                               ownership=args.ownership, conf=Path(args.conf))
        for mi, mech in enumerate(MECHS):
            r = score_flow_real(f["packets"], cip,
                                attempt_id=(fi * len(MECHS) + mi) % 250,
                                mech=mech, ownership=args.ownership,
                                conf=Path(args.conf))
            rows.append({"flow_id": fid, "framing": f.get("framing", "?"),
                         "mech": mech, "baseline_alert": base["alert"],
                         "evaded": r["evaded"], "semantics_ok": r["semantics_ok"],
                         "valid_evasion": r["valid_evasion"],
                         "valid_evasion_endpoint": r.get("valid_evasion_endpoint"),
                         "sids": r.get("sids", []),
                         "baseline_sids": base.get("sids", [])})
            print(f"[{fi+1}/{len(flows)}] {fid} mech={mech} "
                  f"valid={r['valid_evasion']} valid_ep={r.get('valid_evasion_endpoint')} "
                  f"@ {time.time()-t0:.0f}s", flush=True)

    out = {"ownership": args.ownership, "split": "test", "scorer": "real_snort",
           "conf": args.conf, "bar": "two_stream_byte_equality",
           "cells": rows, "n_flows": len(flows),
           "wall_s": round(time.time() - t0, 1)}
    Path(args.out).write_text(json.dumps(out, indent=1))
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
