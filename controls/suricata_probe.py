#!/usr/bin/env python3
"""P16b Hướng 1: per-flow Suricata probe (cost measurement + gate G1a).

Dùng thay cho `controls/cross_engine_check.py` (P4) vì bản đó:
  1. đếm alert bằng `stdout.count("[**]")` -- chưa bao giờ được kiểm chứng;
  2. nuốt exception thành `n = -1` rồi coi như "không evade" -- nên
     cross_engine_v2.json có 5/5 cell = -1 và không có verdict Suricata nào.

Bản này fail-closed (engine crash -> raise, không bao giờ ghi -1), đếm alert từ
fast.log và đối chiếu eve.json, và ghi lại SID để attribution.

Ghi chú chi phí: đo TUẦN TỰ một tiến trình Suricata mỗi flow, không song song --
đây là con số dùng để kiểm gate G1c, nên nó phải phản ánh chi phí thật của một
sweep, không phải chi phí của một hàng đợi.

Run:
    PYTHONPATH=ai_agent:snort_validation .venv/bin/python controls/suricata_probe.py \
        --flows 5 --mechs noop
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "ai_agent"), str(ROOT / "snort_validation")]

from c2_semantics import client_ip_of                     # noqa: E402
from eval_pipeline import mutate_client_only, translate_source  # noqa: E402
from hidden_defender_env import HiddenDefenderEnv          # noqa: E402
from scapy.all import wrpcap                               # noqa: E402
from suricata_runner import alert_profile                  # noqa: E402

YAML = ROOT / "snort_validation/suricata.yaml"
RULES = ROOT / "snort_validation/et_open_c2/suricata.rules"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--flows", type=int, default=5)
    ap.add_argument("--mechs", default="noop",
                    help="comma list; 'noop' = unmutated (control)")
    ap.add_argument("--split", default="test")
    ap.add_argument("--out", default="")
    ap.add_argument("--workdir", default="")
    a = ap.parse_args()

    out_path = Path(a.out) if a.out else (
        ROOT / "snort_validation/reports/suricata_probe_p16.json")
    work = Path(a.workdir) if a.workdir else Path(
        "/tmp/suricata_probe_p16")
    work.mkdir(parents=True, exist_ok=True)
    mechs = [m for m in a.mechs.split(",") if m]

    env = HiddenDefenderEnv(split=a.split, seed=42, real_snort=False)
    env.reset(seed=42)
    flows = env._flows[: a.flows]
    print(f"[*] {len(flows)} flows x {len(mechs)} mech(s), engine=suricata")

    cells, t_all = [], time.time()
    for fi, f in enumerate(flows):
        cip = client_ip_of(f["flow_id"])
        for mech in mechs:
            pkts = (list(f["packets"]) if mech == "noop"
                    else mutate_client_only(f["packets"], mech, cip))
            pkts = translate_source(pkts, cip, attempt_id=fi % 250)
            pcap = work / f"{fi:03d}_{mech}.pcap"
            wrpcap(str(pcap), pkts)
            t0 = time.time()
            # fail-closed: no try/except here on purpose.
            n, sids = alert_profile(pcap, RULES, YAML, work / f"log_{fi:03d}_{mech}")
            dt = time.time() - t0
            cells.append({"flow_id": f["flow_id"],
                          "framing": f.get("framing", "?"),
                          "mech": mech, "alerts": n, "sids": sids,
                          "evaded": n == 0, "seconds": round(dt, 2),
                          "pkts": len(pkts)})
            print(f"  {fi:03d} {mech:22s} alerts={n:3d} sids={sids} "
                  f"{dt:5.1f}s", flush=True)
            pcap.unlink(missing_ok=True)
    wall = time.time() - t_all

    n = len(cells)
    by_mech = {}
    for c in cells:
        m = c["mech"]
        d = by_mech.setdefault(m, {"n": 0, "alerted": 0, "evaded": 0,
                                   "seconds": 0.0, "sids": set()})
        d["n"] += 1
        d["alerted"] += int(not c["evaded"])
        d["evaded"] += int(c["evaded"])
        d["seconds"] += c["seconds"]
        d["sids"].update(c["sids"])
    for m, d in by_mech.items():
        d["mean_s_per_flow"] = round(d["seconds"] / d["n"], 2)
        d["sids"] = sorted(d["sids"])

    out = {"engine": "suricata 7.0.3", "split": a.split, "flows": len(flows),
           "mechs": mechs, "wall_seconds": round(wall, 1),
           "mean_s_per_cell": round(wall / n, 2) if n else None,
           "by_mech": by_mech, "cells": cells,
           "rules": str(RULES.relative_to(ROOT)),
           "rejected_rules": 86,
           "note": ("ownership=client for non-noop mechs; translate_source keeps "
                    "the 5-tuple unique. Fail-closed: engine errors raise.")}
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, indent=1))
    print(f"\nwall={wall:.1f}s cells={n} mean_s_per_cell={out['mean_s_per_cell']}")
    for m, d in by_mech.items():
        print(f"  {m:22s} alerted {d['alerted']}/{d['n']} "
              f"evaded {d['evaded']}/{d['n']} mean={d['mean_s_per_flow']}s")
    print(f"[+] {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())