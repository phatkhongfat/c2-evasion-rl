#!/usr/bin/env python3
"""P4: Suricata cross-engine spot-check for split mechs."""
import argparse
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ai_agent"))
sys.path.insert(0, str(ROOT / "snort_validation"))

from eval_pipeline import client_ip_of, mutate_client_only, translate_source  # noqa: E402
from hidden_defender_env import HiddenDefenderEnv  # noqa: E402
from scapy.all import wrpcap  # noqa: E402


def suricata_alerts(pcap: Path, rules: str, workdir: str) -> int:
    import subprocess
    p = subprocess.run([
        "suricata", "-r", str(pcap), "-S", rules, "-l", workdir,
        "-c", str(ROOT / "snort_validation" / "suricata.yaml"),
    ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=120)
    n = p.stdout.count("[**]")
    return n


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mechs", default="split8,split16,split24,overlap8")
    ap.add_argument("--rules", default=str(
        ROOT / "snort_validation" / "et_open_c2" / "suricata.rules"))
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--out", default=str(
        ROOT / "snort_validation" / "reports" / "cross_engine_v2.json"))
    args = ap.parse_args()

    env = HiddenDefenderEnv(split="test", seed=42, real_snort=False)
    mechs = [m for m in args.mechs.split(",") if m]
    cells = []
    with tempfile.TemporaryDirectory(prefix="xsurf_") as td:
        flows = env._flows[: args.limit] if args.limit else env._flows
        for fi, f in enumerate(flows):
            cip = client_ip_of(f["flow_id"])
            for mech in [None] + mechs:
                pkts = (list(f["packets"]) if mech is None
                        else mutate_client_only(f["packets"], mech, cip))
                pkts = translate_source(pkts, cip, attempt_id=fi % 250)
                name = f"{fi:02d}_{'base' if mech is None else mech}.pcap"
                pcap = Path(td) / name
                wrpcap(str(pcap), pkts)
                try:
                    n = suricata_alerts(pcap, args.rules, td)
                except Exception as e:
                    n = -1
                    print(f"[warn] suricata failed {name}: {e}", file=sys.stderr)
                cells.append({"flow_id": f["flow_id"], "mech": mech or "none",
                              "suricata_alerts": n, "evaded": n == 0 if n >= 0 else False})
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"engine": "suricata", "rules": args.rules,
                               "cells": cells}, indent=1))
    n_base = sum(1 for c in cells if c["mech"] == "none" and c["evaded"])
    print(f"cells={len(cells)} baseline-evaded-by-suricata={n_base} -> {out}")
    print("NOTE: baseline nên evaded=0 (nếu baseline đã 0 alert thì ruleset sai)")


if __name__ == "__main__":
    main()
