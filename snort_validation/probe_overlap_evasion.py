#!/usr/bin/env python3
"""GO/NO-GO probe: does an overlap fragment evade real Snort while keeping the C2?

This is the experiment that decides whether ambiguity-based evasion is real on
this setup.  It is deliberately tiny (one flow, three arms) so it can be run
before any training budget is spent.

Arms, all scored by the real Snort binary:
  A. original            -- the unmutated flow
  B. split               -- two non-overlapping fragments (control: must still alert)
  C. overlap             -- benign decoy first, real bytes overlapping later

For C, semantics_preserved() must be True: the endpoint can still rebuild the
exact original command, while `policy first` (Snort) sees the decoy.

Run:
    .venv/bin/python snort_validation/probe_overlap_evasion.py \
        --capture botnet-capture-20110819-bot --dataset ctu13 --flow 0
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))

from c2_semantics import (  # noqa: E402
    assemble, dht_ping_id, policy_that_recovers, reconstructs_command,
)
from fragment_ops import (  # noqa: E402
    fragment_plan_to_packets, overlap_fragments, split_fragments,
)
from real_packet_env import RealPacketEnv, payload_indices  # noqa: E402
from snort_batch_service import SNORT_CONF  # noqa: E402


def score(packets, tag: str, tmp: Path) -> dict:
    """Write one pcap and read Snort's verdict."""
    from scapy.all import wrpcap
    path = tmp / f"{tag}.pcap"
    logdir = tmp / f"log_{tag}"
    logdir.mkdir(parents=True, exist_ok=True)
    wrpcap(str(path), list(packets))
    subprocess.run(["snort", "-c", str(SNORT_CONF), "-r", str(path),
                    "-A", "fast", "-l", str(logdir), "-q"],
                   capture_output=True, timeout=300)
    alert = logdir / "alert"
    text = alert.read_text(errors="ignore") if alert.exists() else ""
    sids = []
    for m in re.finditer(r"\[1:(\d+):\d+\]\s*([^\[]*)", text):
        sids.append((int(m.group(1)), m.group(2).strip()[:70]))
    return {"alert": bool(text.strip()), "n_alert_lines": len(text.splitlines()),
            "sids": sids}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--capture", default="botnet-capture-20110819-bot")
    ap.add_argument("--dataset", default="ctu13")
    ap.add_argument("--flow", type=int, default=0)
    ap.add_argument("--split-at", type=int, default=8)
    ap.add_argument("--pattern", default="d1:ad2:id20:",
                    help="only fragment packets whose payload contains this; "
                         "'*' fragments every payload-bearing packet")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    env = RealPacketEnv(n_flows=max(args.flow + 1, 1), batch_size=1,
                        capture=args.capture, dataset=args.dataset)
    _key, pkts = env.flows[args.flow]
    pay_idx = payload_indices(pkts)
    if not pay_idx:
        print("[-] flow has no payload; pick another --flow")
        return 1

    from scapy.all import Raw
    pat = args.pattern.encode() if args.pattern != "*" else b""

    # EVERY matching packet must be handled: the rules carry
    # `threshold: type both, count 1, track by_src`, so neutralising one packet
    # leaves the next match to fire the alert.  Measured: flow 0 has 6 packets
    # carrying the DHT ping pattern.
    targets = [i for i in pay_idx
               if args.pattern == "*" or pat in bytes(pkts[i][Raw].load)]
    if not targets:
        print(f"[-] no payload packet matches {args.pattern!r}; try --pattern '*'")
        return 1

    payloads = {i: bytes(pkts[i][Raw].load) for i in targets}
    print(f"[*] capture={args.capture} flow={args.flow} pkts={len(pkts)}")
    print(f"[*] {len(targets)} of {len(pay_idx)} payload packets match "
          f"{args.pattern!r}: indices {targets}")
    for i in targets[:3]:
        print(f"    pkt {i}: {len(payloads[i])} B, head={payloads[i][:12]!r}")

    tmp = Path(tempfile.mkdtemp(prefix="probe_overlap_"))
    results = {}

    # Arm A: original
    results["original"] = score(pkts, "original", tmp)

    def fragment_arm(kind: str):
        out = list(pkts)
        all_frags = {}
        for i in targets:
            frags = (split_fragments(payloads[i], args.split_at) if kind == "split"
                     else overlap_fragments(payloads[i], args.split_at))
            all_frags[i] = frags
            out[i:i + 1] = fragment_plan_to_packets(pkts, frags, i)
        sem = all(reconstructs_command(payloads[i], all_frags[i]) for i in targets)
        return out, all_frags, sem

    # Arm B: clean split (control -- reassembles identically, must still alert)
    split_pkts, _sf, split_sem = fragment_arm("split")
    results["split"] = score(split_pkts, "split", tmp)
    results["split"]["semantics_preserved"] = split_sem

    # Arm C: overlap -- decoy first, real bytes later
    ov_pkts, ov_frags, ov_sem = fragment_arm("overlap")
    results["overlap"] = score(ov_pkts, "overlap", tmp)
    results["overlap"]["semantics_preserved"] = ov_sem
    t0 = targets[0]
    results["overlap"]["policy_that_recovers"] = policy_that_recovers(
        payloads[t0], ov_frags[t0])
    results["overlap"]["snort_first_view[:12]"] = repr(
        assemble(ov_frags[t0], "first")[:12])
    rec = policy_that_recovers(payloads[t0], ov_frags[t0]) or "first"
    results["overlap"]["endpoint_view[:12]"] = repr(
        assemble(ov_frags[t0], rec)[:12])
    results["overlap"]["original[:12]"] = repr(payloads[t0][:12])
    results["targets"] = targets

    print()
    for arm in ("original", "split", "overlap"):
        r = results[arm]
        print(f"[*] {arm:>9}: alert={r['alert']} lines={r['n_alert_lines']} "
              f"semantics={r.get('semantics_preserved', 'n/a')}")
        for sid, msg in r["sids"][:4]:
            print(f"        sid:{sid} {msg}")

    print()
    r = results["overlap"]
    verdict = (not r["alert"]) and r["semantics_preserved"] is True
    print(f"[*] Snort 'first' view : {r['snort_first_view[:12]']}")
    print(f"[*] endpoint view      : {r['endpoint_view[:12]']}")
    print(f"[*] original           : {r['original[:12]']}")
    print(f"\n[*] VERDICT: {'REAL EVASION' if verdict else 'NOT an evasion'}")
    if not verdict and r["alert"]:
        print("    Snort still alerted. Check whether it was an ANOMALY alert "
              "(frag3 detect_anomalies) rather than a rule match.")

    if args.out:
        Path(args.out).write_text(json.dumps(results, indent=2))
        print(f"[+] {args.out}")
    return 0 if verdict else 2


if __name__ == "__main__":
    sys.exit(main())
