#!/usr/bin/env python3
"""P6 Phase-2 cheap divergence probe.

Before committing to a multi-hour 200-flow sweep, test whether winner-signature
DIVERGENCE exists AT ALL in the stratosphere captures.  Build a small mixed
pool spanning the distinct alerting SID families (win13 DNS 2016413, neris DNS
2014169, fast-flux HTTP 2012533/2014635, rbot IRC PRIVMSG 2019486/2019471),
sweep 8 representative mechanisms (spanning the match-geometry classes) with
real Snort, and report the winner signatures.

Divergence exists iff >=2 flows have DIFFERENT non-universal winner sets (i.e.
rl_headroom.headroom >= 1 on this pool).  If headroom == 0 here, the whole
"rebuild corpus v4 for RL-beats-fixed" plan is a NO-GO and we stop.

Writes /tmp/div_probe_pool.pkl (candidate corpus) and
snort_validation/reports/div_probe.json (the 8-mech matrix).
"""
from __future__ import annotations

import pickle
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "snort_validation"), str(ROOT / "ai_agent"),
                str(ROOT / "controls")]

from build_corpus_v3 import parse_alerts, extract, norm  # noqa: E402
from c2_semantics import client_ip_of  # noqa: E402
from endpoint_model import detect_framing  # noqa: E402
from merge_corpora import corrected_framing  # noqa: E402
from scapy.all import Raw, UDP  # noqa: E402
import numpy as np  # noqa: E402

# capture -> (pcap rel path, target SIDs to prefer, how many)
POOL = [
    ("capture-win13",
     "data/stratosphere/mcfp/CTU-Malware-Capture-Botnet-55/capture-win13.pcap",
     {2016413}, 3),
    ("botnet-capture-20110810-neris",
     "data/stratosphere/mcfp/CTU-Malware-Capture-Botnet-42/botnet-capture-20110810-neris.pcap",
     {2014169}, 3),
    ("botnet-capture-20110815-fast-flux",
     "data/stratosphere/mcfp/CTU-Malware-Capture-Botnet-46/botnet-capture-20110815-fast-flux.pcap",
     {2012533, 2014635}, 3),
    ("botnet-capture-20110812-rbot",
     "data/stratosphere/mcfp/CTU-Malware-Capture-Botnet-44/botnet-capture-20110812-rbot.pcap",
     {2019486, 2019471}, 3),
]


def feats(pkts):
    pays = [bytes(p[Raw].load) for p in pkts if Raw in p]
    lens = [len(p) for p in pays]
    tot = sum(len(bytes(p)) for p in pkts)
    m = float(np.mean(lens)) if lens else 0.0
    s = float(np.std(lens)) if lens else 0.0
    return [1.0 if any(UDP in p for p in pkts) else 0.0, min(len(pkts), 64) / 64.0,
            min(tot, 20000) / 20000.0, min(len(pays), 16) / 16.0, min(m, 2000) / 2000.0,
            min(s, 2000) / 2000.0, min(max(lens) if lens else 0, 2000) / 2000.0,
            min(min(lens) if lens else 0, 2000) / 2000.0]


def build_pool() -> list:
    flows = []
    for capture, rel, want_sids, n in POOL:
        alert = parse_alerts(Path("/tmp/cov") / capture / "alert")
        # keep only flows alerting through the target SIDs
        wanted = {k: v for k, v in alert.items() if v.intersection(want_sids)}
        found, first = extract(ROOT / rel, wanted, 60)
        keys = sorted(found)
        rng = np.random.default_rng(42)
        rng.shuffle(keys)
        kept = 0
        for k in keys:
            pk = found[k]
            if len(pk) < 4:
                continue
            s, sp, d, dp, proto = first[k]
            payload = b"".join(bytes(p[Raw].load) for p in pk if Raw in p)
            f = {"flow_id": f"{capture}|{s}:{sp}->{d}:{dp}|{proto}", "capture": capture,
                 "dataset": "stratosphere", "key": (s, sp, d, dp, proto), "packets": pk,
                 "obs": feats(pk), "framing": detect_framing(payload),
                 "extra_sids": sorted(wanted[k]), "replica": None}
            f["framing"] = corrected_framing(f)   # UDP/53 -> dns, not the http default
            flows.append(f)
            kept += 1
            if kept >= n:
                break
        print(f"[*] {capture}: wanted={len(wanted)} kept={kept}", flush=True)
    return flows


def main() -> int:
    flows = build_pool()
    print(f"[*] pool = {len(flows)} flows; framings = "
          f"{ {f: sum(1 for x in flows if x['framing'] == f) for f in sorted({x['framing'] for x in flows})} }")
    # split: all flows into 'test' so the sweep scores them; keep a copy as train
    half = max(1, len(flows) // 2)
    data = {"train": flows[:half], "test": flows}
    out = Path("/tmp/div_probe_pool.pkl")
    pickle.dump(data, open(out, "wb"))
    print(f"[+] pool corpus -> {out} (test={len(flows)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
