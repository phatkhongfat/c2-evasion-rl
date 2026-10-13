#!/usr/bin/env python3
"""Build corpus v3: flows on which the EXPERT ruleset fires a SID outside the
naive 4-SID set (so naive and expert can actually differ).

Flow discovery comes from Snort `-A fast` alert files (one dir per capture),
packets are re-extracted bidirectionally from the pcap, and every kept flow is
re-verified with real Snort under the expert conf. Output is a NEW pickle;
the v2 corpus is never touched.
"""
from __future__ import annotations

import argparse
import pickle
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "snort_validation"), str(ROOT / "ai_agent")]

NAIVE = {2008581, 2008583, 2008585, 2012627}
ALERT_RE = re.compile(r"\[1:(\d+):\d+\].*\{(TCP|UDP)\} (\d+\.\d+\.\d+\.\d+):(\d+) -> (\d+\.\d+\.\d+\.\d+):(\d+)")

# (dataset, capture name, pcap path relative to ROOT, alert dir name)
#
# P13: extended from 4 to all 15 locally-available MCFP captures. The list is
# frozen here BEFORE any headroom measurement so that the candidate traffic
# cannot be cherry-picked after seeing which capture yields multi-SID flows.
# Captures whose harvest produced zero in-threat-model alerts are kept anyway
# (donbot, sogou, qvod, capture-win19, and the four 2013/2014 win* captures):
# a zero row is a result that has to be reported, not a candidate to drop.
_MCFP = "data/stratosphere/mcfp"
SOURCES = [
    ("stratosphere", "botnet-capture-20110815-fast-flux",
     f"{_MCFP}/CTU-Malware-Capture-Botnet-46/botnet-capture-20110815-fast-flux.pcap"),
    ("stratosphere", "botnet-capture-20110812-rbot",
     f"{_MCFP}/CTU-Malware-Capture-Botnet-44/botnet-capture-20110812-rbot.pcap"),
    ("stratosphere", "botnet-capture-20110810-neris",
     f"{_MCFP}/CTU-Malware-Capture-Botnet-42/botnet-capture-20110810-neris.pcap"),
    ("stratosphere", "botnet-capture-20110811-neris",
     f"{_MCFP}/CTU-Malware-Capture-Botnet-43/botnet-capture-20110811-neris.pcap"),
    ("stratosphere", "botnet-capture-20110816-donbot",
     f"{_MCFP}/CTU-Malware-Capture-Botnet-47/botnet-capture-20110816-donbot.pcap"),
    ("stratosphere", "botnet-capture-20110816-sogou",
     f"{_MCFP}/CTU-Malware-Capture-Botnet-48/botnet-capture-20110816-sogou.pcap"),
    ("stratosphere", "botnet-capture-20110816-qvod",
     f"{_MCFP}/CTU-Malware-Capture-Botnet-49/botnet-capture-20110816-qvod.pcap"),
    ("cybersure-win", "capture-win13",
     f"{_MCFP}/CTU-Malware-Capture-Botnet-55/capture-win13.pcap"),
    ("cybersure-win", "capture-win19",
     f"{_MCFP}/CTU-Malware-Capture-Botnet-11/capture-win19.pcap"),
    ("cybersure-win", "2013-08-20_captureWin5",
     f"{_MCFP}/CTU-Malware-Capture-Botnet-9/2013-08-20_captureWin5.pcap"),
    ("cybersure-win", "2013-10-18_capture-win15",
     f"{_MCFP}/CTU-Malware-Capture-Botnet-14/2013-10-18_capture-win15.pcap"),
    ("cybersure-win", "2013-11-06_capture-win8",
     f"{_MCFP}/CTU-Malware-Capture-Botnet-22/2013-11-06_capture-win8.pcap"),
    ("cybersure-win", "2014-03-12_capture-win15",
     f"{_MCFP}/CTU-Malware-Capture-Botnet-59/2014-03-12_capture-win15.pcap"),
    ("cybersure-win", "2014-04-07_capture-win6",
     f"{_MCFP}/CTU-Malware-Capture-Botnet-64/2014-04-07_capture-win6.pcap"),
    ("cybersure-win", "2014-04-07_capture-win11",
     f"{_MCFP}/CTU-Malware-Capture-Botnet-65/2014-04-07_capture-win11.pcap"),
]


def norm(proto, a, ap, b, bp):
    return (proto, *sorted([(a, int(ap)), (b, int(bp))]))


def parse_alerts(alert_file: Path) -> dict:
    """normalized 5-tuple -> set of SIDs that are NOT in the naive set."""
    out: dict = {}
    for line in alert_file.read_text(errors="ignore").splitlines():
        m = ALERT_RE.search(line)
        if not m:
            continue
        sid = int(m.group(1))
        if sid in NAIVE:
            continue
        proto, a, ap, b, bp = m.group(2).lower(), m.group(3), m.group(4), m.group(5), m.group(6)
        out.setdefault(norm(proto, a, ap, b, bp), set()).add(sid)
    return out


def extract(pcap: Path, wanted: dict, max_pkts: int):
    from scapy.all import IP, PcapReader, TCP, UDP
    found: dict = {}
    first: dict = {}
    with PcapReader(str(pcap)) as rd:
        for pkt in rd:
            if IP not in pkt:
                continue
            if TCP in pkt:
                proto, L = "tcp", TCP
            elif UDP in pkt:
                proto, L = "udp", UDP
            else:
                continue
            k = norm(proto, pkt[IP].src, pkt[L].sport, pkt[IP].dst, pkt[L].dport)
            if k not in wanted:
                continue
            if k not in first:
                first[k] = (pkt[IP].src, int(pkt[L].sport), pkt[IP].dst, int(pkt[L].dport), proto)
            lst = found.setdefault(k, [])
            if len(lst) < max_pkts:
                lst.append(pkt)
    return found, first


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--alerts", default="/tmp/cov")
    ap.add_argument("--out", default=str(ROOT / "snort_validation/reports/hidden_defender_corpus_v3.pkl"))
    ap.add_argument("--max-pkts", type=int, default=60)
    ap.add_argument("--per-capture", type=int, default=400)
    ap.add_argument("--n-test", type=int, default=40)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--verify", action="store_true", help="re-score each flow with real Snort (expert conf)")
    a = ap.parse_args()

    import numpy as np
    from c2_semantics import client_ip_of
    from endpoint_model import detect_framing
    from scapy.all import Raw, UDP

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

    flows = []
    for dataset, capture, rel in SOURCES:
        alert = Path(a.alerts) / capture / "alert"
        wanted = parse_alerts(alert)
        found, first = extract(ROOT / rel, wanted, a.max_pkts)
        rng = np.random.default_rng(a.seed)
        keys = sorted(found)
        rng.shuffle(keys)
        kept = 0
        for k in keys:
            pkts = found[k]
            if len(pkts) < 4:
                continue
            s, sp, d, dp, proto = first[k]
            payload = b"".join(bytes(p[Raw].load) for p in pkts if Raw in p)
            flows.append({"flow_id": f"{capture}|{s}:{sp}->{d}:{dp}|{proto}", "capture": capture,
                          "dataset": dataset, "key": (s, sp, d, dp, proto), "packets": pkts,
                          "obs": feats(pkts), "framing": detect_framing(payload),
                          "extra_sids": sorted(wanted[k]), "replica": None})
            kept += 1
            if kept >= a.per_capture:
                break
        print(f"[*] {capture}: alert-flows={len(wanted)} kept={kept}", flush=True)

    if a.verify:
        from eval_pipeline import score_flow_real
        good = []
        conf = ROOT / "snort_validation/et_open_c2/snort_et_c2.conf"
        for i, f in enumerate(flows):
            r = score_flow_real(f["packets"], client_ip_of(f["flow_id"]), attempt_id=i % 250,
                                mech=None, conf=conf, ownership="both")
            sids = {x for x in (r.get("sids") or []) if isinstance(x, int)}
            if sids - NAIVE:
                f["baseline_sids"] = sorted(sids)
                good.append(f)
        print(f"[*] verify: {len(good)}/{len(flows)} flows keep an extra SID under real Snort")
        flows = good

    by_cap: dict = {}
    for f in flows:
        by_cap.setdefault(f["capture"], []).append(f)
    rng = np.random.default_rng(a.seed)
    test, train = [], []
    caps = sorted(by_cap)
    per = max(1, a.n_test // len(caps))
    for c in caps:
        g = by_cap[c]
        idx = rng.permutation(len(g))
        n = min(per, len(g))
        for j, i in enumerate(idx):
            (test if j < n else train).append(g[i])
    while len(test) < a.n_test and train:
        test.append(train.pop())
    test = test[: a.n_test]
    pickle.dump({"train": train, "test": test}, open(a.out, "wb"))
    print(f"[+] train={len(train)} test={len(test)} -> {a.out}")
    print("[+] test per capture:", {c: sum(1 for f in test if f["capture"] == c) for c in caps})
    print("[+] test framing:", {fr: sum(1 for f in test if f["framing"] == fr) for fr in sorted({f["framing"] for f in test})})
    return 0


if __name__ == "__main__":
    sys.exit(main())
