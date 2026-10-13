#!/usr/bin/env python3
"""Gate S1 over harvested alert files, stratified by Snort rule priority.

The first S1 measurement on the ET Open 3.0.0 harvest looked like a clean pass
(380 of 24161 5-tuples carry 2+ in-threat-model SIDs). That number is
inflated: the most frequent SID is 2003068 "ET SCAN Potential SSH Scan
OUTBOUND" with 21039 alerts, and scan rules co-fire on the same 5-tuple as the
real C2 traffic. Counting them as separate SIDs inflates the gate.

Priority is rule metadata that has nothing to do with whether a flow was
evaded, so stratifying on it is not tuning the bar to the result: priority 1
is ET's own "high likelihood of a security problem" tier and holds exactly the
malware rules (FakeAV C2 check-in, IRC bot commands).

Usage:
    python controls/sid_s1_from_alerts.py --alerts DIR [--priority 1]
"""

import argparse
import collections
import pathlib
import re

P2P_SIDS = {2008581, 2008583, 2008585}

# [1:SID:rev] ... [Priority: N] ... {TCP} src -> dst:dport
LINE = re.compile(
    r"\[1:(\d+):\d+\].*?\[Priority: (\d)\].*?"
    r"\{(\w+)\}\s+(\d+\.\d+\.\d+\.\d+):\d+\s*->\s*(\d+\.\d+\.\d+\.\d+):(\d+)"
)
MSG = re.compile(r"\[1:\d+:\d+\]\s+(.*?)\s+\[\*\*\]")


def load(alert_dir: pathlib.Path, priority: int):
    per_flow: dict = {}
    messages: dict = {}
    for cap in sorted(alert_dir.iterdir()):
        alert = cap / "alert"
        if not cap.is_dir() or not alert.exists():
            continue
        for ln in alert.read_text(errors="ignore").splitlines():
            m = LINE.search(ln)
            if not m:
                continue
            sid, pri = int(m.group(1)), int(m.group(2))
            mm = MSG.search(ln)
            if mm:
                messages.setdefault(sid, mm.group(1))
            if sid in P2P_SIDS or pri > priority:
                continue
            key = (cap.name, m.group(4), m.group(5), m.group(6))
            per_flow.setdefault(key, set()).add(sid)
    per_flow = {k: v for k, v in per_flow.items() if v}
    return per_flow, messages


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--alerts", required=True, type=pathlib.Path)
    ap.add_argument("--priority", type=int, default=1)
    args = ap.parse_args()

    per_flow, messages = load(args.alerts, args.priority)
    multi = {k: v for k, v in per_flow.items() if len(v) >= 2}
    pairs = collections.Counter(
        tuple(sorted(v)) for k, v in per_flow.items() if len(v) >= 2
    )

    print(f"threat model: priority <= {args.priority}, P2P SIDs excluded")
    print(f"5-tuples alerting : {len(per_flow)}")
    print(f"5-tuples >= 2 SID : {len(multi)}")
    print(f"max SIDs / tuple  : {max((len(v) for v in per_flow.values()), default=0)}")
    print(f"distinct SIDs     : {len({s for v in per_flow.values() for s in v})}")
    print("\nSID-set distribution:")
    for n, c in sorted(collections.Counter(len(v) for v in per_flow.values()).items()):
        print(f"  {n} SID : {c}")
    print("\nmost common multi-SID sets:")
    for combo, c in pairs.most_common(10):
        label = ", ".join(f"{s} ({messages.get(s, '?')})" for s in combo)
        print(f"  x{c}  {label}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())