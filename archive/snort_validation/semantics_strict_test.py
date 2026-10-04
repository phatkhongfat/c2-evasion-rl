#!/usr/bin/env python3
"""Correct per-datagram reassembly, and the honest semantics bar.

Two corrections over fragment_validity_test.py:

1. It treated a whole TCP flow as one IP datagram, so splitting each of the 7
   packets into 2 fragments looked like "7 final fragments".  Fragmentation is
   per datagram; reassembly must group by IP identification first.

2. `semantics_intact` only checks each original payload is a substring of the
   stream, which passes for prepend: the junk sits in front of each segment
   while every segment's own bytes survive.  The correct bar for a stream
   protocol is that the reassembled stream still STARTS with the original
   command -- an HTTP request line at a non-zero offset is not an HTTP request.
"""
from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

from scapy.layers.inet import IP
from scapy.packet import Raw

REPO = Path("/root/.hermes/c2-evasion-rl")
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))

from hidden_defender_env import ACTION_NAMES, apply_mech, load_corpus, payloads_of  # noqa: E402

REPORTS = REPO / "snort_validation/reports"


def group_datagrams(pkts):
    """key = (src, dst, proto, ip_id); value = list of (offset, MF, payload)."""
    groups = defaultdict(list)
    for p in pkts:
        if IP not in p:
            groups[("raw", id(p))].append((0, False, bytes(p[Raw].load)
                                          if Raw in p else b""))
            continue
        ip = p[IP]
        mf = bool(int(ip.flags) & 1)
        off = int(ip.frag) * 8
        key = (ip.src, ip.dst, ip.proto, int(ip.id))
        groups[key].append((off, mf, bytes(p[Raw].load) if Raw in p else b""))
    return groups


def reassemble(frs):
    """RFC 791 within one datagram.  Returns (payload, error|None)."""
    if not any(mf for _o, mf, _p in frs):
        return b"".join(p for _o, _mf, p in frs), None
    for off, _mf, _p in frs:
        if off % 8:
            return b"", f"offset {off} not multiple of 8"
    finals = [o for o, mf, _p in frs if not mf]
    if len(finals) != 1:
        return b"", f"{len(finals)} final fragments (expected 1)"
    if len({o for o, _mf, _p in frs}) != len(frs):
        return b"", "duplicate fragment offsets"
    buf = bytearray()
    for off, _mf, p in sorted(frs, key=lambda f: f[0]):
        want = off - len(buf)
        if want < 0:
            return b"", f"overlap at offset {off}"
        if want > 0:
            return b"", f"gap of {want} bytes at offset {off}"
        buf.extend(p)
    return bytes(buf), None


def per_datagram_ok(orig_pkts, mut_pkts):
    """True when every original datagram is present, intact, in the mutation."""
    og, mg = group_datagrams(orig_pkts), group_datagrams(mut_pkts)
    for key, ofrs in og.items():
        want, err = reassemble(ofrs)
        if err:
            return False, f"original malformed: {err}"
        cands = [reassemble(f) for f in mg.values()]
        if not any(e is None and got == want for got, e in cands):
            return False, "no mutated datagram reassembles to the original"
    return True, ""


def main() -> int:
    flows = load_corpus("test")
    n = len(flows)
    report = {}
    print(f"{'mechanism':<12} {'dgram-ok':>9} {'stream-starts-cmd':>19}  errors")
    print("-" * 76)
    for mech in ACTION_NAMES:
        dgram = 0
        starts = 0
        errs = Counter()
        for f in flows:
            op, mp = f["packets"], apply_mech(f["packets"], mech)
            ok, err = per_datagram_ok(op, mp)
            if ok:
                dgram += 1
            elif err:
                errs[err.split(" (")[0][:34]] += 1
            orig = b"".join(payloads_of(op))
            if b"".join(payloads_of(mp)) == orig:
                starts += 1
        report[mech] = {"datagram_integrity": dgram,
                        "stream_starts_with_command": starts, "n": n,
                        "errors": dict(errs)}
        top = ", ".join(f"{k}={v}" for k, v in errs.most_common(2)) or "-"
        print(f"{mech:<12} {dgram:>4}/{n} {starts:>14}/{n}  {top}")

    out = REPORTS / "semantics_strict_test.json"
    out.write_text(json.dumps(report, indent=2))
    print(f"\n[+] {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
