#!/usr/bin/env python3
"""Are the evasions real, or just malformed packets that Snort discards?

`semantics_intact` only checks that the original payloads appear in order, which
would pass even for fragments a real IP stack rejects.  If the mutated packets
are structurally invalid -- bad fragment offset, wrong MF flag, truncated
datagram -- then "evasion" is an artifact: the C2 channel is dead and Snort had
no choice.  That distinction decides whether this study measures attacker skill
or packet corruption, so it gets checked explicitly.

Reassembly is done per RFC 791 here rather than trusting packet order, because
out-of-order delivery is normal and a correct implementation must sort by
fragment offset.
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.inet6 import IPv6
from scapy.packet import Raw

REPO = Path("/root/.hermes/c2-evasion-rl")
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))

from hidden_defender_env import ACTION_NAMES, apply_mech, load_corpus, payloads_of  # noqa: E402

REPORTS = REPO / "snort_validation/reports"


def fragments(pkts):
    """(offset_in_bytes, more_flag, payload) for every fragmented IPv4 packet."""
    out = []
    for p in pkts:
        if IP not in p:
            continue
        ip = p[IP]
        if not ip.flags or int(ip.flags) & 1 == 0:  # MF not set
            out.append((0, False, bytes(p[Raw].load) if Raw in p else b""))
            continue
        out.append((int(ip.frag) * 8, True,
                    bytes(p[Raw].load) if Raw in p else b""))
    return out


def reassemble(pkts):
    """RFC 791 reassembly.  Returns (payload, error) with error None on success."""
    frs = fragments(pkts)
    if not frs:
        return b"", "no-fragments"
    if not any(mf for _o, mf, _p in frs):
        return b"".join(p for _o, _mf, p in frs), None
    for off, _mf, p in frs:
        if off % 8:
            return b"", f"offset {off} not a multiple of 8"
    finals = [o for o, mf, _p in frs if not mf]
    if len(finals) != 1:
        return b"", f"{len(finals)} final fragments (expected exactly 1)"
    starts = sorted({o for o, _mf, _p in frs})
    if len(starts) != len(frs):
        return b"", "duplicate fragment offsets"
    buf = bytearray()
    for off, _mf, p in sorted(frs, key=lambda f: f[0]):
        want = off - len(buf)
        if want < 0:
            return b"", f"overlapping fragments at offset {off}"
        if want > 0:
            return b"", f"gap of {want} bytes before offset {off}"
        buf.extend(p)
    return bytes(buf), None


def main() -> int:
    flows = load_corpus("test")
    n = len(flows)
    report = {}
    print(f"{'mechanism':<12} {'reassembles':>12} {'== orig':>9}  errors")
    print("-" * 78)
    for mech in ACTION_NAMES:
        ok = 0
        same = 0
        errs = Counter()
        for f in flows:
            orig_pkts = f["packets"]
            orig_payload = b"".join(payloads_of(orig_pkts))
            mut = apply_mech(orig_pkts, mech)
            got, err = reassemble(mut)
            if err is None:
                ok += 1
                if got == orig_payload:
                    same += 1
                else:
                    errs["reassembles-but-differs"] += 1
            else:
                errs[err.split(" (")[0]] += 1
        report[mech] = {"reassembles": ok, "byte_identical_to_original": same,
                        "errors": dict(errs)}
        top = ", ".join(f"{k}={v}" for k, v in errs.most_common(3)) or "-"
        print(f"{mech:<12} {ok:>7}/{n} {same:>8}/{n}  {top}")

    out = REPORTS / "fragment_validity_test.json"
    out.write_text(json.dumps(report, indent=2))
    print(f"\n[+] {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
