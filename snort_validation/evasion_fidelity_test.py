#!/usr/bin/env python3
"""Is `prepend` a real evasion or just a broken C2 channel?

fragment_validity_test showed prepend reassembles 16/16 but the reassembled
bytes DIFFER from the original.  `semantics_intact` accepted that because it
only checks substring containment -- the original command is still *inside* the
stream, just no longer at the start.

A real IRC or line-based C2 client parses from the start of the stream.  Junk
bytes in front of PRIVMSG mean the command never executes, so the malware is
offline and the "evasion" is meaningless.  This prints the actual bytes so the
claim is checked rather than assumed, and classifies each mechanism by whether
the command still starts at offset 0.
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

REPO = Path("/root/.hermes/c2-evasion-rl")
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))

from hidden_defender_env import ACTION_NAMES, apply_mech, load_corpus, payloads_of  # noqa: E402

REPORTS = REPO / "snort_validation/reports"


def main() -> int:
    flows = load_corpus("test")
    n = len(flows)
    print("[*] first 3 flows, original vs mutated payload (first 72 bytes)\n")
    for i, f in enumerate(flows[:3]):
        orig = b"".join(payloads_of(f["packets"]))
        print(f"--- flow {i} ({f['capture']}) original ---")
        print(f"    {orig[:72]!r}")
        for mech in ("prepend12", "split8", "pad16"):
            mut = b"".join(payloads_of(apply_mech(f["packets"], mech)))
            print(f"    {mech:<10} {mut[:72]!r}")
        print()

    # strict criterion: command must still begin the stream
    report = {}
    print(f"{'mechanism':<12} {'stream-intact':>14} {'contains-only':>14}")
    print("-" * 44)
    for mech in ACTION_NAMES:
        stream_ok = 0
        contains = 0
        for f in flows:
            orig = b"".join(payloads_of(f["packets"]))
            mut = b"".join(payloads_of(apply_mech(f["packets"], mech)))
            if mut == orig:
                stream_ok += 1
            if orig in mut:
                contains += 1
        report[mech] = {"stream_starts_with_command": stream_ok,
                        "original_substring_present": contains, "n": n}
        print(f"{mech:<12} {stream_ok:>8}/{n} {contains:>13}/{n}")

    out = REPORTS / "evasion_fidelity_test.json"
    out.write_text(json.dumps(report, indent=2))
    print(f"\n[+] {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
