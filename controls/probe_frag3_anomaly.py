"""Does frag3's `detect_anomalies` explain the remaining surrogate gap?

Real Snort evades 16/40 on split8/16/24 while the replica catches 39/40.
Snort's frag3 under `policy first detect_anomalies` refuses to reassemble a
chain whose fragments leave a gap or overlap; real_rules_replica.py:436
concatenates fragments in offset order without checking contiguity, so a
gapped chain is silently repaired and the rule still matches.

Measures per mechanism: flows that fragment at all, and of those, how many
chains have a gap, an overlap, or both.
"""
import collections
import pathlib
import sys

ROOT = pathlib.Path("/root/.hermes/c2-evasion-rl")
sys.path[:0] = [str(ROOT), str(ROOT / "ai_agent"), str(ROOT / "snort_validation")]

from scapy.layers.inet import IP  # noqa: E402
from scapy.packet import Raw  # noqa: E402

from hidden_defender_env import HiddenDefenderEnv, ACTION_NAMES, apply_mech  # noqa: E402
from c2_semantics import client_ip_of  # noqa: E402


def chain_stats(pkts):
    """Return per-chain gap/overlap counts, or None if nothing is fragmented."""
    groups: dict = collections.OrderedDict()
    for p in pkts:
        if IP not in p:
            continue
        ip = p[IP]
        offset = (ip.frag & 0x1FFF) * 8
        mf = bool(ip.flags)          # scapy keeps MF in IP.flags, not IP.frag
        if not mf and offset == 0:
            continue                  # not a fragment
        groups.setdefault((ip.src, ip.dst, ip.proto, ip.id), []).append(
            (offset, len(bytes(p[Raw].load)) if Raw in p else 0))

    if not groups:
        return None
    gaps = overlaps = 0
    for frags in groups.values():
        frags.sort()
        cursor = None
        for off, ln in frags:
            if off == 0:
                cursor = ln
                continue
            if cursor is None:
                cursor = off + ln
                continue
            if off > cursor:
                gaps += 1
            elif off < cursor:
                overlaps += 1
            cursor = max(cursor, off + ln)
    return {"chains": len(groups), "gaps": gaps, "overlaps": overlaps}


def main() -> int:
    env = HiddenDefenderEnv(split="test", seed=42, real_snort=False)
    print(f"[*] {len(env._flows)} test flows\n")
    print(f"{'mechanism':20s} {'fragmented':>10s} {'gap':>5s} {'ovl':>5s} "
          f"{'both':>5s}")
    for mech in ACTION_NAMES:
        if mech == "noop":
            continue
        stat = collections.Counter()
        for f in env._flows:
            pkts = list(f["packets"])
            cid = client_ip_of(f.get("flow_id"))
            cand = apply_mech(pkts, mech, cid, ownership="client")
            st = chain_stats(cand)
            if st is None:
                continue
            stat["flows"] += 1
            stat["gap"] += st["gaps"] > 0
            stat["ovl"] += st["overlaps"] > 0
            stat["both"] += (st["gaps"] > 0 and st["overlaps"] > 0)
        if stat["flows"]:
            print(f"{mech:20s} {stat['flows']:10d} {stat['gap']:5d} "
                  f"{stat['ovl']:5d} {stat['both']:5d}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())