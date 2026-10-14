"""Join the semantics-gate audit against flow framing.

`probe_reward_gate_gap.py` found 16 flows where the reward's own gate (D8,
lenient) says OK but strict byte-equality says BROKEN, for both
http_header_pad and http_header_case.  The framing cross-tab separately
reported http_header_pad and http_header_case evading 16/16 of the "c2-http"
flows.  If those 16 are the same 16, then the 100% figure is measured on
exactly the flows where the mutation is not byte-preserving, and the two
findings are one finding.

This probe answers that with one join instead of two parallel counts.
"""
import collections
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "ai_agent"), str(ROOT / "snort_validation")]

from scapy.layers.inet import IP, TCP, UDP  # noqa: E402

from c2_semantics import semantics_ok_reward  # noqa: E402
from hidden_defender_env import (  # noqa: E402
    HiddenDefenderEnv,
    apply_mech,
    client_ip_of,
)
from hidden_defender_env import semantics_intact  # noqa: E402

MECHS = ["http_header_pad", "http_header_case", "split8", "split16", "split24"]


def main() -> None:
    env = HiddenDefenderEnv(split="test", seed=42, real_snort=False)
    rows = []
    for flow in env._flows:
        pkts = list(flow["packets"])
        cid = client_ip_of(flow["flow_id"])
        own = [p for p in pkts if IP in p and p[IP].src == cid]
        kind = "c2-http" if any(TCP in p for p in own) else (
            "p2p-dht" if any(UDP in p for p in own) else "?")
        rec = {"flow_id": flow["flow_id"], "kind": kind}
        for mech in MECHS:
            out = apply_mech(pkts, mech, client_ip=cid)
            lenient = semantics_ok_reward(pkts, out, cid)
            strict = semantics_intact(pkts, out, cid)
            rec[mech] = (lenient, strict)
        rows.append(rec)

    print(f"{'mechanism':20s} {'lenient_ok':>11s} {'strict_ok':>10s} "
          f"{'silent':>7s} | silent nằm ở framing nào")
    for mech in MECHS:
        lenient = sum(1 for r in rows if r[mech][0])
        strict = sum(1 for r in rows if r[mech][1])
        silent = [r for r in rows if r[mech][0] and not r[mech][1]]
        by_kind = collections.Counter(r["kind"] for r in silent)
        print(f"{mech:20s} {lenient:>11d} {strict:>10d} {len(silent):>7d} | "
              f"{dict(by_kind) or '-'}")

    print()
    for mech in MECHS:
        silent = [r for r in rows if r[mech][0] and not r[mech][1]]
        if not silent:
            continue
        print(f"--- {mech}: {len(silent)} flow nhận reward nhưng KHÔNG byte-preserving")
        for r in silent[:3]:
            print(f"      {r['kind']}  {r['flow_id']}")
        print()

    # The decisive number: split* must NOT be contaminated if its evasion
    # claim is to survive the gate question.
    print("Kiểm tra: split* có sạch không?")
    for mech in ("split8", "split16", "split24"):
        silent = sum(1 for r in rows if r[mech][0] and not r[mech][1])
        print(f"  {mech:10s} silent={silent}  "
              f"{'SẠCH' if silent == 0 else 'NHIỄM'}")


if __name__ == "__main__":
    main()