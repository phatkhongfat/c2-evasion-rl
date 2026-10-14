"""Do split8 / split16 / split24 actually fragment differently?

The 17-mechanism sweep reports 591 fragment packets for all three, which
cannot be right: an 8-byte unit needs strictly more fragments than a 24-byte
one. Either they fragment identically (three actions, one behaviour) or one
of them silently falls through to the same code path.
"""
import pathlib
import sys

ROOT = pathlib.Path("/root/.hermes/c2-evasion-rl")
sys.path[:0] = [str(ROOT), str(ROOT / "ai_agent"), str(ROOT / "snort_validation")]

from scapy.all import IP, Raw, TCP  # noqa: E402

from hidden_defender_env import (HiddenDefenderEnv, apply_mech,  # noqa: E402
                                mech_applicable, payloads_of)
from c2_semantics import client_ip_of  # noqa: E402

env = HiddenDefenderEnv(split="test", seed=42, real_snort=False)
flows = env._flows


def frags(packets):
    n = 0
    for p in packets:
        if IP in p:
            off = (p[IP].frag & 0x1FFF) * 8
            if bool(p[IP].flags) or off > 0:
                n += 1
    return n


def frag_units(packets):
    """Distinct fragment sizes produced, to see which unit actually ran."""
    sizes = set()
    for p in packets:
        if IP in p and Raw in p:
            off = (p[IP].frag & 0x1FFF) * 8
            if bool(p[IP].flags) or off > 0:
                sizes.add(len(bytes(p[Raw].load)))
    return sorted(sizes)


baseline = sum(frags(f["packets"]) for f in flows)
print(f"flows={len(flows)}  fragments already in the corpus: {baseline}\n")

print(f"{'mech':10s} {'appl':>5s} {'pkts_in':>8s} {'pkts_out':>9s} "
      f"{'frags':>7s} {'new_frags':>10s}  fragment_sizes")
for mech in ("noop", "split8", "split16", "split24", "split_slow",
             "overlap8", "reorder", "ttl"):
    appl = sum(bool(mech_applicable(payloads_of(f["packets"]), mech))
            for f in flows)
    tot_in = tot_out = tot_f = 0
    sizes = set()
    for f in flows:
        pkts = list(f["packets"])
        cid = client_ip_of(f.get("flow_id"))
        cand = pkts if mech == "noop" else apply_mech(pkts, mech, cid,
                                                      ownership="client")
        tot_in += len(pkts)
        tot_out += len(cand)
        tot_f += frags(cand)
        sizes |= set(frag_units(cand))
    new = tot_f - (0 if mech == "noop" else baseline)
    print(f"{mech:10s} {appl:5d} {tot_in:8d} {tot_out:9d} {tot_f:7d} "
          f"{new:10d}  {sorted(sizes)[:8]}")