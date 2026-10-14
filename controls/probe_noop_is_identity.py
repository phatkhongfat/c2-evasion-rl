"""Is `noop` actually a no-op on the wire?

`apply_mech` starts with `out = [ensure_chain(p).copy() for p in pkts]`
(hidden_defender_env.py:250), so EVERY action -- including the do-nothing one
-- re-serialises each packet from scapy's layer model before scoring it. If
that round-trip is not byte-exact, a flow that the corpus replica detects can
stop being detected without a single byte of attacker intent, and PPO collects
+REWARD_EVADE for it.

Measures, per flow: bytes changed by the round-trip, and whether the replica
verdict flips between the original packets and the noop'd ones.
"""
import pathlib
import sys

REPO = pathlib.Path("/root/.hermes/c2-evasion-rl")
sys.path[:0] = [str(REPO), str(REPO / "ai_agent"), str(REPO / "snort_validation")]

from hidden_defender_env import (  # noqa: E402
    apply_mech, client_ip_of, load_corpus,
)
from real_rules_replica import RealRulesReplica  # noqa: E402
from scapy.all import raw  # noqa: E402


def _detected(rep, pkts) -> bool:
    return rep.verdict(pkts, home_ip=None)


def main() -> int:
    flows = load_corpus("test")
    n_detect_orig = n_detect_noop = 0
    flows_with_byte_drift = []
    verdict_flips = []

    for f in flows:
        pkts = list(f["packets"])
        rep = f["replica"]
        if getattr(rep, "reassemble", None) is None:
            rep = RealRulesReplica(rep.rules, reassemble=True)

        noop = apply_mech(pkts, "noop", client_ip_of(f["flow_id"]))

        drift = sum(1 for a, b in zip(pkts, noop) if raw(a) != raw(b))
        if len(noop) != len(pkts):
            drift += abs(len(noop) - len(pkts))
        if drift:
            flows_with_byte_drift.append((f["flow_id"], drift, len(pkts)))

        d_orig = _detected(rep, pkts)
        d_noop = _detected(rep, noop)
        n_detect_orig += d_orig
        n_detect_noop += d_noop
        if d_orig and not d_noop:
            verdict_flips.append(f["flow_id"])

    print(f"flows: {len(flows)}")
    print(f"detected on ORIGINAL packets : {n_detect_orig}/{len(flows)}")
    print(f"detected after `noop`         : {n_detect_noop}/{len(flows)}")
    print(f"verdict lost purely to noop   : {len(verdict_flips)}")
    print(f"flows whose bytes changed     : {len(flows_with_byte_drift)}")
    if flows_with_byte_drift:
        print("\nsample drift (flow_id, packets_changed, total_packets):")
        for fid, d, n in flows_with_byte_drift[:8]:
            print(f"  {fid}  {d}/{n}")
    if verdict_flips:
        print("\nflows that STOPPED being detected after noop:")
        for fid in verdict_flips[:8]:
            print(f"  {fid}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
