"""The replica must model frag3's anomaly policy, not silently repair chains.

`snort_validation/real_rules_replica.py` joins IP fragments by sorting on offset
and concatenating their payloads.  That repairs a chain whose fragments do not
cover the datagram: a gap is closed for free and the rule matches the payload
it should never have been handed.

Snort 2.9 runs `preprocessor frag3_engine: policy first detect_anomalies`, so a
chain with a gap or an overlap is *not* reassembled at all.  The 17-mechanism
sweep measured real Snort evading 16/40 on split8/16/24 while the replica caught
39/40, and probe_frag3_anomaly.py measured a gap in 40/40 fragmented flows.

These tests pin the anomaly policy down.  They fail until the replica can drop
anomalous chains, and the noop control guards against a gate that simply
disables detection.
"""
import pathlib
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path[:0] = [str(REPO), str(REPO / "ai_agent"), str(REPO / "snort_validation")]

from hidden_defender_env import apply_mech, client_ip_of, load_corpus  # noqa: E402
from real_rules_replica import RealRulesReplica  # noqa: E402


@pytest.fixture(scope="module")
def detectable_flows():
    """Test flows the replica detects, with a mechanism that fragments them."""
    out = []
    for f in load_corpus("test"):
        rep = f["replica"]
        if getattr(rep, "reassemble", None) is None:
            rep = RealRulesReplica(rep.rules, reassemble=True)
        cid = client_ip_of(f["flow_id"])
        pkts = list(f["packets"])
        if not rep.verdict(pkts, home_ip=None):
            continue
        out.append((pkts, rep, cid))
    assert out, "no detectable test flows -- fixture would be vacuous"
    return out


def _replica(rep, **kw):
    return RealRulesReplica(rep.rules, reassemble=True, **kw)


def test_a_gapped_chain_is_not_reassembled(detectable_flows):
    """split8 leaves a gap in every fragmented flow; frag3 refuses that chain."""
    gapped = []
    for pkts, rep, cid in detectable_flows:
        cand = apply_mech(pkts, "split8", cid, ownership="client")
        if len(cand) != len(pkts):
            gapped.append((pkts, rep, cid, cand))
    assert gapped, "split8 fragmented nothing -- fixture would be vacuous"

    repaired = sum(1 for pkts, rep, cid, cand in gapped
                   if _replica(rep, frag3_timeout=60.0).verdict(cand, home_ip=None))
    refused = sum(1 for pkts, rep, cid, cand in gapped
                  if _replica(rep, frag3_timeout=60.0,
                              anomaly_check=True).verdict(cand, home_ip=None))
    assert refused < repaired, (
        "anomaly_check changed nothing: the replica is still repairing gapped "
        f"chains ({repaired}/{len(gapped)} still detected)")


def test_anomaly_check_leaves_unfragmented_flows_detected(detectable_flows):
    """Control: a contiguous stream must still be reassembled and detected."""
    still = [cid for pkts, rep, cid in detectable_flows
             if _replica(rep, frag3_timeout=60.0,
                         anomaly_check=True).verdict(pkts, home_ip=None)]
    assert len(still) == len(detectable_flows), (
        f"anomaly_check broke detection on unfragmented flows: "
        f"{len(detectable_flows) - len(still)}/{len(detectable_flows)} lost")