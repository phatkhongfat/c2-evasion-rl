"""The training surrogate must not be blind to a third of the corpus.

Measured 2026-10-14 (controls/probe_replica_superset_invariant.py):

    shipped per-flow replica   3 rules    noop detected  16/40
    for_sids(6 corpus SIDs)    6 rules    noop detected  40/40
    full 21,374-rule parse   21374 rules  noop detected  40/40

A ruleset holding every rule must never fire less often than one holding a
subset of them, so these two tests pin that invariant down. They fail today
because each flow ships a protocol-family subset of the corpus rule set.
"""
import pathlib
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path[:0] = [str(REPO), str(REPO / "ai_agent"), str(REPO / "snort_validation")]

from hidden_defender_env import load_corpus  # noqa: E402
from real_rules_replica import RealRulesReplica  # noqa: E402


@pytest.fixture(scope="module")
def test_flows():
    return load_corpus("test")


def _noop_detected(replica, flow) -> bool:
    """The unmutated flow must alert. Pickle replicas predate `reassemble`."""
    if getattr(replica, "reassemble", None) is None:
        replica = RealRulesReplica(replica.rules, reassemble=True)
    return replica.verdict(flow["packets"], home_ip=None)


def test_surrogate_detects_every_test_flow_under_noop(test_flows):
    """Fidelity gate: noop must alert on 40/40, or the reward surface is flat."""
    missed = [f["flow_id"] for f in test_flows if not _noop_detected(f["replica"], f)]
    assert missed == [], (
        f"{len(missed)}/{len(test_flows)} flows are invisible to the training "
        f"surrogate -- PPO sees +REWARD_EVADE for noop on them: {missed[:5]}")


def test_full_ruleset_is_a_superset_of_the_shipped_replica(test_flows):
    """A bigger ruleset must never detect fewer flows."""
    union = set()
    for f in test_flows:
        union |= {r.sid for r in f["replica"].rules}
    full = RealRulesReplica.for_sids(union)
    regressions = [
        f["flow_id"] for f in test_flows
        if _noop_detected(f["replica"], f) and not _noop_detected(full, f)
    ]
    assert regressions == [], (
        f"widening the ruleset lost detection on {regressions[:5]}")


def test_noop_does_not_alter_a_single_byte(test_flows):
    """`apply_mech` re-serialises every packet; that must be lossless.

    A non-byte-exact round-trip would flip verdicts with no attacker intent
    at all, and PPO would bank +REWARD_EVADE for the harness's own drift.
    """
    from scapy.all import raw
    from hidden_defender_env import apply_mech, client_ip_of

    drifted = []
    for f in test_flows:
        pkts = list(f["packets"])
        noop = apply_mech(pkts, "noop", client_ip_of(f["flow_id"]))
        if len(noop) != len(pkts) or any(
                raw(a) != raw(b) for a, b in zip(pkts, noop)):
            drifted.append(f["flow_id"])
    assert drifted == [], f"`noop` rewrote {len(drifted)} flows: {drifted[:5]}"
