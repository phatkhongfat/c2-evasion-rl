"""The replica must model the engine's fragment timeout, not just rejoin bytes.

`apply_mech("split_slow")` spaces its fragments 75 s apart, past Snort's
default frag3_timeout of 60 s.  Real Snort therefore never reassembles that
flow into the buffer the rule matched -- which the 17-mechanism sweep measured
as split_slow evading 23/40 on Snort 2.9.20.

`snort_validation/real_rules_replica.py` joins IP fragments by offset with no
notion of time, so it hands the rule the complete buffer and reports
"detected".  Against a time-blind reassembler NO semantics-preserving
mechanism can ever evade, the +10 reward is unreachable, and PPO has no
gradient to follow.

These tests pin the timeout down.  They fail until the replica accepts a
`frag3_timeout` and drops fragment groups whose inter-arrival gap exceeds it,
mirroring what an engine whose reassembly session has expired does.
"""
import pathlib
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path[:0] = [str(REPO), str(REPO / "ai_agent"), str(REPO / "snort_validation")]

from hidden_defender_env import apply_mech, client_ip_of, load_corpus  # noqa: E402
from real_rules_replica import RealRulesReplica  # noqa: E402


@pytest.fixture(scope="module")
def slow_flows():
    """Test flows that the replica detects and that split_slow can fragment."""
    out = []
    for f in load_corpus("test"):
        rep = f["replica"]
        if getattr(rep, "reassemble", None) is None:
            rep = RealRulesReplica(rep.rules, reassemble=True)
        cid = client_ip_of(f["flow_id"])
        pkts = list(f["packets"])
        if not rep.verdict(pkts, home_ip=None):
            continue
        cand = apply_mech(pkts, "split_slow", cid, ownership="client")
        if len(cand) == len(pkts):
            continue  # nothing was fragmentable; split_slow stayed a no-op
        out.append((f, rep, cid))
    return out


def test_fragment_timeout_is_opt_in(slow_flows):
    """Default behaviour is unchanged: no timeout, perfect reassembly."""
    f, _, _ = slow_flows[0]
    assert RealRulesReplica(f["replica"].rules).frag3_timeout is None


def test_split_slow_beats_the_default_frag3_timeout(slow_flows):
    """The attack's premise: fragments spaced past 60 s evade the engine."""
    caught = 0
    for f, rep, cid in slow_flows:
        cand = apply_mech(list(f["packets"]), "split_slow", cid,
                          ownership="client")
        leaky = RealRulesReplica(rep.rules, reassemble=True, frag3_timeout=60.0)
        if not leaky.verdict(cand, home_ip=None):
            caught += 1
    assert caught, "split_slow evaded nothing -- the timeout is not modelled"


def test_time_blind_reassembly_catches_what_snort_lets_through(slow_flows):
    """The gap this fix closes, asserted rather than assumed.

    A replica without a timeout catches every split_slow flow; one with a
    60 s timeout lets some through.  If the second stops happening the two
    implementations have been silently merged again.
    """
    blind_caught = blind_total = timed_caught = 0
    for f, rep, cid in slow_flows:
        cand = apply_mech(list(f["packets"]), "split_slow", cid,
                          ownership="client")
        blind = RealRulesReplica(rep.rules, reassemble=True)
        leaky = RealRulesReplica(rep.rules, reassemble=True, frag3_timeout=60.0)
        blind_total += 1
        blind_caught += bool(blind.verdict(cand, home_ip=None))
        timed_caught += bool(leaky.verdict(cand, home_ip=None))
    assert blind_caught == blind_total, (
        "expected the time-blind replica to catch every fragmented flow")
    assert timed_caught < blind_caught, (
        f"timeout model changed nothing: {timed_caught}/{blind_total}")
