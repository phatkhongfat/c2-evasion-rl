"""The training environment must model the engine's defrag session lifetime.

Without this the surrogate reassembles every fragment chain regardless of
timing, so no action can ever evade and PPO receives a flat reward surface.
The RED state is: `HiddenDefenderEnv` has no knob for the timeout, so the
policy is trained against a detector that can never be evaded.
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "ai_agent"), str(ROOT / "snort_validation")]

from hidden_defender_env import (HiddenDefenderEnv, ACTION_NAMES,  # noqa: E402
                                apply_mech, semantics_intact,
                                REWARD_EVADE, REWARD_ALERTED)
from c2_semantics import client_ip_of  # noqa: E402


@pytest.fixture(scope="module")
def env():
    return HiddenDefenderEnv(split="test", seed=42, real_snort=False,
                            reassemble=True, replica_frag3_timeout=60.0)


def test_env_forwards_the_timeout_to_every_flow_replica(env):
    """Each flow keeps its own replica, so all of them need the timeout."""
    assert env._flows, "test split is empty"
    for flow in env._flows:
        assert flow["replica"].frag3_timeout == 60.0


def test_without_the_timeout_no_action_evades_with_intact_semantics():
    """Control: the pre-fix surrogate has no REACHABLE evasion.

    Counting "not detected" alone would be misleading -- the payload-mangling
    mechanisms are undetected precisely because they destroy the bytes the
    rule matched on, and the env pays REWARD_BREAK_SEMANTICS for those. Only
    an evasion that also passes the byte-equality gate can earn REWARD_EVADE,
    so that is what the control must assert.
    """
    blind = HiddenDefenderEnv(split="test", seed=42, real_snort=False,
                              reassemble=True)
    reached = 0
    undetected = 0
    for flow in blind._flows:
        pkts = list(flow["packets"])
        cid = client_ip_of(flow.get("flow_id"))
        for mech in ACTION_NAMES:
            cand = pkts if mech == "noop" else apply_mech(pkts, mech, cid,
                                                          ownership="client")
            if blind._detected(flow, cand):
                continue
            undetected += 1
            if semantics_intact(pkts, cand, cid):
                reached += 1
    assert undetected, "control is broken: nothing evades at all"
    assert reached == 0, (
        "expected no REACHABLE evasion without the timeout modelled, got "
        f"{reached} ({undetected} undetected overall) -- the control no "
        "longer controls")


def test_timeout_modelling_opens_a_positive_reward_gradient(env):
    """After the fix, split_slow must reach the evade reward on some flow.

    This is the whole point: PPO needs at least one action that scores better
    than the -1 floor, otherwise every action looks identical.
    """
    best = []
    for flow in env._flows:
        pkts = list(flow["packets"])
        cid = client_ip_of(flow.get("flow_id"))
        cand = apply_mech(pkts, "split_slow", cid, ownership="client")
        if not env._detected(flow, cand):
            best.append(flow["flow_id"])
    assert best, "split_slow evaded nothing; the reward surface is still flat"
    assert REWARD_EVADE > REWARD_ALERTED