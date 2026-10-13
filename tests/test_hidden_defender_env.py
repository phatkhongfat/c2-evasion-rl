#!/usr/bin/env python3
"""Tests for HiddenDefenderEnv.

The critical property is that the reward the agent sees is CORRECT: +10 only
when the alert is gone AND the C2 command still reconstructs.  A bug that made
corrupt8 look like a valid evasion would silently invalidate every downstream
number, so that is asserted explicitly.
"""
from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pytest

REPO = Path("/root/.hermes/c2-evasion-rl")
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))

from hidden_defender_env import (  # noqa: E402
    ACTION_COSTS, ACTION_NAMES, HiddenDefenderEnv, N_ACTIONS, OBS_DIM, apply_mech,
    load_corpus, payloads_of, semantics_intact,
    PROTOCOL_MATCH_BONUS, REWARD_ALERTED, REWARD_BREAK_SEMANTICS, REWARD_EVADE,
)


def test_corpus_loads_with_expected_shape():
    train, test = load_corpus("train"), load_corpus("test")
    assert len(train) == 1153
    assert len(test) == 40
    assert len(train[0]["obs"]) == 8
    assert all(0.0 <= v <= 1.0 for v in train[0]["obs"]), "obs must be normalised"


def test_corpus_has_both_captures_in_both_splits():
    for split in ("train", "test"):
        caps = {f["capture"] for f in load_corpus(split)}
        assert len(caps) == 2, f"{split} must contain both captures, got {caps}"


def test_obs_carries_no_rule_information():
    """Observation must be defender-blind: numeric features only."""
    for f in load_corpus("train"):
        obs = f["obs"]
        assert len(obs) == 8
        assert all(isinstance(v, float) for v in obs)


def test_action_space_is_discrete_seventeen():
    env = HiddenDefenderEnv(split="train")
    assert env.action_space.n == N_ACTIONS == 17
    assert env.observation_space.shape == (OBS_DIM,)
    assert ACTION_NAMES[:3] == ["split8", "split16", "split24"]
    assert "prepend4" in ACTION_NAMES and "noop" in ACTION_NAMES
    # Protocol-aware mechanisms A and B.
    assert {"http_header_pad", "length_wrapper"} <= set(ACTION_NAMES)
    # P3: slow fragmentation joined the action space as the 15th action.
    assert ACTION_NAMES[14] == "split_slow"
    # P15 (D9, docs/action_space_policy_p15.md): post-P14 non-split mechanisms.
    assert ACTION_NAMES[15] == "http_header_case"
    assert ACTION_NAMES[16] == "query_param_prepend"


def test_step_returns_wellformed_gym_tuple():
    env = HiddenDefenderEnv(split="train")
    obs, _ = env.reset()
    assert obs.shape == (OBS_DIM,) and obs.dtype == np.float32
    obs2, reward, terminated, truncated, info = env.step(0)
    assert obs2.shape == (OBS_DIM,)
    # Direction 1: reward is the base reward MINUS the action cost, so compare
    # against the cost-adjusted set rather than the raw constants.  split8 (the
    # action stepped here) is protocol-appropriate on both framings, so a valid
    # evasion additionally earns the family shaping bonus.
    cost = ACTION_COSTS[0]
    expected = {base - cost for base in
                (REWARD_BREAK_SEMANTICS, REWARD_ALERTED)}
    expected.add(REWARD_EVADE - cost)
    expected.add(REWARD_EVADE - cost + PROTOCOL_MATCH_BONUS)
    assert any(abs(reward - e) < 1e-6 for e in expected)
    assert abs(info["action_cost"] - cost) < 1e-6
    assert isinstance(terminated, bool) and isinstance(truncated, bool)
    for key in ("alert", "evaded", "semantics_ok", "action", "flow_id"):
        assert key in info, f"info missing {key}"


def test_environment_terminates_after_all_flows():
    env = HiddenDefenderEnv(split="train")
    env.reset()
    n = 0
    terminated = False
    while not terminated:
        _obs, _r, terminated, _tr, _i = env.step(3)   # prepend4
        n += 1
        assert n <= len(env._flows), "episode failed to terminate"
    assert n == len(env._flows)


def test_noop_still_alerts_on_every_baseline_flow():
    """noop must NOT evade: every corpus flow alerts at baseline by design."""
    env = HiddenDefenderEnv(split="train")
    idx_noop = ACTION_NAMES.index("noop")
    env.reset()
    alerts = 0
    for _ in range(len(env._flows)):
        _o, reward, term, _t, info = env.step(idx_noop)
        if info["alert"]:
            alerts += 1
        if term:
            break
    total = len(env._flows)
    assert alerts == total, f"noop evaded {total - alerts}/{total} flows, corpus is not all-positive"


def test_corrupt_breaks_semantics_and_scores_minus_ten():
    """corrupt8 destroys the command: it may dodge the alert but must be penalised."""
    env = HiddenDefenderEnv(split="train")
    idx = ACTION_NAMES.index("corrupt8")
    env.reset()
    n_checked = 0
    for _ in range(len(env._flows)):
        _o, reward, term, _t, info = env.step(idx)
        if info["evaded"] and not info["semantics_ok"]:
            # Direction 1: base penalty minus this action's cost.
            assert abs(reward - (REWARD_BREAK_SEMANTICS - ACTION_COSTS[idx])) < 1e-6
            n_checked += 1
        if term:
            break
    assert n_checked > 0, "corrupt8 never dodged an alert; test would be vacuous"


def test_prepend_breaks_the_channel():
    """prepend must NOT earn reward: it evades by destroying the command.

    Under the old substring bar prepend scored 43/80 "valid" and looked like the
    strongest mechanism.  It is not an evasion at all -- the junk bytes sit in
    front of every segment, so the reassembled stream no longer begins with the
    C2 command and the endpoint never executes it.  Byte equality is the bar.
    """
    env = HiddenDefenderEnv(split="train")
    idx = ACTION_NAMES.index("prepend4")
    env.reset()
    valid = 0
    for _ in range(len(env._flows)):
        _o, reward, term, _t, info = env.step(idx)
        if info["evaded"] and info["semantics_ok"]:
            valid += 1
        if term:
            break
    assert valid == 0, (
        f"prepend4 preserved the channel on {valid}/64 flows; the strict "
        "semantics bar should reject it everywhere")


def test_split24_preserves_semantics_and_evades():
    """split24 is the split mechanism that both preserves the client stream and
    (on HTTP) dodges the replica under the client-only, strict-bar design.  The
    reward it earns is the base evasion reward minus its cost, plus the
    protocol-appropriate family bonus (split24 is appropriate on both
    framings); the cost must be reported in info so the penalty is auditable."""
    env = HiddenDefenderEnv(split="train")
    idx = ACTION_NAMES.index("split24")
    env.reset()
    valid = 0
    for _ in range(len(env._flows)):
        _o, reward, term, _t, info = env.step(idx)
        if info["evaded"] and info["semantics_ok"]:
            assert abs(reward - (REWARD_EVADE - ACTION_COSTS[idx]
                                 + PROTOCOL_MATCH_BONUS)) < 1e-6
            valid += 1
        if term:
            break
    assert valid > 0, "split24 never produced a valid evasion; test is vacuous"


def test_semantics_intact_is_conservative():
    """An UNMODIFIED flow's client stream must always compare equal to itself,
    and a client-only mutation that changes the client's bytes must be
    rejected.  This is the shared strict bar, not the old relaxed parser."""
    for f in load_corpus("train")[:8]:
        # identity: unmodified packets are byte-equal to themselves
        assert semantics_intact(f["packets"], f["packets"]), \
            "unmodified flow reported as semantically broken"
        # a client-side byte change must break it
        pre = apply_mech(f["packets"], "prepend4")
        assert not semantics_intact(f["packets"], pre), \
            "a client prepend changed the bytes but was accepted"


def test_deterministic_given_fixed_action_sequence():
    a, b = HiddenDefenderEnv(split="train"), HiddenDefenderEnv(split="train")
    a.reset(); b.reset()
    for action in (0, 3, 11, 3, 6, 9):
        _o1, r1, *_ = a.step(action)
        _o2, r2, *_ = b.step(action)
        assert r1 == r2
