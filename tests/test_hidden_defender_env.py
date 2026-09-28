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
    ACTION_COSTS, ACTION_NAMES, HiddenDefenderEnv, N_ACTIONS, load_corpus,
    payloads_of, semantics_intact,
    REWARD_ALERTED, REWARD_BREAK_SEMANTICS, REWARD_EVADE,
)


def test_corpus_loads_with_expected_shape():
    train, test = load_corpus("train"), load_corpus("test")
    assert len(train) == 64
    assert len(test) == 16
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


def test_action_space_is_discrete_fourteen():
    env = HiddenDefenderEnv(split="train")
    assert env.action_space.n == N_ACTIONS == 14
    assert env.observation_space.shape == (8,)
    assert ACTION_NAMES[:3] == ["split8", "split16", "split24"]
    assert "prepend4" in ACTION_NAMES and "noop" in ACTION_NAMES
    # Protocol-aware mechanisms A and B.
    assert {"http_header_pad", "length_wrapper"} <= set(ACTION_NAMES)


def test_step_returns_wellformed_gym_tuple():
    env = HiddenDefenderEnv(split="train")
    obs, _ = env.reset()
    assert obs.shape == (8,) and obs.dtype == np.float32
    obs2, reward, terminated, truncated, info = env.step(0)
    assert obs2.shape == (8,)
    # Direction 1: reward is the base reward MINUS the action cost, so compare
    # against the cost-adjusted set rather than the raw constants.
    cost = ACTION_COSTS[0]
    expected = {base - cost for base in
                (REWARD_EVADE, REWARD_BREAK_SEMANTICS, REWARD_ALERTED)}
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
        assert n <= 64, "episode failed to terminate"
    assert n == 64


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
    assert alerts == 64, f"noop evaded {64 - alerts}/64 flows, corpus is not all-positive"


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


def test_split_preserves_semantics_and_evades():
    env = HiddenDefenderEnv(split="train")
    idx = ACTION_NAMES.index("split8")
    env.reset()
    valid = 0
    for _ in range(len(env._flows)):
        _o, reward, term, _t, info = env.step(idx)
        if info["evaded"] and info["semantics_ok"]:
            # Direction 1: base reward minus this action's cost, and the cost
            # must be reported in info so the penalty is auditable.
            assert abs(reward - (REWARD_EVADE - ACTION_COSTS[idx])) < 1e-6
            valid += 1
        if term:
            break
    assert valid >= 20, f"split8 only valid on {valid}/64 train flows"


def test_semantics_intact_is_conservative():
    """A flow's own payloads must always be 'intact' unmodified."""
    for f in load_corpus("train")[:8]:
        orig = payloads_of(f["packets"])
        assert semantics_intact(orig, f["packets"]), \
            "unmodified flow reported as semantically broken"


def test_deterministic_given_fixed_action_sequence():
    a, b = HiddenDefenderEnv(split="train"), HiddenDefenderEnv(split="train")
    a.reset(); b.reset()
    for action in (0, 3, 11, 3, 6, 9):
        _o1, r1, *_ = a.step(action)
        _o2, r2, *_ = b.step(action)
        assert r1 == r2
