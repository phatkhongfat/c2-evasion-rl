#!/usr/bin/env python3
"""P3: split_slow as the 15th RL action (TDD).

split_slow was implemented (commit 3393644) but deliberately kept OUT of the
PPO action space while the action space was 14 actions.  The v3fixed ceiling
sweep then proved it evades the whole DNS/UDP family the fast splits miss
(40/40 valid on the test split, `ceiling_v3_splitslow_fixed.json`), so it is
promoted to a real action.  These tests pin the four things that promotion
touches:

  (i)   ACTION_NAMES / N_ACTIONS            -> 15, split_slow at index 14
  (ii)  ACTION_COSTS[14]                    -> 0.65 (slower / more disruptive
                                                than split8's 0.60)
  (iii) the action mask                     -> allowed only when an owned
                                                packet has transport payload > 8
  (iv)  env.step(split_slow)                -> semantics_ok through the normal
                                                path (real_snort=False replica)
  (v)   PROTOCOL_APPROPRIATE                -> split_slow is the appropriate
                                                primitive for the dns/irc framings

The mask rule mirrors the condition inside apply_mech exactly: `0 < 8 < len(payload)`.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ai_agent"))
sys.path.insert(0, str(ROOT / "snort_validation"))

from scapy.all import IP, Raw, UDP  # noqa: E402

from hidden_defender_env import (  # noqa: E402
    ACTION_COSTS,
    ACTION_NAMES,
    N_ACTIONS,
    PROTOCOL_APPROPRIATE,
    HiddenDefenderEnv,
)

SPLIT_SLOW = "split_slow"


# -- (i) registration -------------------------------------------------------

def test_split_slow_is_registered_as_the_fifteenth_action():
    assert SPLIT_SLOW in ACTION_NAMES
    assert N_ACTIONS == 15
    assert len(ACTION_NAMES) == 15
    assert ACTION_NAMES.index(SPLIT_SLOW) == 14


def test_action_space_reports_fifteen_actions():
    env = HiddenDefenderEnv(split="test")
    assert env.action_space.n == 15


# -- (ii) cost --------------------------------------------------------------

def test_split_slow_cost_is_above_split8():
    """0.65 > split8's 0.60: slow fragmentation holds a fragment past frag3's
    60s timeout, so it is slower and more disruptive than a fast split."""
    assert 14 in ACTION_COSTS
    assert ACTION_COSTS[14] == 0.65
    assert ACTION_COSTS[14] > ACTION_COSTS[0]        # split8
    assert len(ACTION_COSTS) == 15


# -- (iii) mask -------------------------------------------------------------

def _udp_flow(flow_id, client_payload, server_payload=b""):
    pkts = [IP(src="10.0.0.1", dst="10.0.0.2")
            / UDP(sport=1234, dport=53) / Raw(load=client_payload)]
    if server_payload:
        pkts.append(IP(src="10.0.0.2", dst="10.0.0.1")
                    / UDP(sport=53, dport=1234) / Raw(load=server_payload))
    return {"flow_id": flow_id, "packets": pkts, "framing": "dns",
            "obs": [0.0] * 8}


def test_mask_allows_split_slow_on_a_udp_flow_with_payload_over_eight():
    env = HiddenDefenderEnv(split="test")
    env._flows = [_udp_flow("cap|10.0.0.1:1234->10.0.0.2:53|udp", b"x" * 20)]
    env._idx = 0
    mask = env.action_masks()
    assert len(mask) == 15
    assert mask[14] == 1, "split_slow must be allowed when an owned payload > 8"


def test_mask_blocks_split_slow_when_no_owned_payload_exceeds_eight():
    env = HiddenDefenderEnv(split="test")
    env._flows = [_udp_flow("cap|10.0.0.1:1234->10.0.0.2:53|udp", b"x" * 8)]
    env._idx = 0
    assert env.action_masks()[14] == 0, \
        "an 8-byte payload leaves apply_mech a no-op, so split_slow is masked"


def test_mask_ignores_peer_payload_under_client_ownership():
    """ownership=client must NOT let a big SERVER payload unlock split_slow,
    because apply_mech would not touch it."""
    env = HiddenDefenderEnv(split="test", ownership="client")
    env._flows = [_udp_flow("cap|10.0.0.1:1234->10.0.0.2:53|udp",
                            b"x" * 4, server_payload=b"S" * 100)]
    env._idx = 0
    assert env.action_masks()[14] == 0


def test_mask_unlocks_split_slow_from_peer_payload_under_both_ownership():
    env = HiddenDefenderEnv(split="test", ownership="both")
    env._flows = [_udp_flow("cap|10.0.0.1:1234->10.0.0.2:53|udp",
                            b"x" * 4, server_payload=b"S" * 100)]
    env._idx = 0
    assert env.action_masks()[14] == 1


# -- (iv) step semantics ----------------------------------------------------

def test_step_with_split_slow_preserves_semantics_through_the_normal_path():
    """The action must run end to end (score -> apply_mech -> byte bar) and the
    bar must pass: split_slow is byte-safe by construction.  The replica may or
    may not report evasion; only semantics_ok is asserted here."""
    env = HiddenDefenderEnv(split="test", real_snort=False)
    idx = ACTION_NAMES.index(SPLIT_SLOW)
    found = False
    for i, f in enumerate(env._flows):
        env._idx = i
        if env.action_masks()[14] != 1:
            continue
        env._idx = i
        _obs, _r, _t, _tr, info = env.step(idx)
        assert info["action"] == SPLIT_SLOW
        assert info["semantics_ok"] is True, \
            f"split_slow broke semantics on {f['flow_id']}"
        found = True
        break
    assert found, "no test flow exposed split_slow (mask closed everywhere?)"


# -- (v) protocol-appropriate bonus mapping ---------------------------------

def test_split_slow_is_appropriate_for_dns_and_irc():
    assert SPLIT_SLOW in PROTOCOL_APPROPRIATE["dns"]
    assert SPLIT_SLOW in PROTOCOL_APPROPRIATE["irc"]
