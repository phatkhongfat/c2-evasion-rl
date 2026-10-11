"""RED tests for the `split_slow` mechanism (O1, 2026-10-10).

`split_slow` = ordinary `split_fragments` (byte-identical, non-overlapping)
but the fragments are spread > frag3 `timeout 60`s apart, so frag3 should drop
the head fragment before reassembly and miss the rule.

Byte-safe by construction: no overlap, no byte change. These tests assert the
byte-equality invariant FIRST, because that is the bar that has killed every
other mechanism in this project.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "snort_validation"))
sys.path.insert(0, str(ROOT / "ai_agent"))

import pytest                                              # noqa: E402
from scapy.all import IP, Raw, TCP, Ether                 # noqa: E402
from c2_semantics import (assemble, semantics_preserved,  # noqa: E402
                          bytes_equal_semantics)
from fragment_ops import make_slow_fragments               # noqa: E402
from hidden_defender_env import apply_mech                 # noqa: E402
from eval_pipeline import mutate_client_only               # noqa: E402

PAYLOAD = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nHELLO_BOT"
CIP = "10.0.0.1"


def test_make_slow_fragments_delays_past_frag3_timeout():
    """Fragments must be spread MORE than 60s apart (frag3 default timeout)."""
    frags = make_slow_fragments(PAYLOAD, 8, delay=75.0)
    assert [f.offset for f in frags] == [0, 8]
    delays = [f.delay for f in frags]
    assert delays[0] == 0.0
    assert delays[1] > 60.0          # strictly past the timeout
    assert delays == sorted(delays)  # non-negative, non-decreasing


def test_make_slow_fragments_reassembles_under_any_policy():
    """THE bar: the command must survive reassembly regardless of policy."""
    frags = make_slow_fragments(PAYLOAD, 8, delay=75.0)
    for policy in ("first", "last"):
        assert assemble(frags, policy) == PAYLOAD
    assert semantics_preserved(PAYLOAD, frags) is True


def test_make_slow_fragments_rejects_non_positive_delay():
    with pytest.raises(ValueError):
        make_slow_fragments(PAYLOAD, 8, delay=0.0)


def _tcp(payload=PAYLOAD):
    return Ether() / IP(src=CIP, dst="10.0.0.2") / TCP(
        sport=1234, dport=80, seq=1000) / Raw(payload)


def test_apply_split_slow_preserves_the_byte_bar_end_to_end():
    """The whole point: fragmentation must NOT change the recovered stream,
    so it can never be barred as 'invalid' the way overlap8 is."""
    orig = [_tcp()]
    mut = apply_mech(orig, "split_slow", client_ip=CIP)
    assert len(mut) > 1, "must actually fragment"
    assert bytes_equal_semantics(orig, mut, CIP) is True


def test_apply_split_slow_sets_the_timestamp_gap():
    """The delay must become a real timestamp gap on the emitted packets."""
    orig = [_tcp()]
    orig[0].time = 1000.0
    mut = apply_mech(orig, "split_slow", client_ip=CIP)
    times = sorted(float(p.time) for p in mut)
    assert times[-1] - times[0] > 60.0


def test_mutate_client_only_handles_split_slow():
    """The EVALUATION path (mutate_client_only, used by score_flow_real and
    therefore by the ceiling sweep) has its own dispatch, separate from
    apply_mech. Both must support split_slow."""
    orig = [_tcp()]
    orig[0].time = 1000.0
    mut = mutate_client_only(orig, "split_slow", CIP)
    assert len(mut) > 1, "must actually fragment"
    times = sorted(float(p.time) for p in mut)
    assert times[-1] - times[0] > 60.0
    assert bytes_equal_semantics(orig, mut, CIP) is True


def test_split_slow_is_not_in_the_ppo_action_space_yet():
    """split_slow is deliberately NOT in ACTION_NAMES: adding it would change
    N_ACTIONS 14->15 and invalidate the trained PPO checkpoint. Registration
    waits until the ceiling sweep proves it evades. The sweep reaches it via
    --mechs, not the action space."""
    from hidden_defender_env import ACTION_NAMES
    assert "split_slow" not in ACTION_NAMES