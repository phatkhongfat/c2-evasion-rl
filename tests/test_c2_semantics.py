"""The semantics oracle: did the mutation destroy the C2 command?

An evasion is only real if the endpoint can still reconstruct the original
payload. Dropping the payload-bearing packet (what the current policy does) is
destruction, not evasion, so the oracle must reject it.
"""
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "snort_validation"))

from c2_semantics import (  # noqa: E402
    Fragment, assemble, dht_ping_id, semantics_preserved,
)


def test_non_overlapping_fragments_reassemble():
    frags = [Fragment(offset=0, data=b"abcdefgh"),
             Fragment(offset=8, data=b"ijklmnop")]
    assert assemble(frags, policy="first") == b"abcdefghijklmnop"
    assert assemble(frags, policy="last") == b"abcdefghijklmnop"


def test_overlap_first_and_last_disagree():
    # offset 0 arrives twice with different bytes
    frags = [Fragment(offset=0, data=b"AAAAAAAA"),
             Fragment(offset=8, data=b"BBBBBBBB"),
             Fragment(offset=0, data=b"CCCCCCCC")]
    assert assemble(frags, policy="first") == b"AAAAAAAABBBBBBBB"
    assert assemble(frags, policy="last") == b"CCCCCCCCBBBBBBBB"


def test_semantics_preserved_when_one_policy_recovers_original():
    original = b"d1:ad2:id20:" + b"\x01" * 86
    frags = [Fragment(offset=0, data=b"\x00" * 8),
             Fragment(offset=8, data=original[8:]),
             Fragment(offset=0, data=original[:8])]
    assert semantics_preserved(original, frags) is True


def test_semantics_destroyed_when_no_policy_recovers_original():
    original = b"d1:ad2:id20:" + b"\x01" * 86
    # the real first 8 bytes are simply gone
    frags = [Fragment(offset=0, data=b"\x00" * 8),
             Fragment(offset=8, data=original[8:])]
    assert semantics_preserved(original, frags) is False


def test_dht_ping_id_extracts_the_id_field():
    payload = b"d1:ad2:id20:0123456789abcdefghij1:q4:ping1:t2:aa1:y1:qe"
    assert dht_ping_id(payload) == b"0123456789abcdefghij"
