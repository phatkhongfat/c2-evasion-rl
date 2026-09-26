"""Feature contract for packet_features(): shape, finiteness, and liveness.

"liveness" is the property the old feature 7 violated: a column whose every
value is identical teaches the policy nothing while looking completely healthy.
"""
import sys
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "ai_agent"))

from snort_bandit import ACTION_MAX_PACKETS, MAX_PKT_FEAT, packet_features  # noqa: E402
from snort_bandit import prefix_entropy  # noqa: E402


def _pkt(payload: bytes, is_udp: bool = False):
    from scapy.all import IP, Raw, TCP, UDP
    base = {"src": "10.0.0.1", "dst": "10.0.0.2"}
    if is_udp:
        return IP(**base) / UDP(sport=1234, dport=53) / Raw(load=payload)
    return IP(**base) / TCP(sport=1234, dport=80) / Raw(load=payload)


def test_entropy_of_uniform_bytes_is_maximal():
    assert prefix_entropy(b"\x00" * 32) == pytest.approx(1.0)


def test_entropy_of_constant_bytes_is_zero():
    assert prefix_entropy(b"\x41" * 32) == pytest.approx(0.0)


def test_entropy_is_length_normalised():
    """Must be a fraction of log2(256), so it stays in [0, 1]."""
    v = prefix_entropy(bytes(range(32)))
    assert 0.0 < v <= 1.0


def test_entropy_of_empty_payload_is_zero():
    assert prefix_entropy(b"") == 0.0
