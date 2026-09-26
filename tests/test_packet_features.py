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
from real_packet_env import RealPacketEnv  # noqa: E402

_CAPTURES = [("stratosphere", "botnet-capture-20110811-neris"),
             ("ctu13", "botnet-capture-20110819-bot")]


def _pkt(payload: bytes, is_udp: bool = False):
    from scapy.all import IP, Raw, TCP, UDP
    base = {"src": "10.0.0.1", "dst": "10.0.0.2"}
    if is_udp:
        return IP(**base) / UDP(sport=1234, dport=53) / Raw(load=payload)
    return IP(**base) / TCP(sport=1234, dport=80) / Raw(load=payload)


def test_entropy_of_maximal_payload():
    """32 distinct byte values carry 5 bits, and the normaliser is log2(256)=8,
    so the ceiling for any 32-byte payload is 0.625 -- not 1.0."""
    assert prefix_entropy(bytes(range(32))) == pytest.approx(5.0 / 8.0)


def test_entropy_of_constant_bytes_is_zero():
    assert prefix_entropy(b"\x41" * 32) == pytest.approx(0.0)


def test_entropy_is_length_normalised():
    """Must be a fraction of log2(256), so it stays in [0, 1]."""
    v = prefix_entropy(bytes(range(32)))
    assert 0.0 < v <= 1.0


def test_entropy_of_empty_payload_is_zero():
    assert prefix_entropy(b"") == 0.0


# ---------------------------------------------------------------- finiteness
def test_features_are_finite_on_empty_flow():
    """A flow with no packets must not produce NaN (empty-mean traps)."""
    f = packet_features([])
    assert f.shape == (ACTION_MAX_PACKETS, MAX_PKT_FEAT)
    assert np.isfinite(f).all()


def test_features_are_finite_on_packets_without_payload():
    """20110810-neris / capture-win13 have almost no payload at all; the
    fallback branch for n_payload == 0 must stay finite."""
    from scapy.all import IP, TCP
    pkts = [IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1, dport=2)
            for _ in range(5)]
    f = packet_features(pkts)
    assert np.isfinite(f).all()


def test_features_have_expected_shape_on_real_flow():
    flows = RealPacketEnv(n_flows=24, capture="botnet-capture-20110811-neris",
                          dataset="stratosphere", batch_size=64).flows
    f = packet_features(flows[0][1])
    assert f.shape == (ACTION_MAX_PACKETS, MAX_PKT_FEAT)
    assert np.isfinite(f).all()


# ------------------------------------------------------------------ liveness
def _all_real_features():
    """Every packet of every flow in both working captures, as
    (capture, flow_index, packet_index, feature_index, value).

    Liveness is a dataset-wide property: a column is dead only if it is
    constant across BOTH captures, so a single 1-packet flow (where is_first
    and is_last both equal 1.0) cannot trigger a false positive.
    """
    rows = []
    for _ds, cap in _CAPTURES:
        flows = RealPacketEnv(n_flows=24, capture=cap, dataset=_ds,
                              batch_size=64).flows
        for fi, flow in enumerate(flows):
            packets = flow[1]
            f = packet_features(packets)
            for pi in range(min(len(packets), ACTION_MAX_PACKETS)):
                for c in range(MAX_PKT_FEAT):
                    rows.append((cap, fi, pi, c, float(f[pi, c])))
    return rows


def test_no_dead_feature_columns():
    """The regression guard for feature 7 ('1.0 if i < n else 0.0').

    Slow by nature: it loads all 48 flows of both captures (~3 min). Keep it --
    it is the only test that would have caught a constant column.
    """
    rows = _all_real_features()
    assert rows, "no flows loaded - the liveness check would pass vacuously"
    dead = []
    for c in range(MAX_PKT_FEAT):
        vals = {r[4] for r in rows if r[3] == c}   # r[3]=col, r[4]=value
        if len(vals) < 2:
            dead.append(c)
    assert not dead, f"dead feature columns at indices {dead}"
