"""`_corrupted` must only record packets that actually carry a payload.

Defect (measured): real_packet_env.py:268-269 added `target` to
`self._corrupted` unconditionally, so the observation's `coverage` feature rose
while nothing was mutated. The policy then reported progress it had not made --
measured: it emitted CORRUPT at packet index 1 on all 12 steps of all 32 flows
and reported `_corrupted == {1}`, but index 1 is a handshake packet with no
payload (payload sits at indices 3 and 5).
"""
import sys
from pathlib import Path

import numpy as np
import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "tests"))

from _packets import tcp_flow  # noqa: E402
from real_packet_env import A_CORRUPT  # noqa: E402


@pytest.fixture
def env():
    """A RealPacketEnv with no pcap and no Snort: only `_corrupted` is needed.

    `object.__new__` deliberately bypasses `__init__`, which would otherwise
    load flows from disk and spawn a Snort service.
    """
    from real_packet_env import RealPacketEnv
    e = object.__new__(RealPacketEnv)
    e._corrupted = set()
    return e


def test_corrupt_on_handshake_packet_records_nothing(env):
    pkts = tcp_flow(2)                       # payload at indices 3, 4
    action = np.array([1, A_CORRUPT, 1])     # index 1 == handshake, no payload
    env._apply_mutation(pkts, action)
    assert env._corrupted == set(), (
        "corrupting a payload-free packet must not register as progress")


def test_corrupt_on_payload_packet_records_index(env):
    from scapy.all import Raw
    pkts = tcp_flow(2)
    action = np.array([3, A_CORRUPT, 1])
    out = env._apply_mutation(pkts, action)
    assert env._corrupted == {3}
    # offset 0 of the payload is overwritten with (j*97 + 13) % 256
    assert bytes(out[3][Raw].load)[:4] == bytes([13, 110, 207, 48])


def test_action_space_is_data_independent():
    """The space must be a constant so a checkpoint reloads on any flow set.

    Defect (measured): max_packets was min(max flow length, ACTION_MAX_PACKETS),
    so a model trained when the longest flow had 11 packets could only reach
    indices 0..10 against an env that offered 0..31.
    """
    from real_packet_env import ACTION_MAX_PACKETS, RealPacketEnv
    for cap, ds in [("botnet-capture-20110811-neris", "stratosphere"),
                    ("botnet-capture-20110819-bot", "ctu13")]:
        e = RealPacketEnv(n_flows=8, capture=cap, dataset=ds)
        assert e.action_space.nvec[0] == ACTION_MAX_PACKETS, (
            f"{cap}: space width {e.action_space.nvec[0]} != {ACTION_MAX_PACKETS}")
