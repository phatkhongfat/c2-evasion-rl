"""Fragment construction: the mutated stream must keep the command AND
present different bytes to a `policy first` reassembler."""
import sys
from pathlib import Path

import pytest
from scapy.all import IP, Raw, UDP, TCP

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "snort_validation"))

from c2_semantics import Fragment, assemble, reconstructs_command  # noqa: E402
from fragment_ops import (  # noqa: E402
    fix_checksums,
    overlap_fragments,
    split_fragments,
)


def _dht_payload():
    # 12-byte pattern at offset 0, as measured on real DHT flows
    return b"d1:ad2:id20:" + b"\x11" * 20 + b"e1:q4:ping1:t2:aa1:y1:qe" + b"\x22" * 50


def test_split_then_overlap_keeps_command_but_hides_pattern():
    payload = _dht_payload()
    frags = overlap_fragments(payload, split_at=8)
    # endpoint can still recover the original command
    assert reconstructs_command(payload, frags) is True
    # but a `policy first` reassembler sees benign bytes at offset 0
    first_view = assemble(frags, policy="first")
    assert first_view[:8] != payload[:8]
    assert not first_view.startswith(b"d1:ad2:id20:")


def test_split_fragments_reassemble_to_original():
    payload = _dht_payload()
    frags = split_fragments(payload, split_at=8)
    assert assemble(frags, policy="first") == payload
    assert assemble(frags, policy="last") == payload


def test_overlap_fragments_have_valid_offsets():
    frags = overlap_fragments(_dht_payload(), split_at=8)
    for f in frags:
        assert f.offset % 8 == 0, "IP fragment offsets are in 8-byte units"


def test_fragment_plan_to_packets_preserves_all_bytes():
    from scapy.all import IP, Raw, UDP
    from fragment_ops import fragment_plan_to_packets

    payload = _dht_payload()
    pkt = (IP(src="10.0.0.1", dst="10.0.0.2")
           / UDP(sport=4444, dport=6881) / Raw(load=payload))
    frags = overlap_fragments(payload, split_at=8)
    out = fragment_plan_to_packets([pkt], frags, 0)

    assert len(out) == 3
    # every original byte is still present somewhere on the wire
    seen = set()
    for p in out:
        assert IP in p and Raw in p
        for b in bytes(p[Raw].load):
            seen.add(b)
    for b in payload:
        assert b in seen
    # offsets are 8-byte units and only the final fragment clears MF
    assert [p[IP].frag for p in out] == [0, 1, 0]
    assert [int(p[IP].flags) for p in out] == [1, 0, 1]


def _pkt(transport_cls):
    p = IP(src="10.0.0.1", dst="10.0.0.2") / transport_cls(sport=1234, dport=80)
    return p / Raw(load=b"original")


def test_fix_checksums_udp():
    new = b"a much longer body that changes the checksum"
    p = fix_checksums(_pkt(UDP), new)
    assert p[Raw].load == new
    assert p[UDP].chksum is not None


def test_fix_checksums_tcp():
    p = fix_checksums(_pkt(TCP), b"another entirely different length of body")
    assert p[TCP].chksum is not None


def test_fix_checksums_original_untouched():
    p = _pkt(UDP)
    before = bytes(p[Raw].load)
    fix_checksums(p, b"different")
    assert bytes(p[Raw].load) == before


def test_fix_checksums_value_reflects_new_payload():
    """A stale checksum makes Snort drop the packet, which would make every
    mechanism 'evade' for the wrong reason -- so the value must really change
    with the payload."""
    short = fix_checksums(_pkt(UDP), b"x" * 10)[UDP].chksum
    long = fix_checksums(_pkt(UDP), b"x" * 400)[UDP].chksum
    assert short != long
