"""transport-layer payload ops: transport_payload / has_payload / as_raw.

scapy dissects UDP/53 into a DNS layer, so ``Raw in pkt`` is False on DNS
traffic even though the packet carries bytes.  Every mechanism and the
byte-equality bar filtered on ``Raw in pkt``, which silently no-opped all 33
DNS flows of the corpus.  These tests pin the transport-layer readers that
replace that filter, plus ``as_raw`` which flattens a dissected payload back
into one Raw layer so the in-place mutators can rewrite it.

split_slow on a REAL corpus flow is covered too: it must fragment a payload
bearing UDP packet, keep the reassembled transport bytes equal to the
original (the byte-equality bar), and step the fragment timestamps by 75s.
"""
import pickle
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "snort_validation"))
sys.path.insert(0, str(ROOT / "ai_agent"))

import pytest                                                    # noqa: E402
from scapy.all import DNS, DNSQR, Ether, ICMP, IP, Raw, TCP, UDP  # noqa: E402
from c2_semantics import (as_raw, bytes_equal_semantics,          # noqa: E402
                          client_ip_of_packets, has_payload,
                          transport_payload)

CIP = "10.0.0.1"
SIP = "10.0.0.2"
PAYLOAD = b"HTTP/1.1 200 OK\r\n\r\nHELLO_BOT_COMMAND"


# ---------- transport_payload ----------

def test_transport_payload_reads_tcp_raw():
    p = IP(src=CIP, dst=SIP) / TCP(sport=1234, dport=80) / Raw(load=PAYLOAD)
    assert transport_payload(p) == PAYLOAD


def test_transport_payload_reads_udp_raw():
    p = IP(src=CIP, dst=SIP) / UDP(sport=1234, dport=53) / Raw(load=PAYLOAD)
    assert transport_payload(p) == PAYLOAD


def test_transport_payload_reads_icmp_raw():
    """ICMP is not TCP/UDP, but it can still carry a Raw payload on the wire."""
    p = IP(src=CIP, dst=SIP) / ICMP() / Raw(load=PAYLOAD)
    assert transport_payload(p) == PAYLOAD
    assert has_payload(p) is True


def test_transport_payload_reads_dissected_dns():
    p = (Ether() / IP(src=CIP, dst="8.8.8.8") / UDP(sport=40000, dport=53)
         / DNS(rd=1, qd=DNSQR(qname="mgis42.ru.")))
    assert Raw not in p, "precondition: scapy dissected this into a DNS layer"
    assert b"mgis42" in transport_payload(p)


# ---------- has_payload ----------

def test_has_payload_true_for_payload_bearing():
    p = IP(src=CIP, dst=SIP) / UDP(sport=1, dport=2) / Raw(load=b"x" * 10)
    assert has_payload(p) is True


def test_has_payload_false_for_bare_tcp_ack():
    p = IP(src=CIP, dst=SIP) / TCP(sport=1, dport=2, flags="A")
    assert has_payload(p) is False
    assert transport_payload(p) == b""


def test_has_payload_false_for_ip_only():
    p = IP(src=CIP, dst=SIP)
    assert has_payload(p) is False


# ---------- as_raw ----------

def test_as_raw_roundtrips_a_dissected_packet_without_losing_bytes():
    p = (Ether() / IP(src=CIP, dst="8.8.8.8") / UDP(sport=40000, dport=53)
         / DNS(rd=1, qd=DNSQR(qname="mgis42.ru.")))
    before = transport_payload(p)
    out = as_raw(p)
    assert Raw in out, "as_raw must add a Raw layer to a dissected payload"
    assert transport_payload(out) == before, "the wire bytes must be unchanged"


def test_as_raw_is_a_noop_on_a_packet_that_already_has_raw():
    p = IP(src=CIP, dst=SIP) / UDP(sport=1, dport=2) / Raw(load=PAYLOAD)
    assert as_raw(p) is p


def test_as_raw_enables_in_place_rewrite_of_dns_payload():
    """The bug: assigning pkt[Raw].load raised IndexError on DNS traffic."""
    p = (Ether() / IP(src=CIP, dst="8.8.8.8") / UDP(sport=40000, dport=53)
         / DNS(rd=1, qd=DNSQR(qname="mgis42.ru.")))
    with pytest.raises(IndexError):
        p[Raw].load = b"junk"           # precondition: raw assign fails
    out = as_raw(p)
    out[Raw].load = b"prepended" + bytes(out[Raw].load)
    assert bytes(out[Raw].load).startswith(b"prepended")


# ---------- split_slow on a real corpus flow ----------

def _udp_flow_with_payload():
    """One client UDP packet with >8 bytes of transport payload, taken from a
    real corpus flow (v3 fixed corpus)."""
    pkl = ROOT / "snort_validation" / "reports" / "hidden_defender_corpus_v3fixed.pkl"
    if not pkl.exists():
        pytest.skip(f"corpus pickle missing: {pkl}")
    data = pickle.loads(pkl.read_bytes())
    for flow in data["train"] + data["test"]:
        pkts = flow["packets"]
        if not any(UDP in p for p in pkts):
            continue
        cip = client_ip_of_packets(pkts)
        for p in pkts:
            if (IP in p and UDP in p and p[IP].src == cip
                    and len(transport_payload(p)) > 8):
                return p, cip
    pytest.skip("no payload-bearing client UDP packet in the corpus")


def test_split_slow_reassembles_to_original_transport_payload():
    from hidden_defender_env import apply_mech

    pkt, cip = _udp_flow_with_payload()
    pkt = pkt.copy()
    pkt.time = 1000.0
    orig = [pkt]
    mut = apply_mech(orig, "split_slow", client_ip=cip, ownership="both")
    assert len(mut) > len(orig), "split_slow must actually fragment the flow"
    # the byte-equality bar: reassembled transport bytes == original
    assert bytes_equal_semantics(orig, mut, cip) is True


def test_split_slow_steps_fragment_timestamps_by_75s():
    from hidden_defender_env import apply_mech

    pkt, cip = _udp_flow_with_payload()
    pkt = pkt.copy()
    pkt.time = 1000.0
    mut = apply_mech([pkt], "split_slow", client_ip=cip, ownership="both")
    times = sorted(float(p.time) for p in mut)
    assert len(times) == 2, "one packet with payload>8 -> two fragments"
    assert times[1] - times[0] == pytest.approx(75.0)
    assert times[1] - times[0] > 60.0     # strictly past frag3's timeout
