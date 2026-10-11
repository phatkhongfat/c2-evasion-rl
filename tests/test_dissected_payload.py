"""scapy auto-dissects UDP/53 into a DNS layer, so `Raw in pkt` is False for DNS
traffic even though the packet carries bytes.  Every mechanism filtered on
`Raw in pkt`, which silently made all 33 DNS flows of the corpus a no-op.

These tests pin the fix: fragmentation must work on dissected payloads too.
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ai_agent"))
sys.path.insert(0, str(ROOT / "snort_validation"))
sys.path.insert(0, str(ROOT / "controls"))

from scapy.all import DNS, DNSQR, Ether, IP, Raw, TCP, UDP      # noqa: E402
from c2_semantics import bytes_equal_semantics                  # noqa: E402
from eval_pipeline import mutate_client_only                    # noqa: E402
from fragment_ops import (fragment_plan_to_packets,             # noqa: E402
                          has_payload, make_slow_fragments,
                          transport_payload)
from hidden_defender_env import apply_mech                       # noqa: E402

CIP = "10.1.2.3"
SIP = "8.8.8.8"


def dns_flow(n_packets=3):
    """A UDP/53 flow whose payloads scapy dissects into DNS layers."""
    pkts = []
    for i in range(n_packets):
        name = ["mgis42.ru.", "m-ra.ru.", "lrp-russia.ru."][i % 3]
        pkts.append(Ether() / IP(src=CIP, dst=SIP) /
                    UDP(sport=40000 + i, dport=53) /
                    DNS(rd=1, qd=DNSQR(qname=name)))
    return pkts


def tcp_flow():
    return [Ether() / IP(src=CIP, dst=SIP) /
            TCP(sport=1234, dport=888, flags="PA") / Raw(load=b"X" * 200)]


# ---------- unit: the payload reader sees through scapy's dissection ----------

def test_dissected_dns_payload_is_visible_even_though_raw_is_absent():
    p = dns_flow()[0]
    assert Raw not in p, "precondition: scapy dissected this into a DNS layer"
    assert DNS in p
    assert has_payload(p) is True
    # the query name must be present in the raw payload bytes
    assert b"mgis42" in transport_payload(p)


def test_transport_payload_is_wire_identical_to_raw_on_a_raw_packet():
    p = tcp_flow()[0]
    assert transport_payload(p) == b"X" * 200


def test_packet_without_transport_payload_reports_none():
    p = Ether() / IP(src=CIP, dst=SIP)
    assert has_payload(p) is False
    assert transport_payload(p) == b""


def test_fragment_plan_accepts_a_dissected_dns_packet():
    pkts = dns_flow()
    frags = make_slow_fragments(transport_payload(pkts[0]), 8)
    out = fragment_plan_to_packets(pkts, frags, 0)
    assert len(out) == 2
    assert all(Raw in f for f in out)


# ---------- integration: split_slow must actually mutate DNS ------------------

def test_split_slow_fragments_a_dns_flow_instead_of_no_op():
    pkts = dns_flow()
    out = apply_mech(pkts, "split_slow", client_ip=CIP, ownership="both")
    assert len(out) > len(pkts), "split_slow was a no-op on the DNS flow"
    assert any(int(p[IP].flags) & 1 for p in out if IP in p)


def test_eval_path_mutate_client_only_also_fragments_dns():
    pkts = dns_flow()
    out = mutate_client_only(pkts, "split_slow", CIP, ownership="both")
    assert len(out) > len(pkts), "eval path was a no-op on the DNS flow"


def test_split_slow_on_dns_keeps_the_byte_equality_bar():
    pkts = dns_flow()
    out = apply_mech(pkts, "split_slow", client_ip=CIP, ownership="both")
    assert len(out) > len(pkts)
    assert bytes_equal_semantics(pkts, out, CIP) is True


def test_tcp_still_works_regression():
    pkts = tcp_flow()
    out = apply_mech(pkts, "split_slow", client_ip=CIP, ownership="both")
    assert len(out) > len(pkts)
    assert bytes_equal_semantics(pkts, out, CIP) is True