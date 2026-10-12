"""The byte bar must FAIL CLOSED on a capture it cannot compare.

Root cause (2026-10-12): `bytes_equal_semantics` reassembles IPv4 only.
`reassembled_client_bytes` filters on scapy's `IP` layer (IPv4-only), and
`wire_deliverable._datagrams` skips every packet with no `IP`.  An IPv6
capture therefore recovers ``b""`` on BOTH sides, so two IPv6 captures with
DIFFERENT payloads compared EQUAL -- a fail-OPEN hole in the semantics bar.

The rule: a mechanism that cannot be SHOWN byte-preserving must not be
COUNTED as byte-preserving.  When a capture carries an IP family the bar
cannot read, the verdict is "unverifiable" and the bar must return False.

These tests assert DESIRED behaviour and were RED against the pre-fix bar.
The corpus is 100% IPv4, so this is defensive hardening: no already-reported
number changes.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "snort_validation"))
sys.path.insert(0, str(ROOT / "ai_agent"))

from scapy.all import ARP, Ether, IP, IPv6, Raw, TCP   # noqa: E402
from c2_semantics import (                             # noqa: E402
    bytes_equal_semantics,
    reassembled_client_bytes,
)

CIP = "2001:db8::1"
SIP = "2001:db8::2"
PAYLOAD = b"HALLO_FROM_BOT_COMMAND_SEQUENCE_0123456789"
OTHER = b"TOTALLY_DIFFERENT_PAYLOAD_BYTES_9876543210"


def _ipv6(payload, src=CIP, dst=SIP):
    return [Ether() / IPv6(src=src, dst=dst)
            / TCP(sport=1234, dport=80) / Raw(load=payload)]


def _ipv4(payload, src="10.0.0.1", dst="10.0.0.2"):
    return Ether() / IP(src=src, dst=dst) / TCP(sport=1234, dport=80) \
        / Raw(load=payload)


def test_ipv6_payloads_are_invisible_to_the_ipv4_recovery():
    """Documents the root cause: an IPv6 payload never enters the recovered
    stream, so byte comparison is structurally blind to it."""
    assert reassembled_client_bytes(_ipv6(PAYLOAD), CIP) == b""
    assert reassembled_client_bytes(_ipv6(OTHER), CIP) == b""


def test_ipv6_payload_change_is_not_counted_as_preserved():
    """THE hole: different IPv6 payloads must NOT compare equal."""
    orig = _ipv6(PAYLOAD)
    mut = _ipv6(OTHER)
    assert bytes_equal_semantics(orig, mut, CIP) is False


def test_ipv6_identical_captures_are_unverifiable_and_rejected():
    """Fail closed even when the bytes happen to match: the bar cannot show
    an IPv6 capture byte-preserving, so it must not certify one."""
    cap = _ipv6(PAYLOAD)
    assert bytes_equal_semantics(cap, list(cap), CIP) is False


def test_ipv6_introduced_by_a_mutation_is_rejected():
    """A mutation that turns an IPv4 flow into IPv6 (or adds IPv6 frames)
    must be rejected, not silently ignored."""
    orig = [_ipv4(PAYLOAD)]
    mut = [_ipv4(PAYLOAD), *_ipv6(PAYLOAD)]
    assert bytes_equal_semantics(orig, mut, "10.0.0.1") is False


def test_guard_is_precise_ipv4_with_arp_still_compares():
    """The guard must reject only IP families the bar cannot read -- not every
    packet without an `IP` layer.  A capture with ARP frames (no IP payload)
    around an identical IPv4 flow still compares equal."""
    orig = [_ipv4(PAYLOAD), Ether() / ARP()]
    mut = [_ipv4(PAYLOAD), Ether() / ARP()]
    assert bytes_equal_semantics(orig, mut, "10.0.0.1") is True
