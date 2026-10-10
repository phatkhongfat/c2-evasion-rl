"""Characterisation tests for overlap8 (O0 diagnostic, 2026-10-10).

Recorded finding: overlap8 can NEVER record a valid evasion under the current
two-stream byte-equality bar, for two DIFFERENT reasons depending on transport:

  * TCP  -- `fragment_plan_to_packets` needs an 8-byte-aligned transport
            header; a 20-byte TCP header is not 8-aligned, so the plan raises
            ValueError, `apply_mech` catches it and keeps the original packet.
            The mechanism is a NO-OP: it never even changes a byte.

  * UDP  -- the mechanism DOES apply (3 packets out), but the packet-level bar
            (`bytes_equal_semantics` -> `reassembled_client_bytes`) reassembles
            fragments by OFFSET within runs split at each offset-0 fragment. It
            does NOT model arrival-order policy resolution, so the decoy at
            offset 0 and the real head at offset 0 land in different runs and
            the recovered stream != original. Bar rejects it.

Both are locked here so neither can silently drift. These tests assert CURRENT
behaviour, not desired behaviour.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "snort_validation"))
sys.path.insert(0, str(ROOT / "ai_agent"))

from scapy.all import IP, Raw, TCP, UDP, Ether                # noqa: E402
from c2_semantics import (assemble, semantics_preserved,      # noqa: E402
                          bytes_equal_semantics)
from fragment_ops import overlap_fragments                    # noqa: E402
from hidden_defender_env import apply_mech                    # noqa: E402

PAYLOAD = b"HALLO_FROM_BOT_COMMAND_SEQUENCE_0123456789"
CIP = "10.0.0.1"


def _tcp():
    return Ether() / IP(src=CIP, dst="10.0.0.2") / TCP(
        sport=1234, dport=80, seq=1000) / Raw(PAYLOAD)


def _udp():
    return Ether() / IP(src=CIP, dst="10.0.0.2") / UDP(
        sport=1234, dport=53) / Raw(PAYLOAD)


def test_overlap_separates_views_at_fragment_level():
    """The design intent is sound: policy=first hides the command from Snort,
    policy=last recovers it for the endpoint."""
    frags = overlap_fragments(PAYLOAD, 8)
    assert assemble(frags, "first") != PAYLOAD   # Snort sees the decoy
    assert assemble(frags, "last") == PAYLOAD    # endpoint recovers the command
    assert semantics_preserved(PAYLOAD, frags) is True


def test_overlap8_is_noop_on_tcp():
    """20-byte TCP header is not 8-aligned -> mechanism cannot apply."""
    orig = [_tcp()]
    mut = apply_mech(orig, "overlap8", client_ip=CIP)
    assert len(mut) == 1
    assert bytes(mut[0][Raw].load) == PAYLOAD     # byte-for-byte unchanged


def test_overlap8_applies_on_udp_but_is_rejected_by_the_bar():
    """UDP header IS 8-aligned, so the mechanism applies (3 packets), but the
    packet-level bar rejects it (offset-based reassembly ignores arrival
    order). This is why overlap8 shows 0 valid evasions on UDP flows too."""
    orig = [_udp()]
    mut = apply_mech(orig, "overlap8", client_ip=CIP)
    assert len(mut) == 3                         # it DID apply
    assert bytes_equal_semantics(orig, mut, CIP) is False   # bar says invalid