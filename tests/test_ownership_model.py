#!/usr/bin/env python3
"""Two-sided ownership model (attacker owns the C2 server too).

ownership="client" (default) = the conservative model, unchanged.
ownership="both" = a mechanism may rewrite BOTH endpoints' packets, and the
Fix-3 byte-equality bar then guards BOTH recovered streams.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path("/root/.hermes/c2-evasion-rl")
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))

from scapy.all import IP, Raw, TCP  # noqa: E402

from c2_semantics import bytes_equal_semantics  # noqa: E402
from eval_pipeline import mutate_client_only  # noqa: E402
from hidden_defender_env import apply_mech  # noqa: E402


def _bidirectional_flow():
    """client 10.0.0.1 <-> server 10.0.0.2, both sides carry payloads."""
    pkts = [
        IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=4444, flags="S"),
        IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=4444, dport=1234, flags="SA"),
        IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=4444, flags="A"),
        IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=4444, flags="PA")
        / Raw(load=b"C" * 200),
        IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=4444, dport=1234, flags="PA")
        / Raw(load=b"S" * 200),
    ]
    return pkts, "10.0.0.1", "10.0.0.2"


def test_bar_rejects_server_side_byte_change():
    """A 1-byte change on the SERVER stream must fail the bar even though the
    client stream is untouched (fails before Phase 1: bar is client-only)."""
    pkts, cip, sip = _bidirectional_flow()
    mut = [p.copy() for p in pkts]
    for p in mut:
        if IP in p and p[IP].src == sip and Raw in p:
            p[Raw].load = b"X" + bytes(p[Raw].load)[1:]
    assert bytes_equal_semantics(pkts, mut, cip) is False


def test_bar_accepts_fragmentation_of_server_stream():
    """Fragmentation preserves every byte, so fragmenting the server reply
    must still pass the bar (vacuous pass before Phase 1, meaningful after)."""
    from fragment_ops import fragment_plan_to_packets, split_fragments

    pkts, cip, sip = _bidirectional_flow()
    mut = []
    for idx, p in enumerate(pkts):
        if IP in p and p[IP].src == sip and Raw in p:
            frags = split_fragments(bytes(p[Raw].load), 8)
            mut.extend(fragment_plan_to_packets(pkts, frags, idx))
        else:
            mut.append(p)
    assert bytes_equal_semantics(pkts, mut, cip) is True


def test_apply_mech_client_default_leaves_server_intact():
    pkts, cip, sip = _bidirectional_flow()
    mut = apply_mech(pkts, "split8", cip)          # default ownership="client"
    for p in mut:
        if IP in p and p[IP].src == sip and Raw in p:
            assert bytes(p[Raw].load) == b"S" * 200


def test_apply_mech_both_mutates_server_but_bar_holds():
    pkts, cip, sip = _bidirectional_flow()
    mut = apply_mech(pkts, "split8", cip, ownership="both")
    srv_raw = [p for p in mut if IP in p and p[IP].src == sip and Raw in p]
    assert len(srv_raw) >= 2                       # 200-byte reply fragmented
    assert bytes_equal_semantics(pkts, mut, cip) is True


def test_mutate_client_only_both_mutates_server():
    pkts, cip, sip = _bidirectional_flow()
    mut = mutate_client_only(pkts, "split8", cip, ownership="both")
    srv_raw = [p for p in mut if IP in p and p[IP].src == sip and Raw in p]
    assert len(srv_raw) >= 2


def test_invalid_ownership_rejected():
    pkts, cip, _sip = _bidirectional_flow()
    with pytest.raises(ValueError):
        apply_mech(pkts, "split8", cip, ownership="peer")
    with pytest.raises(ValueError):
        mutate_client_only(pkts, "split8", cip, ownership="peer")


def test_eval_cli_exposes_ownership_flag():
    r = subprocess.run(
        [sys.executable, str(REPO / "ai_agent" / "eval_fixed_pipeline.py"), "--help"],
        capture_output=True, text=True, timeout=180)
    assert "--ownership" in r.stdout


def test_train_cli_exposes_ownership_flag():
    r = subprocess.run(
        [sys.executable, str(REPO / "ai_agent" / "train_hidden_defender_ppo.py"), "--help"],
        capture_output=True, text=True, timeout=180)
    assert "--ownership" in r.stdout
