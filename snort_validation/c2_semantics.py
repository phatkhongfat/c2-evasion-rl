#!/usr/bin/env python3
"""Did a mutation preserve the C2 command, or destroy it?

WHY THIS EXISTS
---------------
The trained policy evades real Snort at 96.9% by emitting DROP on the
payload-bearing packets (measured: 372 of 384 actions). The C2 command never
arrives, so nothing is being evaded -- the traffic is just deleted. Any evasion
figure that counts that as success is worthless.

This module decides whether the ORIGINAL payload is still recoverable from the
mutated packet stream under at least one standard endpoint reassembly policy.
An evasion counts only when Snort does not alert AND the command survives.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Sequence

POLICIES = ("first", "last")


@dataclass(frozen=True)
class Fragment:
    """A piece of a payload at a byte offset in the reassembled stream."""

    offset: int
    data: bytes


def assemble(frags: Sequence[Fragment], policy: str = "first") -> bytes:
    """Reassemble fragments, resolving overlaps by arrival order.

    `policy="first"` keeps the earliest-arriving bytes for a region (what Snort
    is configured with: `frag3_engine: policy first`).
    `policy="last"` keeps the latest (common endpoint behaviour).

    Fragments are given in ARRIVAL ORDER, which is what makes the two policies
    differ: the list is not sorted before assembly.
    """
    if policy not in POLICIES:
        raise ValueError(f"unknown policy {policy!r}; expected one of {POLICIES}")
    if not frags:
        return b""

    size = max(f.offset + len(f.data) for f in frags)
    buf: List[Optional[int]] = [None] * size
    # Iterate in ARRIVAL ORDER for both policies; the difference is who wins a
    # contested byte. `first` keeps the earliest writer, `last` lets each later
    # writer overwrite. (Reversing the list for `last` would be wrong: it makes
    # the EARLIEST fragment write last and therefore win, which is the opposite
    # of "last wins".)
    for f in frags:
        for i, byte in enumerate(f.data):
            pos = f.offset + i
            if pos >= size:
                continue
            if policy == "first" and buf[pos] is not None:
                continue          # first writer wins
            buf[pos] = byte       # last writer wins
    # A hole means the stream is not fully reconstructible under this policy.
    if any(b is None for b in buf):
        return b""
    return bytes(b for b in buf if b is not None)


def semantics_preserved(original: bytes,
                        frags: Sequence[Fragment]) -> bool:
    """True when some standard endpoint policy recovers `original` exactly.

    Deliberately generous to the attacker: if EITHER policy recovers the
    original bytes, the command is considered intact. That is the honest bar --
    we cannot know which policy the real endpoint uses, and the evasion claim
    only needs one that works.
    """
    return any(assemble(frags, p) == original for p in POLICIES)


def policy_that_recovers(original: bytes,
                         frags: Sequence[Fragment]) -> Optional[str]:
    """Which policy recovers the original, for reporting. None if neither."""
    for p in POLICIES:
        if assemble(frags, p) == original:
            return p
    return None


def dht_ping_id(payload: bytes) -> Optional[bytes]:
    """Extract the `id` field of a bencoded BitTorrent DHT ping.

    Format: d1:ad2:id20:<20 bytes>e1:q4:ping1:t2:<..>1:y1:qe

    Used to show that a reconstructed payload is not merely byte-identical but
    still parseable as the C2 message it was.
    """
    if not payload.startswith(b"d1:ad2:id20:"):
        return None
    start = len(b"d1:ad2:id20:")
    if len(payload) < start + 20:
        return None
    return payload[start:start + 20]


def reconstructs_command(original: bytes, frags: Sequence[Fragment]) -> bool:
    """Byte-exact recovery AND, for DHT, the command still parses.

    Byte-exactness is the gate; the parse check is a sanity assertion that we
    did not recover the bytes in a form the endpoint would reject.
    """
    if not semantics_preserved(original, frags):
        return False
    policy = policy_that_recovers(original, frags)
    if policy is None:
        return False
    got = assemble(frags, policy)
    if got != original:
        return False
    want_id = dht_ping_id(original)
    if want_id is not None and dht_ping_id(got) != want_id:
        return False
    return True
