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


# ---------------------------------------------------------------------------
# The ONE semantics bar, shared by training and evaluation (Fix 3).
# ---------------------------------------------------------------------------
# Training and the honest evaluation MUST decide "was the C2 command
# preserved?" by the same rule, or the reward optimises for something the
# metric scores as zero.  The rule is byte equality of the reassembled CLIENT
# stream: the attacker owns the client side only, and a parser that tolerates
# extra bytes (e.g. an unknown HTTP header) is too loose to certify a real
# evasion.  Both sides import these from here.
#
# The bot (the endpoint whose bytes the attacker owns) is the endpoint in the
# 147.32.84.0/24 honeynet when one is present; the flow's 5-tuple initiator is
# NOT always the bot, because neris C2 flows are captured in both directions.
HOME_NET_PREFIX = "147.32.84."


def client_ip_of(flow_id: str) -> str:
    """The attacker-controlled (bot) IP for a flow.

    The flow id is ``capture|src:sport->dst:dport|proto``.  The bot is the
    endpoint in ``HOME_NET_PREFIX`` when one is present; otherwise fall back to
    the flow initiator, which is the attacker for ordinary client-initiated
    C2 traffic.
    """
    endpoint = flow_id.split("|")[1]
    src = endpoint.split("->")[0].split(":")[0]
    dst = endpoint.split("->")[1].split(":")[0]
    for ip in (src, dst):
        if ip.startswith(HOME_NET_PREFIX):
            return ip
    return src


def client_ip_of_packets(packets: Sequence) -> Optional[str]:
    """Best-effort client IP from the packets alone (same rule as flow ids).

    Used where only the packet list is available.  The env passes the flow id's
    client IP explicitly so it is identical to the evaluation's; this fallback
    is for diagnostic callers that have no flow id.
    """
    from scapy.all import IP

    srcs = [p[IP].src for p in packets if IP in p]
    for ip in srcs:
        if ip.startswith(HOME_NET_PREFIX):
            return ip
    return srcs[0] if srcs else None


def reassembled_client_bytes(packets: Sequence, client_ip: str) -> bytes:
    """The client command stream a handler recovers: client payloads joined.

    A run of consecutive IP fragments is reassembled by offset before joining,
    so fragmentation -- which preserves every byte -- compares equal to the
    original, while a byte-flip or an inserted byte does not.  Grouping by a
    run rather than by IP id is deliberate: captured traffic reuses IP ids
    (often 0) across unrelated packets, so id-keyed grouping would silently
    merge distinct payloads.
    """
    from scapy.all import IP, Raw

    def _is_frag(p) -> bool:
        return int(p[IP].frag) != 0 or bool(int(p[IP].flags) & 0x1)

    stream = [p for p in packets
              if IP in p and Raw in p and p[IP].src == client_ip
              and len(bytes(p[Raw].load)) > 0]

    parts: List[bytes] = []
    j = 0
    while j < len(stream):
        p = stream[j]
        if _is_frag(p):
            gid = int(p[IP].id)
            # Collect the run of same-id fragments, splitting at every
            # offset-0 fragment.  Captured traffic reuses IP ids (usually 0)
            # across unrelated packets, so two packets' fragments can be
            # adjacent with the same id; the offset-0 boundary is what keeps
            # them from being merged into one bogus payload.
            cur: List[tuple] = []
            while j < len(stream) and _is_frag(stream[j]) \
                    and int(stream[j][IP].id) == gid:
                off = int(stream[j][IP].frag) * 8
                data = bytes(stream[j][Raw].load)
                if off == 0 and cur:
                    cur.sort(key=lambda t: t[0])
                    parts.append(b"".join(d for _o, d in cur))
                    cur = []
                cur.append((off, data))
                j += 1
            if cur:
                cur.sort(key=lambda t: t[0])
                parts.append(b"".join(d for _o, d in cur))
        else:
            parts.append(bytes(p[Raw].load))
            j += 1
    return b"".join(parts)


def bytes_equal_semantics(original_packets: Sequence, mutated_packets: Sequence,
                          client_ip: str) -> bool:
    """True iff the recovered CLIENT stream is byte-for-byte identical.

    This is the single strict bar (Fix 3).  Training's reward and the honest
    evaluation both call it, so a mechanism the reward treats as
    semantics-preserving is exactly one the evaluation will too.
    """
    return (reassembled_client_bytes(original_packets, client_ip)
            == reassembled_client_bytes(mutated_packets, client_ip))
