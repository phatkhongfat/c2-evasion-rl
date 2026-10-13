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

from collections import Counter
from dataclasses import dataclass
from typing import List, Optional, Sequence

POLICIES = ("first", "last")


@dataclass(frozen=True)
class Fragment:
    """A piece of a payload at a byte offset in the reassembled stream."""

    offset: int
    data: bytes
    delay: float = 0.0   # seconds after the previous fragment (split_slow)


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

    srcs = [p[IP].src for p in map(ensure_chain, packets) if IP in p]
    for ip in srcs:
        if ip.startswith(HOME_NET_PREFIX):
            return ip
    return srcs[0] if srcs else None


def _ensure_chain(pkt):
    """The same packet with a genuinely populated scapy layer chain.

    scapy restores a pickled packet lazily: when `scapy.all` was never
    imported in this process the chain comes back empty, every membership test
    (`IP in pkt`, `Raw in pkt`) answers False, and the packet looks like bare
    link-layer framing with no payload at all.  A whole flow then scores as
    EMPTY -- no mechanism runs, every endpoint bar returns False, and nothing
    raises.  Re-dissecting from the wire bytes costs one parse and is only paid
    on that anomalous path.
    """
    from scapy.all import IP
    if IP in pkt:
        return pkt
    raw = bytes(pkt)
    for off in (0, 14):          # bare IP, or Ethernet + IP
        if len(raw) > off and raw[off] >> 4 == 4:
            try:
                return pkt.__class__(raw)
            except Exception:
                return pkt
    return pkt


# Public alias: callers that pre-filter a packet list (mechanisms, ip lookups)
# hit the same lazy-unpickle trap and must normalise before testing membership.
ensure_chain = _ensure_chain


def transport_payload(pkt) -> bytes:
    """Payload bytes of a TCP/UDP packet, whatever scapy dissected it into.

    scapy auto-dissects UDP/53 into a DNS layer, so `Raw in pkt` is False on
    DNS traffic even though the packet carries bytes.  Every mechanism and the
    byte-equality bar used to filter on `Raw in pkt`, which silently dropped
    all 33 DNS flows of the corpus from consideration entirely -- they were
    reported as "not evaded" when the mechanism had never run on them at all.
    Read the transport payload directly so scapy's dissection cannot decide
    whether a packet is mutable or visible.
    """
    from scapy.all import TCP, UDP, Raw, Padding
    pkt = _ensure_chain(pkt)
    if Raw in pkt:
        # Pre-existing convention: read the Raw layer only.  TCP corpus
        # packets carry Raw followed by Padding, and callers depend on
        # padding being invisible here.
        return bytes(pkt[Raw].load)
    for cls in (TCP, UDP):
        if cls in pkt:
            pl = pkt[cls].payload
            if Padding in pl or isinstance(pl, Padding):
                return b""          # filler only, nothing to rewrite
            return bytes(pl)
    return b""


def has_payload(pkt) -> bool:
    """True when the packet carries transport payload worth rewriting."""
    return len(transport_payload(pkt)) > 0


def as_raw(pkt):
    """Collapse the transport payload into a single Raw layer, in place.

    In-place mutators (`corrupt`, `pad`, `http_header_pad`, `length_wrapper`)
    assign to `pkt[Raw].load`, which raises IndexError when scapy dissected
    the payload into a higher layer such as DNS.  Now that has_payload() lets
    those packets through, they must be flattened first or the mutator raises.

    The wire bytes are unchanged: an already-parsed layer re-serialises to
    the same octets it was parsed from, so the byte-equality bar still holds.
    The bar would catch it either way -- a lossy collapse makes a mechanism
    score invalid, never a false evasion.

    No-op when the packet already carries a Raw layer.  That guard matters:
    corpus TCP packets carry Raw followed by Padding, and collapsing those
    would fold the padding into Raw.load and silently change what the
    mutators read and write.
    """
    from scapy.all import TCP, UDP, Raw
    if Raw in pkt:
        return pkt
    for cls in (TCP, UDP):
        if cls in pkt:
            pl = bytes(pkt[cls].payload)
            del pkt[cls].payload
            if pl:
                pkt[cls].add_payload(Raw(load=pl))
            return pkt
    return pkt


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

    stream = [_ensure_chain(p) for p in packets]
    stream = [p for p in stream
              if IP in p and has_payload(p) and p[IP].src == client_ip]

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
                data = transport_payload(stream[j])
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
            parts.append(transport_payload(p))
            j += 1
    return b"".join(parts)


def server_ip_of(packets: Sequence, client_ip: str) -> Optional[str]:
    """The responder address: the other endpoint of the session (the C2
    server side).  Moved here from eval_pipeline so the semantics bar can
    guard the server stream too (two-sided ownership); eval_pipeline
    re-imports it, so external callers are unaffected."""
    from scapy.all import IP

    for p in map(ensure_chain, packets):
        if IP in p and p[IP].src != client_ip:
            return p[IP].src
        if IP in p and p[IP].dst != client_ip:
            return p[IP].dst
    return None


def wire_deliverable(original_packets, mutated_packets) -> bool:
    """True iff `mutated_packets` có thể thực sự đi lên wire và đến endpoint
    với CÙNG bytes:

    * một link type đồng nhất, khớp capture gốc (pcap trộn record Ether với
      record IP trần bị libpcap/Snort từ chối: "Inconsistent linktypes");
    * cấu trúc fragment hợp lệ: offset-0 mang transport header, continuation
      GIỮ nguyên `proto` và không mang transport header;
    * theo từng source IP, multiset IP datagram sau reassembly (offset 8-byte,
      byte đến SAU thắng khi trùng offset — chính sách endpoint phổ biến)
      bằng multiset của bản gốc.

    Đây là gate mà pipeline từng thiếu: bar cũ phục hồi payload bytes trong
    bộ nhớ bằng offset bookkeeping bỏ qua gap, nên nó CẶT CỨU cả fragment
    hỏng mà fragment_plan_to_packets từng sinh ra (không Ether, không L4,
    proto=0) — pcap mà không endpoint nào nhận được vẫn được tính là
    semantics-preserving evasion. Xem tests/test_wire_deliverability.py.
    """
    from scapy.all import IP

    if not original_packets or not mutated_packets:
        return False
    link = type(mutated_packets[0])
    if link is not type(original_packets[0]):
        return False
    if any(type(p) is not link for p in mutated_packets):
        return False

    def _is_frag(ip):
        return int(ip.frag) != 0 or bool(int(ip.flags) & 0x1)

    def _datagrams(packets):
        """-> {src_ip: Counter(datagram_bytes)} hoặc None nếu không phục hồi nổi."""
        acc = {}
        i, n = 0, len(packets)
        while i < n:
            p = packets[i]
            if IP not in p:
                i += 1
                continue
            ip = p[IP]
            if not _is_frag(ip):
                acc.setdefault(ip.src, Counter())[bytes(ip.payload)] += 1
                i += 1
                continue
            # một dãy fragment (cắt tại fragment offset-0 kế tiếp, cùng id/src/dst)
            gid, gsrc, gdst = int(ip.id), ip.src, ip.dst
            run = []
            while i < n and IP in packets[i]:
                q = packets[i][IP]
                if (not _is_frag(q) or int(q.id) != gid
                        or q.src != gsrc or q.dst != gdst):
                    break
                if int(q.frag) == 0 and run:
                    break
                run.append(packets[i])
                i += 1
            buf, cleared_end = bytearray(), -1
            for r in run:
                rip = r[IP]
                off = int(rip.frag) * 8
                chunk = bytes(rip.payload)     # IP payload = TH + data
                if not chunk:
                    return None                # fragment rỗng: không hợp lệ
                if off > len(buf):
                    return None                # có gap: không phục hồi nổi
                end = off + len(chunk)
                if end > len(buf):
                    buf.extend(chunk[len(buf) - off:])
                else:
                    buf[off:end] = chunk       # trùng offset: byte sau thắng
                if not (int(rip.flags) & 0x1):
                    cleared_end = max(cleared_end, end)
            if cleared_end != len(buf):
                return None                    # dãy fragment không kết thúc trọn vẹn
            acc.setdefault(gsrc, Counter())[bytes(buf)] += 1
        return acc

    a = _datagrams(original_packets)
    b = _datagrams(mutated_packets)
    if a is None or b is None:
        return False
    if a.keys() != b.keys():
        return False
    return all(a[k] == b[k] for k in a)


def _has_unreadable_ip_family(packets: Sequence) -> bool:
    """True when a capture carries an IP family this bar cannot compare.

    The recovery and datagram paths both key on scapy's ``IP`` layer, which is
    IPv4-only.  An IPv6 capture is therefore invisible to them: it recovers
    ``b""`` on BOTH sides and compares equal no matter what its payloads are.
    A mechanism that cannot be SHOWN byte-preserving must not be COUNTED as
    byte-preserving, so such a capture is unverifiable and the bar must reject
    it.  Deliberately narrow: only IPv6 (the other IP family scapy models) is
    flagged -- a non-IP frame such as ARP carries no payload the bar was ever
    meant to compare and stays ignored, so the guard does not blanket-reject
    every packet without an ``IP`` layer.
    """
    from scapy.all import IPv6

    return any(IPv6 in p for p in packets)


def bytes_equal_semantics(original_packets: Sequence, mutated_packets: Sequence,
                          client_ip: str) -> bool:
    """True iff BOTH recovered streams are byte-for-byte identical
    in BOTH directions **and** the mutated capture is wire-deliverable
    (wire_deliverable). Checked BEFORE assembly so a capture no endpoint
    could ever reassemble can never pass the bar.
    """
    # Fail closed on a capture the bar cannot compare.  Checked first, on the
    # ORIGINAL as well as the mutation, so a mutation cannot smuggle an
    # unreadable IP family past the bar by leaving the original IPv4.
    if _has_unreadable_ip_family(original_packets) \
            or _has_unreadable_ip_family(mutated_packets):
        return False
    if not wire_deliverable(original_packets, mutated_packets):
        return False
    if (reassembled_client_bytes(original_packets, client_ip)
            != reassembled_client_bytes(mutated_packets, client_ip)):
        return False
    sip = server_ip_of(original_packets, client_ip)
    if sip is None:
        return True
    return (reassembled_client_bytes(original_packets, sip)
            == reassembled_client_bytes(mutated_packets, sip))


def endpoint_command_preserved(original_packets: Sequence,
                               mutated_packets: Sequence,
                               client_ip: str) -> bool:
    """True iff a real C2 handler recovers the SAME command from both streams.

    The SECOND declared bar, applied identically to every mechanism.  Where
    ``bytes_equal_semantics`` asks "is the wire identical", this asks "does the
    endpoint still understand the channel" -- the question a protocol-legal
    mutation (an unknown HTTP header, a case-folded field name) has to answer.
    A server ignores an unknown header, so prepending one changes the wire bytes
    without changing the command; the byte bar rejects that, this one certifies
    it.  Both verdicts are reported side by side; this is ADDITIONAL, never a
    replacement, so old reports stay comparable (c2_semantics.py:127 -- training
    and evaluation share ONE rule).

    Fails CLOSED, and deliberately does NOT reuse ``wire_deliverable``.  That
    helper is the BYTE bar's gate: ``_datagrams`` compares the reassembled
    datagram multiset for byte-equality, so gating here would reject exactly the
    protocol-legal mutations this bar exists to certify (an inserted ``X-Pad``
    header yields a different datagram).  ``bytes_equal_semantics`` still applies
    it; the endpoint bar answers the orthogonal question.

    Three fail-closed paths, each load-bearing:

    * an IP family the recovery cannot read (IPv6) is unverifiable -> reject,
      mirroring ``bytes_equal_semantics`` and commit ed6fb8d;
    * ``detect_framing`` falls back to ``"http"`` for an unlabelled flow and
      ``_parse_http`` then returns ``None`` on a stream it cannot read, so a
      naive implementation compares ``None == None`` and reports a vacuous PASS.
      A bar that cannot READ the original cannot CERTIFY the mutation, so
      ``None`` on the ORIGINAL is a rejection;
    * a mutation the handler can no longer parse (``None``) can never equal a
      real command -> reject.
    """
    from endpoint_model import detect_framing, parse_command

    if _has_unreadable_ip_family(original_packets) \
            or _has_unreadable_ip_family(mutated_packets):
        return False

    orig = reassembled_client_bytes(original_packets, client_ip)
    mut = reassembled_client_bytes(mutated_packets, client_ip)

    framing = detect_framing(orig)
    command = parse_command(orig, framing)
    if command is None:
        return False          # unreadable original -> cannot certify

    mutated_command = parse_command(mut, framing)
    if mutated_command is None:
        return False          # handler reads nothing from the mutation
    return mutated_command == command


def endpoint_commands_preserved(original_packets: Sequence,
                                mutated_packets: Sequence,
                                client_ip: str) -> bool:
    """True iff a real handler recovers the SAME per-request command LIST.

    The D7 fix for pipelined HTTP: v1's endpoint_command_preserved reads the
    whole stream after the first CRLFCRLF as one body, so on a pipelined pair
    of POSTs request 2 lands verbatim inside request 1's "command" and a
    protocol-legal case-fold of request 2's header names fails the bar even
    though a real handler (which reads Content-Length, RFC 7230 s3.3.3)
    recovers both commands intact.  This is an ADDITIONAL verdict, never a
    replacement for v1 -- both are reported side by side.

    Same three fail-closed paths as v1: unreadable IP family -> reject; an
    original the parser cannot read -> reject (cannot certify what you cannot
    read); a mutation that parses to None -> reject.
    """
    from endpoint_model import detect_framing, parse_commands

    if _has_unreadable_ip_family(original_packets) \
            or _has_unreadable_ip_family(mutated_packets):
        return False

    orig = reassembled_client_bytes(original_packets, client_ip)
    mut = reassembled_client_bytes(mutated_packets, client_ip)

    framing = detect_framing(orig)
    commands = parse_commands(orig, framing)
    if commands is None:
        return False          # unreadable original -> cannot certify

    mutated_commands = parse_commands(mut, framing)
    if mutated_commands is None:
        return False          # handler reads nothing from the mutation
    return mutated_commands == commands


def _query_map(pairs) -> dict:
    m: dict = {}
    for k, v in pairs:
        m.setdefault(k, []).append(v)
    return m


def endpoint_query_preserved(original_packets: Sequence,
                             mutated_packets: Sequence,
                             client_ip: str) -> bool:
    """True iff a handler acting on PARSED QUERIES recovers the same commands.

    The D5 bar (citation-gated, ledger [6] RFC 3986 / [7] PHP parse_str):
    for a bodyless HTTP request the handler acts on the key->value pairs of
    its query [6 s3.4, 7], parsed before percent-decoding [6 s2.4].  A
    mutation is preserved iff, per request and in the same order:

    * a request with a body keeps that body byte-identical (the relaxation
      applies ONLY to queries -- the same precedent as the unknown X-Junk
      header: a handler reads what it reads, everything else must be intact);
    * a bodyless request keeps its path;
    * a bodyless query request keeps, for EVERY key the ORIGINAL carried, the
      identical list of decoded values (duplicate-key order significant).
      Extra keys added by the mutation are ignored -- a handler reads the
      keys it knows; an unknown parameter is inert, exactly like an unknown
      header.

    Non-HTTP framings delegate to endpoint_commands_preserved.  Fail-closed
    paths are identical to the other endpoint bars: unreadable IP family,
    unreadable original, unreadable mutation, or a request-count mismatch.
    """
    from endpoint_model import detect_framing, parse_commands_q, parse_commands

    if _has_unreadable_ip_family(original_packets) \
            or _has_unreadable_ip_family(mutated_packets):
        return False

    orig = reassembled_client_bytes(original_packets, client_ip)
    mut = reassembled_client_bytes(mutated_packets, client_ip)

    framing = detect_framing(orig)
    if framing != "http":
        return endpoint_commands_preserved(original_packets, mutated_packets,
                                           client_ip)

    co = parse_commands_q(orig, framing)
    if co is None:
        return False          # unreadable original -> cannot certify
    cm = parse_commands_q(mut, framing)
    if cm is None or len(cm) != len(co):
        return False          # handler reads less/differently -> reject

    for eo, em in zip(co, cm):
        ko, vo = eo[0], eo[1:]
        km, vm = em[0], em[1:]
        if ko != km:
            return False
        if ko in ("body", "path", "raw"):
            if vo != vm:
                return False
        else:                 # ko == "query": (path, pairs)
            if vo[0] != vm[0]:
                return False
            om = _query_map(vo[1])
            mm = _query_map(vm[1])
            for k, vals in om.items():
                if mm.get(k) != vals:
                    return False
    return True
