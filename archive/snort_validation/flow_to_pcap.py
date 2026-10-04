#!/usr/bin/env python3
"""
Synthesize pcap files from flow-level metadata (6 features).
Given: dur, tot_pkts, tot_bytes, src_bytes, proto, state
Output: pcap file with packets that match those flow statistics.
"""
import math
import random
from pathlib import Path
from scapy.all import IP, TCP, UDP, ICMP, wrpcap


def synthesize_flow_pcap(
    flow_features: dict,
    src_ip: str = "192.168.1.100",
    dst_ip: str = "10.0.0.50",
    src_port: int = None,
    dst_port: int = None,
    output_path: Path = None
) -> Path:
    """
    Synthesize a pcap matching the given flow features.
    
    Args:
        flow_features: dict with keys: dur, tot_pkts, tot_bytes, src_bytes, proto, state
        src_ip, dst_ip: IP addresses for the flow
        src_port, dst_port: port numbers (randomized if None)
        output_path: where to save the pcap (auto-generated if None)
    
    Returns:
        Path to the generated pcap file
    """
    dur = flow_features.get('dur', 1.0)
    tot_pkts = int(flow_features.get('tot_pkts', 10))
    tot_bytes = int(flow_features.get('tot_bytes', 1000))
    src_bytes = int(flow_features.get('src_bytes', 500))
    proto = flow_features.get('proto', 'tcp')
    state = flow_features.get('state', 'FIN')
    
    # Ensure minimum viable values
    tot_pkts = max(tot_pkts, 2)  # at least SYN + something
    tot_bytes = max(tot_bytes, tot_pkts * 40)  # min IP+TCP header = 40 bytes
    src_bytes = min(src_bytes, tot_bytes - 40)  # leave room for response
    
    dst_bytes = tot_bytes - src_bytes
    
    if src_port is None:
        src_port = random.randint(49152, 65535)
    if dst_port is None:
        dst_port = random.choice([80, 443, 8080, 53, 22, 21])
    
    packets = []
    
    if proto.lower() == 'tcp':
        packets = _synthesize_tcp_flow(
            src_ip, dst_ip, src_port, dst_port, 
            tot_pkts, src_bytes, dst_bytes, state, dur
        )
    elif proto.lower() == 'udp':
        packets = _synthesize_udp_flow(
            src_ip, dst_ip, src_port, dst_port,
            tot_pkts, src_bytes, dst_bytes, dur
        )
    elif proto.lower() == 'icmp':
        packets = _synthesize_icmp_flow(
            src_ip, dst_ip, tot_pkts, tot_bytes, dur
        )
    else:
        # Fallback: generic UDP
        packets = _synthesize_udp_flow(
            src_ip, dst_ip, src_port or 12345, dst_port or 54321,
            tot_pkts, src_bytes, dst_bytes, dur
        )
    
    if output_path is None:
        output_path = Path(f"flow_{random.randint(1000, 9999)}.pcap")
    
    wrpcap(str(output_path), packets)
    return output_path


def _chunk_bytes(total_bytes: int, max_chunk: int) -> list:
    """
    Split `total_bytes` into chunk sizes <= max_chunk (e.g. MSS 1460).
    Mimics real TCP segmentation: a bulk transfer produces near-MSS data
    segments plus a short final segment.
    """
    total_bytes = max(int(total_bytes), 0)
    if total_bytes == 0:
        return []
    n_chunks = max(1, math.ceil(total_bytes / max_chunk))
    base = total_bytes // n_chunks
    rem = total_bytes % n_chunks
    return [base + (1 if i < rem else 0) for i in range(n_chunks)]


def _plan_flow_packets(src_bytes: int, dst_bytes: int, tot_pkts: int, max_chunk: int, orig_tot_pkts: int):
    """
    Build a packet plan [(dir, payload_size), ...] with exactly `tot_pkts`
    entries whose payload sums to src_bytes+dst_bytes (approx; control packets
    carry 0 payload).

    Data packets carry chunky near-MSS payloads; the remaining packet budget
    is filled with control packets (0 payload). If the byte volume alone
    exceeds the packet budget, chunks are merged so the count matches.
    """
    src_chunks = _chunk_bytes(src_bytes, max_chunk)
    dst_chunks = _chunk_bytes(dst_bytes, max_chunk)
    data = [("src", s) for s in src_chunks] + [("dst", s) for s in dst_chunks]

    if len(data) <= tot_pkts:
        # Fill remainder with control packets (0 payload)
        plan = data + [("ctrl", 0)] * (tot_pkts - len(data))
    else:
        # Bytes demand more packets than available: merge into tot_pkts.
        # (Edge case — very few packets carrying unusual byte volume.)
        plan = []
        src_total = sum(s for d, s in data if d == "src")
        dst_total = sum(s for d, s in data if d == "dst")
        n_src = max(1, int(tot_pkts * src_total / max(src_total + dst_total, 1)))
        n_dst = tot_pkts - n_src
        if n_src > 0:
            plan += [("src", src_total // n_src + (1 if i < src_total % n_src else 0)) for i in range(n_src)]
        if n_dst > 0:
            plan += [("dst", dst_total // n_dst + (1 if i < dst_total % n_dst else 0)) for i in range(n_dst)]
    return plan


def _synthesize_tcp_flow(src_ip, dst_ip, sport, dport, tot_pkts, src_bytes, dst_bytes, state, dur):
    """Generate TCP flow packets (realistic bulk-transfer segmentation)."""
    packets = []
    time_offset = 0.0
    time_step = dur / max(tot_pkts - 1, 1) if tot_pkts > 1 else 0.0

    # --- Handshake (SYN / SYN-ACK / ACK) up to 3 control packets ---
    # Data packets carry chunky payloads; the rest are control.
    plan = _plan_flow_packets(src_bytes, dst_bytes, max(tot_pkts - 3, 0), 1460, tot_pkts)
    n_handshake = max(0, tot_pkts - len(plan))
    n_handshake = min(n_handshake, 3)

    seq_src = 1000
    seq_dst = 2000

    if n_handshake >= 1:
        pkt = IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags='S', seq=seq_src)
        pkt.time = time_offset
        packets.append(pkt)
        time_offset += time_step

    if n_handshake >= 2:
        pkt = IP(src=dst_ip, dst=src_ip) / TCP(sport=dport, dport=sport, flags='SA', seq=seq_dst, ack=seq_src + 1)
        pkt.time = time_offset
        packets.append(pkt)
        time_offset += time_step
        seq_dst += 1  # SYN consumes one sequence number: server next data seq = 2001

    if n_handshake >= 3:
        pkt = IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags='A', seq=seq_src + 1, ack=seq_dst)
        pkt.time = time_offset
        packets.append(pkt)
        time_offset += time_step
        seq_src += 1  # SYN consumes one sequence number: client next data seq = 1001

    # --- Data + control (from plan) ---
    ack_seq_src = seq_src + 1        # server acks client data: next expected after seq_src
    ack_seq_dst = seq_dst            # client acks server data: next expected == seq_dst
    for direction, payload_size in plan:
        if direction == "src":
            payload = b'X' * payload_size if payload_size > 0 else b''
            pkt = IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags='PA', seq=seq_src, ack=ack_seq_dst)
            if payload:
                pkt = pkt / payload
            packets.append(pkt)
            seq_src += payload_size
            ack_seq_src = seq_src
        elif direction == "dst":
            payload = b'Y' * payload_size if payload_size > 0 else b''
            pkt = IP(src=dst_ip, dst=src_ip) / TCP(sport=dport, dport=sport, flags='PA', seq=seq_dst, ack=ack_seq_src)
            if payload:
                pkt = pkt / payload
            packets.append(pkt)
            seq_dst += payload_size
            ack_seq_dst = seq_dst
        else:  # control
            pkt = IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags='A', seq=seq_src, ack=ack_seq_dst)
            pkt.time = time_offset
            packets.append(pkt)
        pkt.time = time_offset
        time_offset += time_step

    # FIN if the flow state indicates a completed connection
    if 'FIN' in state.upper() or 'CLOSE' in state.upper():
        if len(packets) < tot_pkts:
            pkt = IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags='FA', seq=seq_src, ack=seq_dst)
            pkt.time = time_offset
            packets.append(pkt)
            time_offset += time_step
        if len(packets) < tot_pkts:
            pkt = IP(src=dst_ip, dst=src_ip) / TCP(sport=dport, dport=sport, flags='FA', seq=seq_dst, ack=seq_src + 1)
            pkt.time = time_offset
            packets.append(pkt)

    return packets[:tot_pkts]


def _synthesize_udp_flow(src_ip, dst_ip, sport, dport, tot_pkts, src_bytes, dst_bytes, dur):
    """Generate UDP flow packets (no control packets — every datagram is data)."""
    packets = []
    time_offset = 0.0
    time_step = dur / max(tot_pkts - 1, 1) if tot_pkts > 1 else 0.0

    plan = _plan_flow_packets(src_bytes, dst_bytes, tot_pkts, 1472, tot_pkts)
    for direction, payload_size in plan:
        if direction == "src":
            payload = b'A' * payload_size
            pkt = IP(src=src_ip, dst=dst_ip) / UDP(sport=sport, dport=dport) / payload
        elif direction == "dst":
            payload = b'B' * payload_size
            pkt = IP(src=dst_ip, dst=src_ip) / UDP(sport=dport, dport=sport) / payload
        else:
            # UDP has no ACK; emit a tiny keep-alive datagram for the budget
            pkt = IP(src=src_ip, dst=dst_ip) / UDP(sport=sport, dport=dport) / b'A'
        pkt.time = time_offset
        packets.append(pkt)
        time_offset += time_step

    return packets[:tot_pkts]


def _synthesize_icmp_flow(src_ip, dst_ip, tot_pkts, tot_bytes, dur):
    """Generate ICMP flow packets."""
    packets = []
    time_offset = 0.0
    time_step = dur / max(tot_pkts - 1, 1) if tot_pkts > 1 else 0.0
    
    payload_per_pkt = (tot_bytes - 28 * tot_pkts) // max(tot_pkts, 1)  # IP+ICMP header ~28
    payload_per_pkt = max(0, min(payload_per_pkt, 1472))
    
    for i in range(tot_pkts):
        payload = b'P' * payload_per_pkt
        if i % 2 == 0:
            pkt = IP(src=src_ip, dst=dst_ip) / ICMP(type=8, code=0) / payload  # Echo request
        else:
            pkt = IP(src=dst_ip, dst=src_ip) / ICMP(type=0, code=0) / payload  # Echo reply
        pkt.time = time_offset
        packets.append(pkt)
        time_offset += time_step
    
    return packets[:tot_pkts]


if __name__ == "__main__":
    # Quick test
    test_flow = {
        'dur': 5.2,
        'tot_pkts': 25,
        'tot_bytes': 3500,
        'src_bytes': 2000,
        'proto': 'tcp',
        'state': 'FIN'
    }
    
    output = synthesize_flow_pcap(test_flow, output_path=Path("test_flow.pcap"))
    print(f"Generated test pcap: {output}")
