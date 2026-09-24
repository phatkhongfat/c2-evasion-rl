#!/usr/bin/env python3
"""
Synthesize pcap files from flow-level metadata (6 features).
Given: dur, tot_pkts, tot_bytes, src_bytes, proto, state
Output: pcap file with packets that match those flow statistics.
"""
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


def _synthesize_tcp_flow(src_ip, dst_ip, sport, dport, tot_pkts, src_bytes, dst_bytes, state, dur):
    """Generate TCP flow packets."""
    packets = []
    time_offset = 0.0
    time_step = dur / max(tot_pkts - 1, 1) if tot_pkts > 1 else 0.0
    
    # SYN
    pkt = IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags='S', seq=1000)
    pkt.time = time_offset
    packets.append(pkt)
    time_offset += time_step
    
    # SYN-ACK
    if tot_pkts > 1:
        pkt = IP(src=dst_ip, dst=src_ip) / TCP(sport=dport, dport=sport, flags='SA', seq=2000, ack=1001)
        pkt.time = time_offset
        packets.append(pkt)
        time_offset += time_step
    
    # ACK
    if tot_pkts > 2:
        pkt = IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags='A', seq=1001, ack=2001)
        pkt.time = time_offset
        packets.append(pkt)
        time_offset += time_step
    
    # Data packets: distribute remaining packets and bytes
    remaining_pkts = tot_pkts - len(packets)
    if remaining_pkts > 0:
        # Split between src→dst and dst→src roughly by byte ratio
        src_pkt_count = max(1, int(remaining_pkts * src_bytes / max(src_bytes + dst_bytes, 1)))
        dst_pkt_count = remaining_pkts - src_pkt_count
        
        src_payload_per_pkt = src_bytes // max(src_pkt_count, 1) if src_pkt_count > 0 else 0
        dst_payload_per_pkt = dst_bytes // max(dst_pkt_count, 1) if dst_pkt_count > 0 else 0
        
        seq_src = 1001
        seq_dst = 2001
        
        for i in range(src_pkt_count):
            payload_size = min(src_payload_per_pkt, 1460)  # MSS limit
            payload = b'X' * payload_size
            pkt = IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags='PA', seq=seq_src, ack=seq_dst) / payload
            pkt.time = time_offset
            packets.append(pkt)
            seq_src += payload_size
            time_offset += time_step
        
        for i in range(dst_pkt_count):
            payload_size = min(dst_payload_per_pkt, 1460)
            payload = b'Y' * payload_size
            pkt = IP(src=dst_ip, dst=src_ip) / TCP(sport=dport, dport=sport, flags='PA', seq=seq_dst, ack=seq_src) / payload
            pkt.time = time_offset
            packets.append(pkt)
            seq_dst += payload_size
            time_offset += time_step
    
    # FIN handshake if state indicates completed connection
    if 'FIN' in state.upper() or 'CLOSE' in state.upper():
        if len(packets) < tot_pkts:
            pkt = IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags='FA', seq=seq_src, ack=seq_dst)
            pkt.time = time_offset
            packets.append(pkt)
            time_offset += time_step
        
        if len(packets) < tot_pkts:
            pkt = IP(src=dst_ip, dst=src_ip) / TCP(sport=dport, dport=sport, flags='FA', seq=seq_dst, ack=seq_src+1)
            pkt.time = time_offset
            packets.append(pkt)
    
    # Trim to exact packet count
    return packets[:tot_pkts]


def _synthesize_udp_flow(src_ip, dst_ip, sport, dport, tot_pkts, src_bytes, dst_bytes, dur):
    """Generate UDP flow packets."""
    packets = []
    time_offset = 0.0
    time_step = dur / max(tot_pkts - 1, 1) if tot_pkts > 1 else 0.0
    
    src_pkt_count = max(1, int(tot_pkts * src_bytes / max(src_bytes + dst_bytes, 1)))
    dst_pkt_count = tot_pkts - src_pkt_count
    
    src_payload_per_pkt = src_bytes // max(src_pkt_count, 1) if src_pkt_count > 0 else 0
    dst_payload_per_pkt = dst_bytes // max(dst_pkt_count, 1) if dst_pkt_count > 0 else 0
    
    for i in range(src_pkt_count):
        payload_size = min(src_payload_per_pkt, 1472)  # typical UDP max without fragmentation
        payload = b'A' * payload_size
        pkt = IP(src=src_ip, dst=dst_ip) / UDP(sport=sport, dport=dport) / payload
        pkt.time = time_offset
        packets.append(pkt)
        time_offset += time_step
    
    for i in range(dst_pkt_count):
        payload_size = min(dst_payload_per_pkt, 1472)
        payload = b'B' * payload_size
        pkt = IP(src=dst_ip, dst=src_ip) / UDP(sport=dport, dport=sport) / payload
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
