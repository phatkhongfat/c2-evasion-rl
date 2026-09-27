"""Shared scapy packet builders for env tests (no Snort, no pcap needed)."""
from scapy.all import IP, Raw, TCP


def tcp_flow(n_payload: int = 2, pad: int = 0):
    """A TCP flow: 3 handshake packets (no payload) then n_payload data packets.

    Data packets land at indices 3, 4, ... so a test can assert that corrupting
    index 1 (handshake) is a no-op while corrupting index 3 is not.
    """
    pkts = [
        IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80, flags="S"),
        IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=80, dport=1234, flags="SA"),
        IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80, flags="A"),
    ]
    for i in range(n_payload):
        payload = bytes([65 + i] * 100 + [0] * pad)
        pkts.append(IP(src="10.0.0.1", dst="10.0.0.2")
                    / TCP(sport=1234, dport=80, flags="PA") / Raw(load=payload))
    return pkts
