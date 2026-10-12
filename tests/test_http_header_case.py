"""http_header_case: lower-case HTTP field NAMES only (RFC 7230 s3.2).

Counterpart to http_header_pad.  It breaks a distance:0 adjacency chain for a
different reason -- the rule matches `Accept|3a 20|` case-SENSITIVELY, and
lowercasing the name moves those bytes out of the match while leaving the
request line and body untouched.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for sub in ("snort_validation", "ai_agent"):
    p = str(ROOT / sub)
    if p not in sys.path:
        sys.path.insert(0, p)

from scapy.all import Ether, IP, TCP, Raw  # noqa: E402
from hidden_defender_env import apply_mech, mech_applicable  # noqa: E402
from endpoint_model import detect_framing, parse_command  # noqa: E402

C, S = "10.0.0.1", "10.0.0.9"
HTTP = (b"POST /getjson HTTP/1.1\r\nAccept: */*\r\nContent-Type: text/plain\r\n"
        b"Host: a.com\r\nContent-Length: 4\r\n\r\ndata=1")


def _pkts(payload):
    return [Ether() / IP(src=C, dst=S) / TCP(sport=1234, dport=80, seq=1, flags="PA")
            / Raw(payload)]


def test_field_names_are_lowercased():
    out = apply_mech(_pkts(HTTP), "http_header_case", C, ownership="both")
    got = bytes(out[0][Raw].load)
    assert b"\r\naccept: */*\r\n" in got
    assert b"\r\nAccept: */*\r\n" not in got
    assert b"\r\ncontent-type: text/plain\r\n" in got


def test_request_line_and_body_untouched():
    out = apply_mech(_pkts(HTTP), "http_header_case", C, ownership="both")
    got = bytes(out[0][Raw].load)
    assert got.startswith(b"POST /getjson HTTP/1.1\r\n")
    assert got.endswith(b"\r\n\r\ndata=1")


def test_command_is_unchanged_and_non_vacuous():
    out = apply_mech(_pkts(HTTP), "http_header_case", C, ownership="both")
    fr_o, fr_m = detect_framing(HTTP), detect_framing(bytes(out[0][Raw].load))
    assert fr_o == fr_m == "http"
    co, cm = parse_command(HTTP, fr_o), parse_command(bytes(out[0][Raw].load), fr_m)
    assert co is not None and co == cm


def test_non_http_framing_is_inapplicable_and_untouched():
    neris = b"neris2:8:ABCDEFGH"
    assert mech_applicable([neris], "http_header_case") is False
    out = apply_mech(_pkts(neris), "http_header_case", C, ownership="both")
    assert bytes(out[0][Raw].load) == neris


def test_checksums_are_recomputed():
    import socket
    from scapy.all import Ether, IP, TCP, checksum
    from scapy.layers.inet import in4_chksum
    out = apply_mech(_pkts(HTTP), "http_header_case", C, ownership="both")
    # The payload must actually have changed, or this test would pass vacuously
    # (scapy fills valid checksums for an untouched packet too).
    assert b"\r\naccept: */*\r\n" in bytes(out[0][Raw].load)
    # Re-parse the full frame from the wire (IP(bytes(p)) would misparse the
    # Ether header), then recompute both checksums independently.
    raw = Ether(bytes(out[0]))
    ip = raw[IP].copy()
    ip.chksum = 0
    assert raw[IP].chksum == checksum(bytes(ip)[:ip.ihl * 4])
    tcp = raw[TCP].copy()
    tcp.chksum = 0
    assert raw[TCP].chksum == in4_chksum(socket.IPPROTO_TCP, raw[IP], bytes(tcp))
