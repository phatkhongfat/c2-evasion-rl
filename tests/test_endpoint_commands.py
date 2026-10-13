"""D7: the endpoint model must read pipelined HTTP requests per Content-Length.

_parse_http treats everything after the first CRLFCRLF as the body, so on a
pipelined stream request 2 lands verbatim inside request 1's "command" and a
protocol-legal mutation of request 2's header names fails the bar even though
a real handler recovers both commands intact.  parse_commands splits by
Content-Length (RFC 7230 s3.3.3 / s6.3.2) and compares per-request commands.
v1 parse_command is untouched; this is an ADDITIONAL bar key.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "snort_validation"))
sys.path.insert(0, str(ROOT / "ai_agent"))

from scapy.all import Ether, IP, TCP, Raw  # noqa: E402
from endpoint_model import parse_command, parse_commands  # noqa: E402

REQ1 = (b"POST /getjson HTTP/1.1\r\nAccept: */*\r\nContent-Length: 6\r\n\r\n"
        b"data=1")
REQ2 = (b"POST /getjson HTTP/1.1\r\nAccept: */*\r\nContent-Length: 6\r\n\r\n"
        b"data=2")
PIPELINED = REQ1 + REQ2


def test_parse_commands_splits_pipelined_requests():
    cmds = parse_commands(PIPELINED, "http")
    assert cmds == [b"data=1", b"data=2"]


GET1 = (b"GET /list.php?c=AAAA&v=2 HTTP/1.0\r\nHost: h\r\n"
        b"User-Agent: Mozilla/4.0\r\n\r\n")
GET2 = (b"GET /list.php?c=BBBB&v=2 HTTP/1.0\r\nHost: h\r\n"
        b"User-Agent: Mozilla/4.0\r\n\r\n")


def test_parse_commands_two_bodyless_gets_are_two_requests():
    # RFC 7230 s3.3.3: a request with no Content-Length has a zero-length body,
    # so what follows the header block is the NEXT request, not this one's body.
    assert parse_commands(GET1 + GET2, "http") == [b"/list.php?c=AAAA&v=2",
                                                   b"/list.php?c=BBBB&v=2"]


def test_parse_commands_cl_less_post_still_owns_rest():
    # Methods that CAN carry a body keep the v1 semantics without CL: the
    # request owns the rest of the stream (fail-safe toward v1, not v2).
    post = b"POST /a HTTP/1.1\r\nHost: h\r\n\r\npayload-bytes"
    assert parse_commands(post, "http") == [b"payload-bytes"]


def test_parse_commands_get_then_truncated_get_fails_closed():
    assert parse_commands(GET1 + b"GET /list.p", "http") is None


def test_parse_commands_single_bodyless_get_unchanged():
    assert parse_commands(GET1, "http") == [b"/list.php?c=AAAA&v=2"]


def test_parse_commands_v1_sees_both_requests_in_one_body():
    # document the v1 defect this bar fixes: one "command" containing req 2
    c = parse_command(PIPELINED, "http")
    assert c == b"data=1" + REQ2


def test_parse_commands_case_folded_headers_preserve_commands():
    folded = PIPELINED.replace(b"Accept:", b"accept:").replace(
        b"Content-Length:", b"content-length:")
    assert parse_commands(folded, "http") == parse_commands(PIPELINED, "http")


def test_parse_commands_bodyless_get_returns_path():
    raw = b"GET /a.php?x=1 HTTP/1.0\r\nHost: h\r\n\r\n"
    assert parse_commands(raw, "http") == [b"/a.php?x=1"]


def test_parse_commands_no_content_length_keeps_v1_rest_as_body():
    raw = b"POST /p HTTP/1.0\r\nHost: h\r\n\r\nbody-without-cl"
    assert parse_commands(raw, "http") == [b"body-without-cl"]


def test_parse_commands_truncated_body_fails_closed():
    raw = (b"POST /p HTTP/1.0\r\nContent-Length: 99\r\n\r\nshort")
    assert parse_commands(raw, "http") is None


def test_parse_commands_non_http_delegates_to_v1():
    raw = b"neris1:x"
    assert parse_commands(raw, "neris") == [raw]
    assert parse_commands(b"junk", "neris") is None


def test_endpoint_commands_preserved_on_pipelined_case_fold():
    from c2_semantics import endpoint_commands_preserved
    cip = "147.32.84.165"

    def pkt(load, seq):
        return (Ether() / IP(src=cip, dst="8.8.8.8")
                / TCP(sport=1024, dport=80, seq=seq, flags="PA") / Raw(load=load))

    orig = [pkt(REQ1, 1), pkt(REQ2, 1 + len(REQ1))]
    mut = [pkt(REQ1.replace(b"Accept:", b"accept:").replace(
                 b"Content-Length:", b"content-length:"), 1),
           pkt(REQ2.replace(b"Accept:", b"accept:").replace(
               b"Content-Length:", b"content-length:"), 1 + len(REQ1))]
    assert endpoint_commands_preserved(orig, mut, cip) is True


def test_endpoint_commands_preserved_rejects_changed_body():
    from c2_semantics import endpoint_commands_preserved
    cip = "147.32.84.165"

    def pkt(load):
        return (Ether() / IP(src=cip, dst="8.8.8.8")
                / TCP(sport=1024, dport=80, flags="PA") / Raw(load=load))

    orig = [pkt(PIPELINED)]
    mut = [pkt(PIPELINED.replace(b"data=2", b"data=X"))]
    assert endpoint_commands_preserved(orig, mut, cip) is False
