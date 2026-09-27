import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "snort_validation"))

from endpoint_model import parse_command, detect_framing, FRAMINGS


def test_http_request_line_parsed():
    """A GET with no body: the command is the path."""
    assert parse_command(b"GET /gate.php HTTP/1.1\r\nHost: c2\r\n\r\n", "http") == b"/gate.php"


def test_http_extra_headers_are_ignored():
    """Mechanism A: junk headers, which a real server skips, body untouched.

    Note the padding is in the HEAD, not the body.  Prepending NULs to the body
    is not protocol-aware -- a server would not strip them -- and must be
    rejected, which is what test_garbage_is_rejected covers.
    """
    padded = (
        b"POST /gate.php HTTP/1.1\r\n"
        b"X-Junk-AAAA: 1111111111111111\r\n"
        b"X-Junk-BBBB: 2222222222222222\r\n"
        b"User-Agent: curl/8.0\r\n"
        b"\r\n"
        + b"d1:ad2:id20:b${"
    )
    assert parse_command(padded, "http") == b"d1:ad2:id20:b${"


def test_irc_privmsg_parsed():
    assert parse_command(b"PRIVMSG #c2 :d1:ad2\r\n", "irc") == b"d1:ad2"


def test_length_prefixed_framing():
    """Mechanism B: header declares the offset where real data starts.

    The offset is counted from the first byte after the colon, so the frame
    must actually carry that many padding bytes.
    """
    body = b"d1:ad2:id20:b${"
    frame = b"LEN2:" + b"\x00" * 2 + body + b"\x00" * 8
    assert parse_command(frame, "length2") == body


def test_garbage_is_rejected():
    """A raw prepend is not protocol-aware: the handler must reject it."""
    assert parse_command(b"\x00" * 12 + b"PRIVMSG #c2 :x\r\n", "irc") is None
    assert parse_command(b"\x00" * 12 + b"GET /a HTTP/1.1\r\n\r\n", "http") is None


def test_framings_are_distinct():
    assert set(FRAMINGS) == {"http", "irc", "length2", "neris"}


def test_detect_framing_http():
    assert detect_framing(b"GET /a HTTP/1.1\r\nHost: x\r\n\r\n") == "http"


def test_detect_framing_irc():
    assert detect_framing(b":bot PRIVMSG #c2 :d1:ad2\r\n") == "irc"


def test_detect_framing_length2():
    assert detect_framing(b"LEN2:\x00\x00d1:ad2") == "length2"


NERIS = b"d1:ad2:id20:0123456789abcdefghij:info_hash20:0123456789abcdefghij"


def test_detect_framing_neris_binary():
    """A binary record chain is not HTTP and must not be labelled as such."""
    assert detect_framing(NERIS) == "neris"


def test_neris_chain_parsed():
    assert parse_command(NERIS, "neris") == NERIS


def test_neris_rejects_prefix():
    """Prepending to a record chain breaks the chain: the handler must reject it."""
    assert parse_command(b"\x00" * 12 + NERIS, "neris") is None


def test_neris_treats_trailing_pad_conservatively():
    """Append is *probably* safe for a length-prefixed protocol, but the full
    Neris grammar was not reverse-engineered, so this module refuses to claim
    it.  A protocol we cannot parse gets the byte-exact bar: only mechanisms
    that preserve bytes (fragmentation) count as safe."""
    assert parse_command(NERIS + b"\x00" * 16, "neris") != parse_command(NERIS, "neris")
