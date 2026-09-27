import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "snort_validation"))

from endpoint_model import parse_command, FRAMINGS


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
    assert set(FRAMINGS) == {"http", "irc", "length2"}
