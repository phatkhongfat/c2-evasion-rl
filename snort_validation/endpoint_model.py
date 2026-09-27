"""Protocol-aware endpoint model: what a real C2 handler would still read.

The previous `semantics_intact` demanded byte equality of the joined payload
stream.  That is the right bar for IP-layer fragmentation, which preserves
bytes by construction, but it is the wrong bar for padding that a protocol
legitimately tolerates -- a server ignores an unknown `X-Junk` header, so
prepending one changes the wire bytes without changing the command.

This module says explicitly which framing a flow uses and returns the command a
real handler would recover, or None when the handler would reject the stream.
"""

from __future__ import annotations

import re

# IRC: ":nick PRIVMSG #chan :<command>"  (also a bare "PRIVMSG #chan :<cmd>")
_IRC = re.compile(rb"(?:^|\s)PRIVMSG\s+\S+\s+:?(?P<cmd>.*?)\r?\n?$", re.S)

_HTTP_SEP = b"\r\n\r\n"


def _parse_http(raw: bytes) -> bytes | None:
    """Return what a real HTTP handler would act on.

    A body carries the command when present (Neris-style C2 posts it there).
    A request with no body is commanded by its path.  Unknown headers are
    skipped, which is what makes mechanism A legitimate.
    """
    head, sep, body = raw.partition(_HTTP_SEP)
    if not sep:
        return None
    request_line = head.split(b"\r\n")[0]
    parts = request_line.split(b" ")
    if len(parts) < 3 or not parts[0].isalpha():
        return None
    stripped = body.rstrip(b"\x00")
    if stripped:
        return stripped
    return parts[1] or None


def _parse_irc(raw: bytes) -> bytes | None:
    m = _IRC.search(raw)
    if m is None:
        return None
    cmd = m.group("cmd").rstrip(b"\x00")
    return cmd or None


def _parse_length2(raw: bytes) -> bytes | None:
    """Header 'LEN<n>:' marks the byte offset where real data starts."""
    head, sep, rest = raw.partition(b":")
    if not sep or not head.startswith(b"LEN"):
        return None
    try:
        offset = int(head[3:])
    except ValueError:
        return None
    if offset < 0 or offset > len(rest):
        return None
    body = rest[offset:].rstrip(b"\x00")
    return body or None


FRAMINGS = {
    "http": _parse_http,
    "irc": _parse_irc,
    "length2": _parse_length2,
}


def parse_command(raw: bytes, framing: str) -> bytes | None:
    """Return the C2 command a real handler would recover, else None."""
    fn = FRAMINGS.get(framing)
    if fn is None:
        raise KeyError(f"unknown framing: {framing!r}")
    return fn(raw)


def detect_framing(raw: bytes) -> str:
    """Guess which framing a captured flow uses.

    Conservative and prefix-based on purpose: mislabelling a flow would make a
    mechanism look like it evades for the wrong reason.  ``length2`` is checked
    first because a wrapped stream would otherwise be misread as HTTP.
    """
    if raw.startswith(b"LEN") and b":" in raw[:12]:
        return "length2"
    if raw.startswith((b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"HTTP/")):
        return "http"
    if _IRC.search(raw):
        return "irc"
    return "http"  # corpus default; flows we have not labelled
