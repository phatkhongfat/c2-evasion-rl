"""The endpoint-command bar: does a real handler still read the same command?

The SECOND declared semantics bar (plan P12).  Where ``bytes_equal_semantics``
asks "is the wire identical", this asks "does the endpoint still understand the
channel" -- the question a protocol-legal mutation (an unknown HTTP header, a
case-folded field name) has to answer.

Every case here is a FAIL-CLOSED case.  The load-bearing one is the vacuity
guard: ``detect_framing`` falls back to ``"http"`` for an unlabelled flow and
``_parse_http`` then returns ``None`` on a stream it cannot read, so a naive
implementation compares ``None == None`` and reports a vacuous PASS.  A bar that
cannot READ the original cannot CERTIFY the mutation, so ``None`` on the ORIGINAL
is a rejection.

Spec deviations from the plan text (verified against the real files, 2026-10-13):

* The plan's T2 skeleton gated on ``wire_deliverable``.  That helper enforces
  *byte-equality of the reassembled datagram multiset* -- it is the byte bar's
  gate.  Gating the endpoint bar on it would reject exactly the protocol-legal
  mutations this bar exists to certify (an inserted ``X-Pad`` header changes the
  datagram bytes but not the command), which contradicts the plan's own
  prediction that ``http_header_pad`` moves to ``valid(endpoint)=16``.  The
  endpoint bar therefore does NOT reuse it; ``bytes_equal_semantics`` still
  applies it and both verdicts are reported side by side.
* The plan's IPv6 case built ``IPv6(src="10.0.0.1")``, which scapy rejects with
  ``OSError``.  Valid IPv6 literals are used instead.
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
for sub in ("snort_validation", "ai_agent"):
    p = str(ROOT / sub)
    if p not in sys.path:
        sys.path.insert(0, p)

from scapy.all import Ether, IP, IPv6, TCP, Raw  # noqa: E402
from c2_semantics import endpoint_command_preserved  # noqa: E402


def _pkt(src, dst, payload, seq=1, ip_proto_tcp=True):
    if ip_proto_tcp:
        return Ether() / IP(src=src, dst=dst) / TCP(sport=1234, dport=80, seq=seq, flags="PA") / Raw(payload)
    return Ether() / IPv6(src=src, dst=dst) / TCP(sport=1234, dport=80, seq=seq, flags="PA") / Raw(payload)


C, S = "10.0.0.1", "10.0.0.9"
C6, S6 = "2001:db8::1", "2001:db8::2"
HTTP = (b"POST /getjson HTTP/1.1\r\nAccept: */*\r\nHost: a.com\r\n"
        b"Content-Length: 4\r\n\r\ndata=1")
NERIS = b"neris2:8:ABCDEFGH"


def _roundtrip(pkt, mutate):
    pkts = [pkt]
    out = [mutate(p.copy()) for p in pkts]
    return pkts, out


def test_identical_stream_preserves():
    """Control: no mutation must pass."""
    pkts = [_pkt(C, S, HTTP)]
    assert endpoint_command_preserved(pkts, [p.copy() for p in pkts], C) is True


def test_unknown_http_header_is_preserved():
    """The legal case: a server ignores unknown headers, so the command survives.

    This is the whole point of the bar -- the wire changed, the channel did not.
    """
    def add_header(p):
        raw = bytes(p[Raw].load)
        head, sep, body = raw.partition(b"\r\n")
        p[Raw].load = head + b"\r\nX-Pad: AAAA\r\n" + body
        del p[IP].chksum
        del p[TCP].chksum
        return p
    pkts, out = _roundtrip(_pkt(C, S, HTTP), add_header)
    assert endpoint_command_preserved(pkts, out, C) is True


def test_header_case_fold_is_preserved():
    """RFC 7230 3.2: field names are case-insensitive."""
    def fold(p):
        raw = bytes(p[Raw].load)
        head, sep, body = raw.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        out_lines = [lines[0]] + [ln.split(b":")[0].lower() + b":" + ln.split(b":", 1)[1]
                                  if b":" in ln else ln for ln in lines[1:]]
        p[Raw].load = b"\r\n".join(out_lines) + b"\r\n\r\n" + body
        del p[IP].chksum
        del p[TCP].chksum
        return p
    pkts, out = _roundtrip(_pkt(C, S, HTTP), fold)
    assert endpoint_command_preserved(pkts, out, C) is True


def test_body_corruption_is_rejected():
    def corrupt(p):
        raw = bytes(p[Raw].load)
        p[Raw].load = raw.replace(b"data=1", b"data=2")
        del p[IP].chksum
        del p[TCP].chksum
        return p
    pkts, out = _roundtrip(_pkt(C, S, HTTP), corrupt)
    assert endpoint_command_preserved(pkts, out, C) is False


def test_vacuity_guard_binary_framing_is_rejected_not_passed():
    """A NERIS record chain whose trailing bytes change must not be certified.

    ``detect_framing`` labels the chain ``neris`` and the parser returns the raw
    bytes, so the command genuinely differs after a 4-NUL append -- this is a
    real rejection, not a vacuous one.  See the two tests below for the actual
    ``None == None`` hole.
    """
    pkts = [_pkt(C, S, NERIS)]
    mut = [_pkt(C, S, NERIS + b"\x00\x00\x00\x00")]
    assert endpoint_command_preserved(pkts, mut, C) is False


def test_vacuity_guard_unparseable_original_is_rejected_not_passed():
    """THE hole: a stream ``detect_framing`` cannot label falls back to "http"
    and ``_parse_http`` returns None on BOTH sides, so a naive implementation
    compares None == None and PASSES.  A bar that cannot read the ORIGINAL
    cannot certify anything, so this must be False.
    """
    from endpoint_model import detect_framing, parse_command

    original = b"\x01\x02\x03\x04"          # unlabelled binary, not a C2 chain
    mutated = b"\x01\x02\x03\x04\x05\x06"    # different bytes, also unreadable

    # Documents the trap: both sides are labelled http and BOTH parse to None,
    # so a naive `parse(mut) == parse(orig)` would report a vacuous True.
    assert detect_framing(original) == "http"
    assert parse_command(original, "http") is None
    assert parse_command(mutated, "http") is None

    pkts = [_pkt(C, S, original)]
    mut = [_pkt(C, S, mutated)]
    assert endpoint_command_preserved(pkts, mut, C) is False


def test_original_unreadable_is_rejected():
    """A bar that cannot read the ORIGINAL cannot certify anything."""
    pkts = [_pkt(C, S, b"")]
    mut = [_pkt(C, S, b"")]
    assert endpoint_command_preserved(pkts, mut, C) is False


def test_original_readable_but_mutation_unreadable_is_rejected():
    """The converse direction: the original is a valid HTTP request, but the
    mutation destroys the request line so the handler reads nothing.  None on
    the mutated side must not compare equal to a real command.
    """
    def nul_prepend(p):
        p[Raw].load = b"\x00\x00\x00\x00" + bytes(p[Raw].load)
        del p[IP].chksum
        del p[TCP].chksum
        return p
    pkts, out = _roundtrip(_pkt(C, S, HTTP), nul_prepend)
    assert endpoint_command_preserved(pkts, out, C) is False


def test_ipv6_fails_closed():
    """Mirrors ed6fb8d: an IP family this bar cannot reassemble is unverifiable,
    so it is rejected rather than counted as preserved.  (The plan's literal
    addresses ``10.0.0.1`` inside ``IPv6()`` are invalid and raise OSError, so
    valid IPv6 literals are used.)
    """
    pkts = [_pkt(C6, S6, HTTP, ip_proto_tcp=False)]
    mut = [_pkt(C6, S6, b"POST /getjson HTTP/1.1\r\n\r\ndata=1", ip_proto_tcp=False)]
    assert endpoint_command_preserved(pkts, mut, C6) is False


@pytest.mark.parametrize("mech,expect", [
    ("noop", True), ("split8", True),
])
def test_dissectors_are_byte_safe(mech, expect):
    from hidden_defender_env import apply_mech
    pkts = [_pkt(C, S, HTTP)]
    out = apply_mech(pkts, mech, C, ownership="both")
    assert endpoint_command_preserved(pkts, out, C) is expect
