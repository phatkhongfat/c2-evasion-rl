"""D5: endpoint_query bar -- per-request command equivalence for parsed queries.

Citation-gated (ledger sources [6] RFC 3986, [7] PHP parse_str):
- the query component starts at the FIRST '?' [6 s3.4];
- queries carry "key=value" pairs [6 s3.4];
- components are parsed and separated BEFORE percent-decoding [6 s2.4], so
  percent-encoded octets decode to the same data;
- a standard handler extracts key-value pairs [7], and acts only on the keys
  it reads -- an unknown extra key is ignored (same precedent as the unknown
  X-Junk header in _parse_http: "Unknown headers are skipped").

Verdict rules: equal request counts; per request, a body-bearing request
must keep its body byte-identical, a bodyless GET's query is compared as
key->values projected onto the ORIGINAL key set (extra keys in the mutation
ignored, percent-decoding applied, duplicate-key order significant).
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "snort_validation"))
sys.path.insert(0, str(ROOT / "ai_agent"))

import pytest  # noqa: E402
from scapy.all import Ether, IP, TCP, Raw  # noqa: E402
from endpoint_model import parse_commands_q, query_pairs  # noqa: E402
from c2_semantics import endpoint_query_preserved  # noqa: E402

CIP = "147.32.84.165"
HEX = b"A1" * 50
GET = (b"GET /list.php?c=" + HEX + b"&v=2&t=0.89 HTTP/1.0\r\n"
       b"Host: h\r\n\r\n")


def pk(load):
    return [(Ether() / IP(src=CIP, dst="8.8.8.8")
             / TCP(sport=1, dport=80, flags="PA") / Raw(load=load))]


# ---- parse layer -----------------------------------------------------------

def test_query_pairs_decodes_and_orders():
    pairs = query_pairs(b"/a?c=AB&v=2")
    assert pairs == [(b"c", b"AB"), (b"v", b"2")]


def test_query_pairs_percent_decoded_equal():
    assert query_pairs(b"/a?c=%41%42") == [(b"c", b"AB")]


def test_parse_commands_q_get_returns_pairs():
    kind, path, val = parse_commands_q(GET, "http")[0]
    assert kind == "query"
    assert path == b"/list.php"
    assert (b"c", HEX) in val and (b"v", b"2") in val


def test_parse_commands_q_post_body_strict():
    req = b"POST /p HTTP/1.0\r\nContent-Length: 6\r\n\r\ndata=1"
    assert parse_commands_q(req, "http") == [("body", b"data=1")]


def test_parse_commands_q_path_no_query():
    req = b"GET /plain HTTP/1.0\r\nHost: h\r\n\r\n"
    assert parse_commands_q(req, "http") == [("path", b"/plain")]


# ---- bar layer -------------------------------------------------------------

def test_prepended_unknown_key_preserved():
    mut = GET.replace(b"?", b"?x=0&", 1)
    assert endpoint_query_preserved(pk(GET), pk(mut), CIP) is True


def test_reordered_params_preserved():
    mut = (b"GET /list.php?v=2&c=" + HEX + b"&t=0.89 HTTP/1.0\r\n"
           b"Host: h\r\n\r\n")
    assert endpoint_query_preserved(pk(GET), pk(mut), CIP) is True


def test_percent_encoded_value_preserved():
    enc = b"".join(b"%%%02X" % c for c in HEX)
    mut = GET.replace(b"c=" + HEX, b"c=" + enc)
    assert endpoint_query_preserved(pk(GET), pk(mut), CIP) is True


def test_changed_value_rejected():
    mut = GET.replace(b"c=" + HEX, b"c=" + b"B2" * 50)
    assert endpoint_query_preserved(pk(GET), pk(mut), CIP) is False


def test_dropped_param_rejected():
    mut = GET.replace(b"&v=2", b"")
    assert endpoint_query_preserved(pk(GET), pk(mut), CIP) is False


def test_path_change_rejected():
    mut = GET.replace(b"/list.php?", b"/other.php?")
    assert endpoint_query_preserved(pk(GET), pk(mut), CIP) is False


def test_pipelined_post_case_fold_preserved():
    r1 = (b"POST /g HTTP/1.1\r\nAccept: */*\r\nContent-Length: 6\r\n\r\n"
          b"data=1")
    r2 = r1.replace(b"data=1", b"data=2")
    orig = r1 + r2
    mut = orig.replace(b"Accept:", b"accept:").replace(
        b"Content-Length:", b"content-length:")
    assert endpoint_query_preserved(pk(orig), pk(mut), CIP) is True


def test_pipelined_post_body_change_rejected():
    r1 = (b"POST /g HTTP/1.1\r\nContent-Length: 6\r\n\r\ndata=1")
    r2 = r1.replace(b"data=1", b"data=2")
    mut = (r1 + r2).replace(b"data=2", b"data=X")
    assert endpoint_query_preserved(pk(r1 + r2), pk(mut), CIP) is False


def test_request_count_mismatch_rejected():
    r1 = b"POST /g HTTP/1.1\r\nContent-Length: 6\r\n\r\ndata=1"
    assert endpoint_query_preserved(pk(r1 + r1), pk(r1), CIP) is False


def test_non_http_framing_delegates_to_commands_bar():
    raw = b"neris1:payload"
    # identical mutation: delegate verdict (v1 semantics) -> True
    assert endpoint_query_preserved(pk(raw), pk(raw), CIP) is True
    # changed payload on neris framing: command differs -> False
    assert endpoint_query_preserved(pk(raw), pk(b"neris1:payloaX"),
                                    CIP) is False


def test_unreadable_original_rejected():
    junk = b"\x01\x02\x03not-a-request"
    assert endpoint_query_preserved(pk(junk), pk(junk), CIP) is False
