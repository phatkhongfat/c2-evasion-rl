"""P14 Phase 2: query_param_prepend -- break literal URI content-chains.

sid:2012533 (Virut.BN checkin) matches content:"list.php?c=" within:32 plus
"&v="/"&t=" distance:0 chains and a pcre on the c= value.  Inserting one
benign extra query parameter right after the '?' breaks every literal while
any standard query parser still recovers c/v/t identically (split '&' then
'='; RFC 3986 -- the inserted key x=0 is simply unknown to the handler).
Cost: +4 bytes, no fragmentation, no split family.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "snort_validation"))
sys.path.insert(0, str(ROOT / "ai_agent"))

from scapy.all import Ether, IP, TCP, Raw  # noqa: E402
from eval_pipeline import client_ip_of, mutate_client_only  # noqa: E402

CIP = "147.32.84.165"
HEX100 = b"A1" * 50
REQ = (b"GET /list.php?c=" + HEX100 + b"&v=2&t=0.89 HTTP/1.0\r\n"
       b"User-Agent: Mozilla/4.0\r\nHost: mewgost.com\r\n\r\n")


def _flow(load=REQ):
    p = (Ether() / IP(src=CIP, dst="8.8.8.8")
         / TCP(sport=1024, dport=80, flags="PA") / Raw(load=load))
    return {"flow_id": f"cap|{CIP}:1024->8.8.8.8:80|tcp",
            "packets": [p], "framing": "http"}


def _client_load(pkts):
    return b"".join(bytes(p[Raw].load) for p in pkts
                    if IP in p and Raw in p and p[IP].src == CIP)


def test_prepend_breaks_literal_chain_only():
    f = _flow()
    mut = mutate_client_only(f["packets"], "query_param_prepend",
                             client_ip_of(f["flow_id"]), ownership="both")
    new = _client_load(mut)
    assert b"list.php?c=" not in new            # sid:2012533 content broken
    assert b"list.php?x=0&c=" in new            # benign param first
    assert b"c=" + HEX100 in new                # c value byte-identical
    assert b"&v=2&t=0.89 HTTP/1.0" in new       # rest of line untouched
    assert len(new) == len(REQ) + 4             # exactly +4 bytes


def test_prepend_skips_requests_without_query():
    f = _flow(b"GET /plain HTTP/1.0\r\nHost: h\r\n\r\n")
    mut = mutate_client_only(f["packets"], "query_param_prepend",
                             client_ip_of(f["flow_id"]), ownership="both")
    assert _client_load(mut) == _client_load(f["packets"])


def test_prepend_skips_non_http_framing():
    neris = b"neris1:" + b"\x00" * 20
    p = (Ether() / IP(src=CIP, dst="8.8.8.8")
         / TCP(sport=1, dport=80, flags="PA") / Raw(load=neris))
    f = {"flow_id": f"cap|{CIP}:1->8.8.8.8:80|tcp", "packets": [p],
         "framing": "neris"}
    mut = mutate_client_only(f["packets"], "query_param_prepend", CIP,
                             ownership="both")
    assert _client_load(mut) == neris


def test_prepend_touches_request_line_only_first_payload_packet():
    # request line lives in the first client payload packet; a second data
    # packet must be left alone
    p1 = (Ether() / IP(src=CIP, dst="8.8.8.8")
          / TCP(sport=1, dport=80, seq=1, flags="PA") / Raw(load=REQ))
    p2 = (Ether() / IP(src=CIP, dst="8.8.8.8")
          / TCP(sport=1, dport=80, seq=1 + len(REQ), flags="PA")
          / Raw(load=b"more-bytes"))
    f = {"flow_id": f"cap|{CIP}:1->8.8.8.8:80|tcp", "packets": [p1, p2],
         "framing": "http"}
    mut = mutate_client_only(f["packets"], "query_param_prepend", CIP,
                             ownership="both")
    assert bytes(mut[1][Raw].load) == b"more-bytes"


def test_env_apply_mech_byte_identical_to_pipeline():
    """Fix 3: the env mirror and the pipeline must produce identical bytes."""
    from hidden_defender_env import apply_mech
    f = _flow()
    via_pipe = mutate_client_only([p.copy() for p in f["packets"]],
                                  "query_param_prepend", CIP, ownership="both")
    via_env = apply_mech([p.copy() for p in f["packets"]],
                         "query_param_prepend", CIP)
    assert [bytes(p) for p in via_pipe] == [bytes(p) for p in via_env]


def test_unknown_mech_still_raises_or_noops_consistently():
    # guard: adding the new mech must not change behaviour of unknown names
    f = _flow()
    try:
        mutate_client_only(f["packets"], "no_such_mech", CIP, ownership="both")
    except (ValueError, KeyError):
        return
    # if it did not raise, bytes must be unchanged (existing contract)
    assert _client_load(f["packets"]) == REQ
