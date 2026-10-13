"""P15.1: post-P14 action space -- http_header_case (15) + query_param_prepend (16).

TDD RED for T1.1/T1.2.  The two P14 mechanisms are already implemented in
``apply_mech`` and measured to win (http_header_case 16/16 old-corpus C2;
query_param_prepend 4/4 Virut); P15 exposes them as actions.  These tests pin
the four things that promotion touches:

  (i)   ACTION_NAMES / N_ACTIONS  -> 17, new names at idx 15/16, old idx frozen
  (ii)  ACTION_COSTS[15]/[16]     -> 0.05 (D10)
  (iii) mech_applicable           -> query_param_prepend needs HTTP + a '?'
  (iv)  the action mask           -> 15/16 HTTP-only; 16 also needs a '?'

Framing note (deviation from the plan draft): ``detect_framing`` returns
``"http"`` as the corpus DEFAULT for anything it does not recognise, so the
plan's DNS-fake payload ``b"\\x01J\\x01\\x00dns"`` is classified HTTP and cannot
prove "non-HTTP is inapplicable".  A genuinely non-HTTP payload (a neris record
chain) is used instead.
"""
import pickle
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "snort_validation"), str(ROOT / "ai_agent")]

from scapy.all import Ether, IP, TCP, Raw  # noqa: E402
import hidden_defender_env as hde  # noqa: E402

CIP = "147.32.84.165"
REQ = (b"GET /list.php?c=" + b"A1" * 50 + b"&v=2&t=0.89 HTTP/1.0\r\n"
       b"User-Agent: Mozilla/4.0\r\nHost: mewgost.com\r\n\r\n")
# A payload detect_framing classifies as non-HTTP (neris record chain).
NERIS = b"neris2:8:ABCDEFGH"


def _pkts(load=REQ, src=CIP):
    return [Ether() / IP(src=src, dst="8.8.8.8")
            / TCP(sport=1024, dport=80, flags="PA") / Raw(load=load)]


def test_action_names_extended():
    assert hde.ACTION_NAMES[15] == "http_header_case"
    assert hde.ACTION_NAMES[16] == "query_param_prepend"
    assert hde.N_ACTIONS == 17
    # idx cũ bất biến (model cũ không load được là chấp nhận, idx không được xê dịch)
    assert hde.ACTION_NAMES[:15] == [
        "split8", "split16", "split24", "prepend4", "prepend8", "prepend12",
        "pad16", "reorder", "ttl", "corrupt8", "overlap8", "noop",
        "http_header_pad", "length_wrapper", "split_slow"]


def test_costs_per_d10():
    assert hde.ACTION_COSTS[15] == 0.05
    assert hde.ACTION_COSTS[16] == 0.05
    assert len(hde.ACTION_COSTS) == 17


def test_mech_applicable_qpp_needs_http_and_query():
    assert hde.mech_applicable([REQ], "query_param_prepend") is True
    assert hde.mech_applicable([b"GET /plain HTTP/1.0\r\n\r\n"],
                               "query_param_prepend") is False
    # A genuinely non-HTTP payload must be inapplicable.  (The plan's
    # b"\x01J\x01\x00dns" is classified http by detect_framing's default.)
    assert hde.mech_applicable([NERIS], "query_param_prepend") is False
    assert hde.mech_applicable([REQ], "http_header_case") is True
    assert hde.mech_applicable([NERIS], "http_header_case") is False


def test_protocol_appropriate_http_includes_new_mechs():
    assert "http_header_case" in hde.PROTOCOL_APPROPRIATE["http"]
    assert "query_param_prepend" in hde.PROTOCOL_APPROPRIATE["http"]


# -- (iv) mask --------------------------------------------------------------

def _flow(flow_id, load, framing):
    """A minimal flow dict carrying exactly the keys load_corpus yields."""
    return {
        "capture": flow_id.split("|")[0],
        "dataset": "p15",
        "extra_sids": [],
        "flow_id": flow_id,
        "framing": framing,
        "key": (flow_id.split("|")[0], "p15", 1024, 80, "tcp"),
        "obs": [0.0] * 8,
        "packets": _pkts(load),
        "replica": None,
    }


def _env_with_flows(flows):
    corpus = {"train": list(flows), "test": list(flows)}
    path = "/tmp/p15_corpus.pkl"
    with open(path, "wb") as fh:
        pickle.dump(corpus, fh)
    env = hde.HiddenDefenderEnv(split="test", corpus=path, real_snort=False)
    return env


def test_mask_http_flow_with_query_allows_both_new_actions():
    fid = f"p15|{CIP}:1024->8.8.8.8:80|tcp"
    env = _env_with_flows([_flow(fid, REQ, "http")])
    mask = env.action_masks()
    assert len(mask) == 17
    assert mask[15] == 1, "http_header_case must be allowed on HTTP"
    assert mask[16] == 1, "query_param_prepend must be allowed on HTTP with '?'"


def test_mask_neris_flow_blocks_both_new_actions():
    fid = f"p15|{CIP}:1024->8.8.8.8:80|tcp"
    env = _env_with_flows([_flow(fid, NERIS, "neris")])
    mask = env.action_masks()
    assert mask[15] == 0, "http_header_case is HTTP-only"
    assert mask[16] == 0, "query_param_prepend is HTTP-only"


def test_mask_http_flow_without_query_blocks_only_qpp():
    fid = f"p15|{CIP}:1024->8.8.8.8:80|tcp"
    env = _env_with_flows([_flow(fid, b"GET /plain HTTP/1.0\r\n\r\n", "http")])
    mask = env.action_masks()
    assert mask[15] == 1, "http_header_case needs no query string"
    assert mask[16] == 0, "query_param_prepend needs a '?' in an owned payload"


# -- T1.5: byte-identity env<->eval + A4 split regression -------------------

def test_env_apply_mech_byte_identical_to_eval_pipeline():
    """Fix 3: the env mirror and the eval pipeline must produce identical bytes
    for both newly promoted mechanisms (the reward and the honest evaluation
    must be scoring the same mutation)."""
    from eval_pipeline import mutate_client_only, client_ip_of
    pkts = _pkts()
    fid = f"cap|{CIP}:1024->8.8.8.8:80|tcp"
    for mech in ("http_header_case", "query_param_prepend"):
        a = hde.apply_mech(pkts, mech, client_ip_of(fid))
        b = mutate_client_only(pkts, mech, client_ip_of(fid))
        ba = b"".join(bytes(p[Raw].load) for p in a if Raw in p)
        bb = b"".join(bytes(p[Raw].load) for p in b if Raw in p)
        assert ba == bb, mech


def test_split_paths_untouched_a4():
    """A4: promoting the new mechanisms must not change split8's behaviour.

    split8 still fragments, and the reassembled client stream is byte-invariant
    -- the property A4 protects (new mechanisms only append to ACTION_NAMES and
    never touch a split branch).
    """
    from c2_semantics import reassembled_client_bytes
    pkts = _pkts()
    m = hde.apply_mech(pkts, "split8", CIP)
    assert len(m) > len(pkts)          # split8 still fragments
    assert (reassembled_client_bytes(pkts, CIP)
            == reassembled_client_bytes(m, CIP)), "split8 broke the byte stream"
