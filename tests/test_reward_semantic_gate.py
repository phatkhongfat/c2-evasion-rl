"""P15.3: the training-reward semantics gate (D8, frozen before code).

``semantics_ok_reward`` = byte-bar OR D7 OR D5, uniform across mechanisms.
These tests prove it is relaxed exactly where the frozen headline bars are
relaxed, that it does NOT leak to mechanisms that break the command, and that
it fails closed on non-HTTP payloads.  An env-level test pins the reward wiring
and the ``info`` keys.

RED before T1.4: ``semantics_ok_reward`` does not exist (AttributeError) and
``step()`` carries no ``semantics_bytes`` key.
"""
import pickle
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "snort_validation"), str(ROOT / "ai_agent")]

from scapy.all import Ether, IP, TCP, Raw  # noqa: E402
import hidden_defender_env as hde  # noqa: E402
from c2_semantics import (  # noqa: E402
    bytes_equal_semantics,
    semantics_ok_reward,
)

CIP = "147.32.84.165"
REQ = (b"GET /list.php?c=" + b"A1" * 50 + b"&v=2&t=0.89 HTTP/1.0\r\n"
       b"User-Agent: Mozilla/4.0\r\nHost: mewgost.com\r\n\r\n")
# A binary payload the HTTP endpoint parser cannot read (parse_commands -> None),
# so D7/D5 fail closed; a pad16 mutation changes its bytes, so the byte bar also
# fails.  (detect_framing returns "http" for it -- the corpus default -- so the
# fail-closed path exercised here is the unreadable-original one, not non-HTTP.)
DNS = b"\x01J\x01\x00dns\x00\x00"


def _pkts(load=REQ, src=CIP):
    return [Ether() / IP(src=src, dst="8.8.8.8")
            / TCP(sport=1024, dport=80, flags="PA") / Raw(load=load)]


# -- 1. relaxed exactly where the frozen bars are --------------------------

def test_qpp_passes_the_reward_gate_though_the_byte_bar_fails():
    pkts = _pkts(REQ)
    mut = hde.apply_mech(pkts, "query_param_prepend", CIP)
    assert semantics_ok_reward(pkts, mut, CIP) is True
    # proves the OR branch is live, not a duplicate of the byte bar
    assert bytes_equal_semantics(pkts, mut, CIP) is False


# -- 2. no leak to a mechanism that breaks the command ---------------------

def test_corrupt8_fails_the_reward_gate():
    pkts = _pkts(REQ)
    mut2 = hde.apply_mech(pkts, "corrupt8", CIP)
    assert semantics_ok_reward(pkts, mut2, CIP) is False


# -- 3. fail-closed on a payload the HTTP parser cannot read --------------

def test_non_http_mutation_fails_the_reward_gate():
    pkts_dns = _pkts(DNS)
    mut = hde.apply_mech(pkts_dns, "pad16", CIP)
    # the mutation actually changed the payload (otherwise the test is vacuous)
    assert bytes(mut[0][Raw].load) != bytes(pkts_dns[0][Raw].load)
    assert bytes_equal_semantics(pkts_dns, mut, CIP) is False
    assert semantics_ok_reward(pkts_dns, mut, CIP) is False


# -- 4. env-level wiring ---------------------------------------------------

def _flow(flow_id, load, framing):
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


class _NeverAlerts:
    """Replica stub: the defender never fires, so every action 'evades'."""

    def verdict(self, pkts, home_ip=None):
        return False


def _env_with_flows(flows):
    corpus = {"train": list(flows), "test": list(flows)}
    path = "/tmp/p15_corpus_gate.pkl"
    with open(path, "wb") as fh:
        pickle.dump(corpus, fh)
    env = hde.HiddenDefenderEnv(split="test", corpus=path, real_snort=False)
    return env


def test_env_step_reward_uses_the_relaxed_gate():
    fid = f"p15|{CIP}:1024->8.8.8.8:80|tcp"
    env = _env_with_flows([_flow(fid, REQ, "http")])
    env._flows[0]["replica"] = _NeverAlerts()
    env._idx = 0
    idx_qpp = hde.ACTION_NAMES.index("query_param_prepend")
    _o, reward, _t, _tr, info = env.step(idx_qpp)
    assert info["evaded"] is True
    assert info["semantics_ok"] is True          # D8 gate passes
    assert info["semantics_bytes"] is False      # strict byte bar still fails
    assert reward == pytest.approx(
        hde.REWARD_EVADE - hde.ACTION_COSTS[idx_qpp]
        + hde.PROTOCOL_MATCH_BONUS)
