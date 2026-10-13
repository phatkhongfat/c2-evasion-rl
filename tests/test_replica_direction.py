"""P15.5 — the replica must honour rule-header DIRECTION when given home_ip.

Root cause (committed evidence, no Snort run): ET Open C2 UDP rules like
sid:2008581 are written ``alert udp $HOME_NET any -> $EXTERNAL_NET any (...)``
with NO ``flow:`` keyword.  ``parse_ruleset`` derived ``to_server``/``from_server``
ONLY from ``flow:``, so such a rule fell through to the direction-agnostic
``both`` payload arm and fired on an UNMODIFIED server packet even when the
client (bot) side was fragmented -- giving surrogate training zero evasion
signal for ``split8`` on neris flows.

These tests pin three behaviours:

  * backward compatibility: ``verdict(pkts)`` with NO ``home_ip`` keeps the old
    legacy result (so ``firing_sids``/baseline artifacts stay reproducible);
  * the new ``home_ip`` path selects payloads by rule-header direction;
  * an explicit ``from_server`` header matches ONLY the external->home packet.
"""
import sys
from pathlib import Path

import pytest
from scapy.all import Ether, IP, Raw, UDP

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))

from hidden_defender_env import apply_mech  # noqa: E402
from real_rules_replica import RealRulesReplica, parse_ruleset  # noqa: E402

RULES = REPO / "snort_validation/et_open_c2/et_open_c2.rules"

BOT = "147.32.84.165"
PEER = "87.0.4.47"
PATTERN = b"d1:ad2:id20:"


def _real_line(sid: int) -> str:
    """The verbatim rule line for ``sid`` (copied, never retyped)."""
    for line in RULES.read_text(errors="ignore").splitlines():
        if f"sid:{sid};" in line and line.strip().lower().startswith("alert"):
            return line
    raise AssertionError(f"sid {sid} not found in {RULES}")


@pytest.fixture()
def ping_rule(tmp_path):
    """A one-rule ruleset holding the REAL sid:2008581 line."""
    p = tmp_path / "one.rules"
    p.write_text(_real_line(2008581) + "\n")
    return parse_ruleset(p)


def _udp(src, dst, sport, dport, payload):
    return Ether() / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / Raw(load=payload)


def _neris_flow():
    """EXTERNAL peer speaks first, then the HOME bot replies with the pattern.

    This is the exact shape of the 24 neris test flows: the first IP packet's
    src is the external peer, so ``_initiator`` is NOT the bot.
    """
    return [
        _udp(PEER, BOT, 24320, 32234, PATTERN + b"\x03Teo9#junk" * 3),
        _udp(BOT, PEER, 32234, 24320, PATTERN + b"5:nodes208:\x0b\xde" * 4),
        _udp(BOT, PEER, 32234, 24320, PATTERN + b"ee1:q4:ping1:t8:\x1b" * 2),
    ]


def test_header_direction_is_parsed(ping_rule):
    assert len(ping_rule) == 1
    assert ping_rule[0].direction == "to_server"


def test_legacy_verdict_without_home_ip_still_fires(ping_rule):
    """No home_ip -> EXACT legacy behaviour (both payload arms)."""
    rep = RealRulesReplica(ping_rule)
    assert rep.verdict(_neris_flow()) is True


def test_home_ip_matches_unfragmented_client_packets(ping_rule):
    rep = RealRulesReplica(ping_rule)
    assert rep.verdict(_neris_flow(), home_ip=BOT) is True


def test_split8_on_client_evades_under_home_ip(ping_rule):
    """Fragmented client -> the to_server rule must NOT fire.

    Legacy (no home_ip) fires on the intact server packet; that is the bug.
    """
    rep = RealRulesReplica(ping_rule)
    pkts = _neris_flow()
    mut = apply_mech(pkts, "split8", BOT)
    assert rep.verdict(mut, home_ip=BOT) is False
    assert rep.verdict(mut) is True        # pins the pre-fix false alert


def test_from_server_header_matches_only_external_packet(tmp_path):
    p = tmp_path / "fromsrv.rules"
    p.write_text(
        'alert udp $EXTERNAL_NET any -> $HOME_NET any '
        '(msg:"t"; content:"ZZ"; sid:9990001; rev:1;)\n'
    )
    rules = parse_ruleset(p)
    assert rules[0].direction == "from_server"
    rep = RealRulesReplica(rules)

    ext_only = [_udp(PEER, BOT, 1, 2, b"ZZ")]
    home_only = [_udp(BOT, PEER, 2, 1, b"ZZ")]
    assert rep.verdict(ext_only, home_ip=BOT) is True
    assert rep.verdict(home_only, home_ip=BOT) is False


def test_alert_count_and_firing_rules_accept_home_ip(ping_rule):
    rep = RealRulesReplica(ping_rule)
    pkts = _neris_flow()
    assert rep.alert_count(pkts, home_ip=BOT) == 1
    assert [r.sid for r in rep.firing_rules(pkts, home_ip=BOT)] == [2008581]
    mut = apply_mech(pkts, "split8", BOT)
    assert rep.alert_count(mut, home_ip=BOT) == 0
    assert rep.firing_rules(mut, home_ip=BOT) == []
