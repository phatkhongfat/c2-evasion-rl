"""P16b: Suricata alert counting must be proven on a known-alerting pcap.

`cross_engine_v2.json` has 5/5 cells = -1 (exception), so NO Suricata verdict has
ever existed in this project.  This test pins the counting method BEFORE any
evasion number uses it -- same discipline as the P14 scapy lazy-unpickle bug.

Provenance of the fixture (measured, not assumed):
- `tests/fixtures/suricata_known_alert.pcap` = 10 packets of one HTTP flow from
  the corpus test split (`botnet-capture-20110811-neris|147.32.84.165:2077->
  184.82.147.251:80|tcp`).  Real Snort 2.9.20 with the committed
  `snort_et_c2.conf` alerts 1 time on it; real Suricata 7.0.3 with the converted
  ruleset alerts 1 time on it (SID 2012627), and fast.log and eve.json agree.
- An earlier fixture idea (the CTU-Malware-Capture-Botnet-9 pcap) was WRONG: it
  alerts 0 times under Snort too.  It is only a "regular file" for `snort -T`.
  Pinning a known-alerting pcap therefore required measuring first.

The counting method under test is deliberately NOT `stdout.count("[**]")`
(that is what controls/cross_engine_check.py used and never validated).
"""
import json
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "snort_validation"), str(ROOT / "ai_agent")]

KNOWN_ALERT_PCAP = ROOT / "tests/fixtures/suricata_known_alert.pcap"
YAML = ROOT / "snort_validation/suricata.yaml"
RULES = ROOT / "snort_validation/et_open_c2/suricata.rules"

# Measured 2026-10-13 on the fixture, both engines.  Kept as an assertion so a
# ruleset/yaml edit that silently changes detection fails here, not later in a
# sweep whose numbers would then be uninterpretable.
EXPECTED_SID = 2012627


def _ready():
    return (shutil.which("suricata") is not None and RULES.exists()
            and YAML.exists() and KNOWN_ALERT_PCAP.exists())


pytestmark = pytest.mark.skipif(
    not _ready(), reason="suricata binary / ruleset / yaml / fixture not present")


def test_known_alerting_pcap_scores_nonzero_and_eve_agrees(tmp_path):
    from suricata_runner import count_alerts
    n = count_alerts(KNOWN_ALERT_PCAP, RULES, YAML, tmp_path)
    assert n > 0, "known-alerting capture scored 0 -- counting method is broken"

    eve_path = tmp_path / "eve.json"
    assert eve_path.exists(), "eve.json missing -- cross-check source absent"
    eve = [json.loads(l) for l in eve_path.read_text().splitlines() if l.strip()]
    n_eve = sum(1 for e in eve if e.get("event_type") == "alert")
    assert n_eve > 0, "fast.log fired but eve.json has no alert event"
    assert abs(n - n_eve) <= max(1, n_eve // 10), (
        f"fast.log {n} vs eve.json {n_eve} disagree beyond tolerance")


def test_benign_pcap_scores_zero(tmp_path):
    """A single UDP datagram must not alert: guards against a counting method
    that counts ANY line in fast.log (headers, summary lines, rule-load noise)."""
    from suricata_runner import count_alerts
    from scapy.all import IP, UDP, wrpcap
    p = tmp_path / "benign.pcap"
    wrpcap(str(p), [IP(src="203.0.113.9", dst="203.0.113.10") / UDP(sport=1, dport=2)])
    assert count_alerts(p, RULES, YAML, tmp_path) == 0


def test_expected_signature_is_the_one_measured_on_the_fixture(tmp_path):
    """Pins WHICH rule fires, so attribution failures surface as a rule-set
    regression rather than as a silently different measurement."""
    from suricata_runner import alert_sids
    sids = alert_sids(KNOWN_ALERT_PCAP, RULES, YAML, tmp_path)
    assert sids, "no sids extracted from known-alerting pcap"
    assert all(isinstance(s, int) and s > 0 for s in sids)
    assert EXPECTED_SID in sids, (
        f"expected sid {EXPECTED_SID} on the fixture, got {sids}")


def test_sid_attribution_survives_the_query_ip_rewrite(tmp_path):
    """The batch harness rewrites the flow source into 198.51.100.0/24, so alert
    attribution must work on a rewritten 5-tuple -- otherwise every per-flow
    number in a batched sweep would be silently wrong.  We do NOT assert a
    particular SID here: whether a rewritten capture still matches is the
    empirical question, and forcing it would be inventing a fact."""
    from scapy.all import IP, TCP, Raw, wrpcap
    from suricata_runner import alert_records
    body = (b"GET /index.php?id=1 HTTP/1.1\r\n"
            b"User-Agent: Mozilla/5.0\r\n"
            b"Accept: */*\r\n\r\n")
    pkts = [
        IP(src="198.51.100.7", dst="93.184.216.34") / TCP(sport=40000, dport=80, flags="S"),
        IP(src="198.51.100.7", dst="93.184.216.34") / TCP(
            sport=40000, dport=80, flags="PA", seq=1, ack=1) / Raw(body),
    ]
    p = tmp_path / "synthetic.pcap"
    wrpcap(str(p), pkts)
    recs = alert_records(p, RULES, YAML, tmp_path)
    assert isinstance(recs, list)
    for r in recs:                      # shape contract only
        assert r.get("event_type") == "alert"
        assert isinstance(r["alert"]["signature_id"], int)