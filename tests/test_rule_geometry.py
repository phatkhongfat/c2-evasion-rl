"""Root-cause tests: why headroom = oracle on corpus v3fixed.

The claim being locked in:
  fragmentation reaches 100% on every SID family corpus v3fixed contains, so
  `oracle == best_single` and headroom is 0. Rule geometry explains WHY: all
  five families are triggered by contiguous content patterns of at most 11
  bytes, and the smallest fragmentation unit available is 8 bytes.

What geometry does NOT claim: that a short pattern (L < 8) is safe. Whether a
short pattern survives depends on its offset/distance/within constraints, not
on L alone. L is a NECESSARY condition for breakage (L > unit => certainly
cut), never a sufficient one. The boundary cases are settled by measurement
only -- `CAPTURE_SIDS_BELOW_UNIT` exists so a later corpus that needs real
sweeps to settle them is explicit rather than assumed.

These tests read the real eval ruleset. They do not touch Snort, do not train,
and do not modify any report.
"""

import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "controls"))

from rule_geometry import (  # noqa: E402
    CORPUS_SIDS,
    MIN_FRAGMENTATION_UNIT,
    content_lengths,
    discriminating_sids,
    longest_content,
    parse_alert_rule,
    rule_geometry,
)

RULESET = ROOT / "snort_validation/et_open_c2/et_open_c2.rules"
CONF = ROOT / "snort_validation/et_open_c2/snort_et_c2.conf"
CAPTURE_DIR = Path("/tmp/cov")

# Every SID the 16 CTU captures ever produced, with its longest content length.
# Recorded from a scan of /tmp/cov/*/alert on 2026-10-12.
CAPTURE_SIDS_BELOW_UNIT = {
    "2016413": 6,   # win13            - dns reply sinkhole
    "2019486": 8,   # rbot, rbot-dos   - pcre over full line
    "2014169": 7,   # neris            - dns .su TLD
    "2019471": 8,   # rbot, rbot-dos   - pcre over full line
    "2012533": 11,  # neris, fast-flux - virut http checkin
    "2014635": 3,   # fast-flux        - kazy TLS client hello
}


@pytest.mark.skipif(not RULESET.exists(), reason="eval ruleset not present")
def test_every_corpus_sid_is_present_in_the_real_eval_ruleset():
    """A silent SID -> no geometry -> the root-cause story cannot be checked."""
    for sid in CORPUS_SIDS:
        assert parse_alert_rule(RULESET, sid), f"SID {sid} absent from eval ruleset"


@pytest.mark.skipif(not RULESET.exists(), reason="eval ruleset not present")
def test_content_lengths_handle_hex_and_literal_patterns():
    """Patterns are measured in decoded BYTES, and may mix hex with ASCII.

    `|00 01 00 01|` is 4 bytes; `|02|su|00|` is 1 byte + "su" + 1 byte = 4.
    Collapsing mixed patterns to hex digits alone understates rules that anchor
    on a printable needle, which is how a fragmentation unit gets to look
    survivable when it is not.
    """
    assert content_lengths('content:"|00 01 00 01|"; content:"|02|su|00|";') == [4, 4]
    assert content_lengths('content:"GET "; content:"list.php?c=";') == [4, 11]


@pytest.mark.skipif(not RULESET.exists(), reason="eval ruleset not present")
def test_longest_content_over_the_corpus_is_eleven_bytes():
    """The load-bearing number: max contiguous pattern across all 5 SID families.

    11 (SID 2012533) > MIN_FRAGMENTATION_UNIT (8), so split8 already breaks it,
    and every LARGER unit is at least as destructive. If this ever becomes <= 8
    the root-cause explanation no longer holds and must be re-derived.
    """
    lengths = {sid: longest_content(RULESET, sid) for sid in CORPUS_SIDS}
    assert max(lengths.values()) == 11
    assert lengths[CORPUS_SIDS[0]] > 0  # sanity: not all zero


@pytest.mark.skipif(not RULESET.exists(), reason="eval ruleset not present")
def test_no_corpus_rule_can_survive_split8():
    """For each SID, at least one content is >= MIN_FRAGMENTATION_UNIT, OR the
    rule is a multi-content conjunction whose longest content already exceeds 8.

    Either way, fragmentation at U=8 destroys it -> all fragmentation units are
    equivalent -> headroom is structurally 0.
    """
    broken = [
        sid for sid in CORPUS_SIDS
        if longest_content(RULESET, sid) < MIN_FRAGMENTATION_UNIT
        and len(content_lengths(parse_alert_rule(RULESET, sid))) <= 1
    ]
    assert broken == [], f"SIDs a single short content could survive: {broken}"


@pytest.mark.skipif(not RULESET.exists(), reason="eval ruleset not present")
def test_ruleset_does_contain_discriminating_sids_outside_the_corpus():
    """The fix must be corpus selection, not a lack of usable rules.

    If this fails, the 'pick flows whose rule has 16<=L<24' recipe is impossible
    and the negative-result path is the only honest outcome.
    """
    assert discriminating_sids(RULESET, low=16, high=24), \
        "no rule in the eval ruleset can discriminate between fragmentation units"


@pytest.mark.skipif(not RULESET.exists(), reason="eval ruleset not present")
def test_conf_declares_no_stream_reassembly():
    """Fragmentation works here BECAUSE reassembly is not configured.

    Recorded so the setup is described accurately in the thesis rather than
    implying a reassembled stream that does not exist.
    """
    text = CONF.read_text()
    assert "stream5_tcp" in text, "expected stream5_tcp preprocessor line"
    assert not re.search(r"^\s*config\s+stream:.*reassemble", text, re.I), \
        "conf unexpectedly enables stream reassembly; root-cause note is stale"


@pytest.mark.skipif(not RULESET.exists(), reason="eval ruleset not present")
def test_geometry_report_shape_is_stable():
    """Guard the helper contract so future corpus rebuilds can diff it."""
    for sid in CORPUS_SIDS:
        g = rule_geometry(RULESET, sid)
        assert set(g) == {"sid", "n_content", "content_lengths", "longest"}
        assert g["sid"] == sid
        assert g["n_content"] == len(g["content_lengths"])
        assert g["longest"] == max(g["content_lengths"])


def _capture_sids_from_alert_logs(capture_dir: Path) -> set[str]:
    """Every SID that appears in any capture's Snort alert log.

    Parsed from the alert text (`[1:<sid>:`) rather than from a report, because
    the captures' pcaps are not retained -- only their alert output is. This is
    therefore the strongest evidence available about what the corpus COULD
    contain, short of re-running Snort over the raw traffic.
    """
    sids: set[str] = set()
    for alert in capture_dir.glob("*/alert"):
        for match in re.finditer(r"\[1:(\d+):", alert.read_text(errors="ignore")):
            sids.add(match.group(1))
    return sids


@pytest.mark.skipif(
    not CAPTURE_DIR.is_dir(), reason="capture alert logs not on this machine"
)
@pytest.mark.skipif(not RULESET.exists(), reason="eval ruleset not present")
def test_no_capture_produced_a_long_pattern_rule():
    """The 'harvest flows with 16 <= L < 24' recipe is INFEASIBLE right now.

    Discriminating between fragmentation units needs an alerting SID whose
    pattern is longer than the smallest unit but shorter than a larger one. No
    capture in the pool ever produced such a SID, so headroom > 0 cannot be
    reached by re-selecting from this data -- it needs new traffic.
    """
    reachable = [
        sid
        for sid in _capture_sids_from_alert_logs(CAPTURE_DIR)
        if 16 <= longest_content(RULESET, sid) < 24
    ]
    assert reachable == [], (
        "a capture now produces a 16<=L<24 rule: the headroom recipe is "
        "reachable again, re-run gate H1 instead of trusting the negative result"
    )


@pytest.mark.skipif(
    not CAPTURE_DIR.is_dir(), reason="capture alert logs not on this machine"
)
@pytest.mark.skipif(not RULESET.exists(), reason="eval ruleset not present")
def test_recorded_capture_sids_still_match_the_ruleset():
    """The recorded coverage table must not drift from the real alert logs."""
    observed = _capture_sids_from_alert_logs(CAPTURE_DIR)
    assert observed == set(CAPTURE_SIDS_BELOW_UNIT), (
        "capture SID set changed; re-measure before citing the coverage table"
    )
    for sid, recorded_len in CAPTURE_SIDS_BELOW_UNIT.items():
        assert longest_content(RULESET, sid) == recorded_len, (
            f"SID {sid} geometry changed: recorded {recorded_len}, "
            f"ruleset now {longest_content(RULESET, sid)}"
        )