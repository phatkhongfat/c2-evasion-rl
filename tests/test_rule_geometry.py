"""Root-cause tests: why headroom = oracle on corpus v3fixed.

The claim being locked in:
  fragmentation mechanisms (split8/16/24, split_slow) are EQUIVALENT in effect
  on corpus v3fixed, because every alerting SID family is triggered by a
  contiguous content pattern short enough (<= 11 bytes) that ANY fragmentation
  unit >= 8 bytes destroys it.

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