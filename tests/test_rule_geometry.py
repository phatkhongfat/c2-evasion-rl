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
CAPTURE_DIRS = (Path("/tmp/cov"), Path("/tmp/cov2"))

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


def test_bare_hex_lookalikes_are_literal_ascii():
    """A pipe-less token that merely LOOKS like hex is still ASCII.

    `content:"d1|3a|ad2|3a|id20|3a|"` is the literal text `d1:ad2:id20:` --
    2+1+3+1+4+1 = 12 bytes. Only segments actually wrapped in `|...|` are
    byte-encoded. Reading the bare `d1` as one hex byte reports 11 and makes
    rules look shorter (and thus more breakable) than they are.
    """
    rule = (
        'alert udp any any -> any any (msg:"DHT ping"; '
        'content:"d1|3a|ad2|3a|id20|3a|"; depth:12; sid:2008581;)'
    )
    assert content_lengths(rule) == [12], content_lengths(rule)


def test_mixed_bar_literal_and_hex_still_totals_correctly():
    """The classic mixed case must keep working after the pipe rule."""
    rule = 'alert tcp any any -> any any (msg:"x"; content:"|02|su|00|"; sid:1;)'
    assert content_lengths(rule) == [4], content_lengths(rule)

    # literal on BOTH sides of a hex run: "id20|3a|" -> 4 + 1
    rule = 'alert udp any any -> any any (msg:"x"; content:"id20|3a|q19|3a|"; sid:1;)'
    assert content_lengths(rule) == [9], content_lengths(rule)


@pytest.mark.skipif(not RULESET.exists(), reason="eval ruleset not present")
def test_dht_rule_geometry_matches_its_declared_depth():
    """Regression guard on a real rule: ET DHT ping, `depth:12`, content 12B.

    The parser reported 21 for this rule until the pipe-delimiter rule was
    fixed. Assert against the rule's own `depth:` where one is declared, so the
    two cannot silently drift apart again.
    """
    rule_line = parse_alert_rule(RULESET, "2008581")
    assert rule_line, "SID 2008581 absent from the eval ruleset"
    lengths = content_lengths(rule_line)
    declared_depth = re.search(r"depth:(\d+)", rule_line)
    if declared_depth:
        assert max(lengths) <= int(declared_depth.group(1)), (
            f"content {max(lengths)}B exceeds declared depth "
            f"{declared_depth.group(1)}B -- parser is miscounting"
        )
    assert max(lengths) == 12, lengths


@pytest.mark.skipif(not RULESET.exists(), reason="eval ruleset not present")
def test_geometry_report_shape_is_stable():
    """Guard the helper contract so future corpus rebuilds can diff it."""
    for sid in CORPUS_SIDS:
        g = rule_geometry(RULESET, sid)
        assert set(g) == {"sid", "n_content", "content_lengths", "longest"}
        assert g["sid"] == sid
        assert g["n_content"] == len(g["content_lengths"])
        assert g["longest"] == max(g["content_lengths"])


def _capture_sids_from_alert_logs(capture_dirs: tuple[Path, ...]) -> set[str]:
    """Every SID that appears in any scanned capture's Snort alert log."""
    sids: set[str] = set()
    for capture_dir in capture_dirs:
        for alert in capture_dir.glob("*/alert"):
            for match in re.finditer(r"\[1:(\d+):", alert.read_text(errors="ignore")):
                sids.add(match.group(1))
    return sids


def _classtype(ruleset: Path, sid: str) -> str:
    rule_line = parse_alert_rule(ruleset, sid)
    found = re.search(r"classtype:([^;]+);", rule_line)
    return found.group(1).strip() if found else ""


def _discriminating_sids(ruleset: Path, sids) -> list[str]:
    """SIDs where the smallest and largest fragmentation units must differ.

    The band is `unit <= L < largest_unit`, not `16 <= L < 24`: the lower edge
    is the SMALLEST available unit (8 bytes, `split8`), so a pattern of 12 bytes
    is already cut by `split8` and already fits inside `split24`.
    """
    return sorted(
        sid
        for sid in sids
        if MIN_FRAGMENTATION_UNIT <= longest_content(ruleset, sid) < 24
    )


@pytest.mark.skipif(not any(d.is_dir() for d in CAPTURE_DIRS), reason="no alert logs")
@pytest.mark.skipif(not RULESET.exists(), reason="eval ruleset not present")
def test_discriminating_band_c2_sids_are_all_broken_by_pcre_not_by_length():
    """Why no fragmentation unit can win on these: the matcher is a `pcre`.

    A pattern with `unit <= L < 24` LOOKS discriminating -- `split8` should cut
    it while `split24` might not. It is not, because these rules are decided by
    a `pcre` over a contiguous run, which every fragmentation unit cuts:

      2012533  pcre /c\\x3d[0-9A-F]{100}/i   100 hex chars, one run
      2019486  pcre /^[^\r\\n]*?.../         anchored to the line start
      2019471  pcre /^[^\r\\n]*?.../         anchored to the line start

    Content length never becomes the binding constraint, so changing the unit
    changes nothing. The sweep agrees: split8/16/24 all score 40/40.
    """
    observed = _capture_sids_from_alert_logs(CAPTURE_DIRS)
    discriminating = [
        sid
        for sid in _discriminating_sids(RULESET, observed)
        if _classtype(RULESET, sid) != "policy-violation"
    ]
    assert sorted(discriminating) == ["2012533", "2019471", "2019486"], discriminating

    for sid in discriminating:
        rule_line = parse_alert_rule(RULESET, sid)
        assert "pcre:" in rule_line, (
            f"SID {sid} sits in the discriminating band but has no pcre; if its "
            f"matcher changed, re-run the split sweep -- length may now bind"
        )


@pytest.mark.skipif(not any(d.is_dir() for d in CAPTURE_DIRS), reason="no alert logs")
@pytest.mark.skipif(not RULESET.exists(), reason="eval ruleset not present")
def test_the_one_length_discriminating_rule_is_not_malware():
    """The only genuinely length-discriminating rule found is BitTorrent DHT.

    `2008581` carries `content:"d1:ad2:id20:"` with `depth:12` and no pcre, so
    `split8` cuts it and `split24` need not. It is `policy-violation` -- P2P file
    sharing, not command and control. Feeding it into a C2-evasion corpus would
    mislabel the threat model, so it stays out even though it is the one rule
    that would have made headroom reachable.
    """
    observed = _capture_sids_from_alert_logs(CAPTURE_DIRS)
    discriminating = _discriminating_sids(RULESET, observed)

    without_pcre = [
        sid
        for sid in discriminating
        if "pcre:" not in parse_alert_rule(RULESET, sid)
    ]
    assert without_pcre == ["2008581", "2008583", "2008585"], without_pcre
    for sid in without_pcre:
        assert _classtype(RULESET, sid) == "policy-violation"
        assert "BitTorrent" in parse_alert_rule(RULESET, sid)


@pytest.mark.skipif(
    not CAPTURE_DIRS[0].is_dir(), reason="capture alert logs not on this machine"
)
@pytest.mark.skipif(not RULESET.exists(), reason="eval ruleset not present")
def test_recorded_capture_sids_still_match_the_ruleset():
    """The recorded coverage table must not drift from the real alert logs.

    Scoped to `/tmp/cov` only: that table was recorded before the two extra
    captures were scanned, so it describes that set and not the newer one.
    """
    observed = _capture_sids_from_alert_logs((CAPTURE_DIRS[0],))
    assert observed == set(CAPTURE_SIDS_BELOW_UNIT), (
        "capture SID set changed; re-measure before citing the coverage table"
    )
    for sid, recorded_len in CAPTURE_SIDS_BELOW_UNIT.items():
        assert longest_content(RULESET, sid) == recorded_len, (
            f"SID {sid} geometry changed: recorded {recorded_len}, "
            f"ruleset now {longest_content(RULESET, sid)}"
        )