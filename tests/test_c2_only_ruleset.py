"""Unit tests for the P2P-filtered C2 ruleset generator.

Synthetic, in-memory fixtures only: the real ruleset is a 15 MB derived
artifact that must stay regenerable rather than committed, so nothing here
reads it from disk.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "controls"))
from build_c2_only_ruleset import filter_rules  # noqa: E402

DROP = ("policy-violation",)

# A rule carrying the dropped classtype (the P2P/BitTorrent family).
P2P_RULE = (
    'alert tcp $HOME_NET any -> $EXTERNAL_NET any '
    '(msg:"ET P2P BitTorrent peer sync"; classtype:policy-violation; '
    "sid:2008581; rev:9;)\n"
)
# A genuine C2 rule: classtype:trojan-activity, must be kept.
C2_RULE = (
    'alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS '
    '(msg:"ET TROJAN FakeAV Check-in"; classtype:trojan-activity; '
    "sid:2012627; rev:5;)\n"
)
# No classtype at all: must be kept (absence is not a match).
NO_CLASSTYPE_RULE = (
    'alert udp $HOME_NET any -> any 53 '
    '(msg:"ET DNS Query for something"; sid:2013016; rev:3;)\n'
)
COMMENT = "# this is a comment, preserved verbatim\n"
BLANK = "\n"


def test_dropped_classtype_line_is_removed():
    assert filter_rules([P2P_RULE], DROP) == []


def test_kept_classtype_line_survives():
    assert filter_rules([C2_RULE], DROP) == [C2_RULE]


def test_line_without_classtype_is_kept():
    assert filter_rules([NO_CLASSTYPE_RULE], DROP) == [NO_CLASSTYPE_RULE]


def test_comments_and_blanks_preserved_verbatim():
    lines = [COMMENT, BLANK, C2_RULE, BLANK]
    assert filter_rules(lines, DROP) == lines


def test_predicate_matches_classtype_anywhere_in_line():
    # The classtype sits in the middle of a long rule, not at a fixed column.
    mid = (
        'alert tcp any any -> any any (msg:"x"; content:"abc"; '
        "classtype:policy-violation; sid:1; rev:1;)\n"
    )
    assert filter_rules([mid], DROP) == []


def test_drop_is_exact_not_substring():
    # policy-violation-extra must NOT be dropped by a "policy-violation" drop.
    similar = (
        'alert tcp any any -> any any (msg:"y"; '
        "classtype:policy-violation-extra; sid:2; rev:1;)\n"
    )
    assert filter_rules([similar], DROP) == [similar]


def test_multiple_drop_classtypes():
    other = (
        'alert tcp any any -> any any (msg:"z"; classtype:not-suspicious; '
        "sid:3; rev:1;)\n"
    )
    assert filter_rules([P2P_RULE, C2_RULE, other], ("policy-violation", "not-suspicious")) == [
        C2_RULE
    ]


def test_order_is_preserved_and_blank_input_yields_empty():
    assert filter_rules([C2_RULE, P2P_RULE, NO_CLASSTYPE_RULE], DROP) == [
        C2_RULE,
        NO_CLASSTYPE_RULE,
    ]
    assert filter_rules([], DROP) == []


def test_output_is_a_list_not_an_iterator():
    out = filter_rules([C2_RULE], DROP)
    assert isinstance(out, list)
