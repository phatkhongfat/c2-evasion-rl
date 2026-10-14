"""RED: multi-byte hex tokens in `|...|` content blocks.

Snort lets `|58 06|` and `|5806|` both mean the two bytes 0x58 0x06. The
parser did `int(tok, 16)` per whitespace-separated token, so `|5806|` raised
`ValueError: byte must be in range(0, 256)`. 72 of the 21374 alert rules in
`et_open_c2/suricata.rules` contain such a token, which is why the corpus had
to be built via `for_sids` on a handful of Snort-2.9 SIDs instead of the full
ruleset.
"""
from pathlib import Path
import sys

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "snort_validation"))

from real_rules_replica import parse_ruleset, RULES  # noqa: E402


def test_spaced_hex_tokens_are_byte_pairs():
    from real_rules_replica import parse_content
    assert parse_content("|58 06|") == b"\x58\x06"


def test_unspaced_multi_byte_hex_token_is_split_into_pairs():
    from real_rules_replica import parse_content
    assert parse_content("|5806|") == b"\x58\x06"


def test_long_hex_token_splits_into_pairs():
    from real_rules_replica import parse_content
    assert parse_content("|0000400907000000|") == bytes.fromhex("0000400907000000")


def test_whole_ruleset_parses_without_raising():
    rules = parse_ruleset(RULES)
    assert len(rules) > 20000