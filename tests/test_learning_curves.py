"""Plan Task 4.2: parse_train_log handles spacing variants, skips bad lines."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "controls"))

from learning_curves import parse_train_log  # noqa: E402

FIXTURE = (
    "[*] epoch  1: 64 queries, 12/64 flows valid this epoch (18.8%)\n"
    "[*] epoch   2:   128 queries, 10/64 flows valid this epoch (15.6%)\n"
    "some other line\n"
    "[*] epoch broken: no numbers here\n"
)


def test_parse_two_valid_rows_skips_bad_lines():
    rows = parse_train_log(FIXTURE)
    assert len(rows) == 2
    assert rows[0] == {"epoch": 1, "queries": 64, "valid": 12, "n": 64, "pct": 18.8}
    assert rows[1]["epoch"] == 2 and rows[1]["queries"] == 128
    assert rows[1]["pct"] == 15.6


def test_parse_empty_text_returns_empty():
    assert parse_train_log("") == []
