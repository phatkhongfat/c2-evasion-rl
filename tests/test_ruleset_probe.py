import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "controls"))
from ruleset_probe import extra_vs_naive


def test_extra_is_set_difference():
    assert extra_vs_naive([2008581, 999, 5]) == [5, 999]


def test_naive_only_has_no_extra():
    assert extra_vs_naive([2008581, 2008583, 2008585, 2012627]) == []
