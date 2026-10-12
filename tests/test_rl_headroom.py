"""TDD: controls/rl_headroom.py — best_single / oracle / headroom + obs
separability diagnostic from a ceiling sweep report.

P12 additions: the tool must be able to summarise under EITHER declared
semantics bar, and must be able to drop cells whose flow has an empty baseline
(nothing to evade) so the oracle is not inflated by vacuous evasions.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "controls"))


def _fixture(tmp_path):
    # 3 flows: f1 only split8 wins; f2 only split_slow wins; f3 both win.
    cells = []

    def add(fid, framing, mech, valid):
        cells.append({"flow_id": fid, "framing": framing, "mech": mech,
                      "evaded": valid, "semantics_ok": True,
                      "valid_evasion": valid, "baseline_alert": True})

    add("f1", "dns", "split8", True);   add("f1", "dns", "split_slow", False)
    add("f2", "dns", "split8", False);  add("f2", "dns", "split_slow", True)
    add("f3", "http", "split8", True);  add("f3", "http", "split_slow", True)
    p = tmp_path / "sweep.json"
    p.write_text(json.dumps({"ownership": "client", "cells": cells,
                             "n_flows": 3}))
    return p


def test_best_single_oracle_headroom(tmp_path):
    from rl_headroom import summarize
    s = summarize(_fixture(tmp_path))
    assert s["best_single"] == {"mech": "split8", "valid": 2}
    assert s["oracle"] == 3
    assert s["headroom"] == 1


def test_per_flow_required_mechs(tmp_path):
    from rl_headroom import summarize
    s = summarize(_fixture(tmp_path))
    # flows where ONLY the slow mechanism wins vs only the fast one
    assert s["flows_only_split_slow"] == ["f2"]
    assert s["flows_only_split8"] == ["f1"]


def test_unique_winner_sets_counts_distinct_structures(tmp_path):
    from rl_headroom import summarize
    s = summarize(_fixture(tmp_path))
    # {split8}, {split_slow}, {split8, split_slow} = 3 distinct winner sets
    assert s["unique_winner_sets"] == 3


# ---------------------------------------------------------------------------
# P12 T4
# ---------------------------------------------------------------------------

def test_summarize_honours_the_bar(tmp_path):
    """The two bars MUST be able to select different winners.

    If they cannot, the second bar bought nothing.
    """
    from rl_headroom import summarize
    cells = [
        {"flow_id": "f1", "mech": "split8",
         "valid_evasion": True, "valid_evasion_endpoint": False},
        {"flow_id": "f2", "mech": "http_header_pad",
         "valid_evasion": False, "valid_evasion_endpoint": True},
    ]
    p = tmp_path / "s.json"
    p.write_text(json.dumps({"cells": cells, "n_flows": 2}))
    a = summarize(p, "valid_evasion")
    b = summarize(p, "valid_evasion_endpoint")
    assert a["headroom"] == 0 and b["headroom"] == 0
    assert a["best_single"]["mech"] == "split8"
    assert b["best_single"]["mech"] == "http_header_pad"


def test_summarize_records_which_bar_it_used(tmp_path):
    from rl_headroom import summarize
    s = summarize(_fixture(tmp_path), "valid_evasion_endpoint")
    assert s["bar"] == "valid_evasion_endpoint"
    # legacy key names must survive so downstream code keeps working
    assert "best_single" in s and "oracle" in s and "headroom" in s
    assert "per_mech_valid" in s


def test_require_baseline_drops_empty_baseline_cells(tmp_path):
    """A flow with nothing to evade must not inflate oracle/best_single."""
    from rl_headroom import summarize
    cells = [
        # f1 is really detected -> evadable
        {"flow_id": "f1", "mech": "split8", "baseline_alert": True,
         "evaded": True, "valid_evasion": True},
        {"flow_id": "f1", "mech": "noop", "baseline_alert": True,
         "evaded": False, "valid_evasion": False},
        # f2 has an empty baseline -> noop "evades" vacuously
        {"flow_id": "f2", "mech": "split8", "baseline_alert": False,
         "evaded": True, "valid_evasion": True},
        {"flow_id": "f2", "mech": "noop", "baseline_alert": False,
         "evaded": True, "valid_evasion": True},
    ]
    p = tmp_path / "s.json"
    p.write_text(json.dumps({"cells": cells, "n_flows": 2}))

    off = summarize(p, "valid_evasion")
    assert off["oracle"] == 2 and off["flows_dropped_no_baseline"] == 0

    on = summarize(p, "valid_evasion", require_baseline=True)
    assert on["oracle"] == 1, "the vacuous flow must not count"
    assert on["best_single"] == {"mech": "split8", "valid": 1}
    assert on["flows_dropped_no_baseline"] == 1, "f2 is ONE flow, not 2 cells"


def test_empty_baseline_filter_does_not_crash_when_all_dropped(tmp_path):
    """Degenerate input must return a summary, not raise on max() of nothing."""
    from rl_headroom import summarize
    cells = [{"flow_id": "f1", "mech": "noop", "baseline_alert": False,
              "evaded": True, "valid_evasion": True}]
    p = tmp_path / "s.json"
    p.write_text(json.dumps({"cells": cells, "n_flows": 1}))
    s = summarize(p, "valid_evasion", require_baseline=True)
    assert s["flows_dropped_no_baseline"] == 1
    assert s["oracle"] == 0
    assert s["best_single"]["valid"] == 0


# ---------------------------------------------------------------------------
# CLI: argparse must accept --corpus (the bare sys.argv[2] defect)
# ---------------------------------------------------------------------------

def test_cli_parses_corpus_flag_without_treating_it_as_a_path(tmp_path):
    """`rl_headroom.py SWEEP.json --corpus X` used to open the literal
    '--corpus'.  argparse must consume the flag."""
    from rl_headroom import build_parser
    a = build_parser().parse_args([str(tmp_path / "s.json"),
                                   "--corpus", "corpus.pkl"])
    assert a.sweep == str(tmp_path / "s.json")
    assert a.corpus == "corpus.pkl"


def test_cli_defaults_to_require_baseline_on():
    from rl_headroom import build_parser
    a = build_parser().parse_args(["s.json"])
    assert a.require_baseline is True
    assert a.bar == "valid_evasion"


def test_cli_bar_rejects_unknown_bar():
    import pytest
    from rl_headroom import build_parser
    with pytest.raises(SystemExit):
        build_parser().parse_args(["s.json", "--bar", "nonsense"])
