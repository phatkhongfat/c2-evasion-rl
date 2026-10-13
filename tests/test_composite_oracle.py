import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "controls"))

from composite_oracle import composite_headroom, greedy_cover

REAL = REPO / "snort_validation/reports/ceiling_v4_both_test_dualbar.json"


def _cell(fid, mech, sids, valid, baseline_sids=None):
    return {
        "flow_id": fid,
        "mech": mech,
        "baseline_alert": True,
        "baseline_sids": baseline_sids if baseline_sids is not None else sids,
        "sids": sids,
        "valid_evasion": valid,
        "valid_evasion_endpoint": valid,
    }


# ---------- pure function ----------

def test_no_single_mechanism_wins_but_cover_does_is_compositional():
    # split8 leaves 2014169; http_header_case leaves 2012627. Neither wins alone.
    cells = [
        _cell("f1", "split8", [2014169], False, [2012627, 2014169]),
        _cell("f1", "http_header_case", [2012627], False, [2012627, 2014169]),
    ]
    out = composite_headroom(cells)
    assert out["compositional_flows"] == ["f1"]
    assert out["composite_headroom"] == 1
    assert out["per_flow"]["f1"]["cover"] == ["split8", "http_header_case"]


def test_single_mechanism_already_wins_is_not_compositional():
    cells = [_cell("f1", "split8", [], True, [2012627, 2014169])]
    assert composite_headroom(cells)["compositional_flows"] == []


def test_all_flows_single_winnable_gives_zero_composite_headroom():
    cells = [_cell("f1", "split8", [], True, [2012627]),
             _cell("f2", "split16", [], True, [2012627])]
    out = composite_headroom(cells)
    assert out["compositional_flows"] == []
    assert out["composite_headroom"] == 0


def test_uncovered_residual_sid_is_reported_not_claimed_as_headroom():
    # http_header_case kills 2012627 but leaves 2014169 -> a singleton cover
    # (http_header_case) is already a *single* mechanism, so this is NOT
    # compositional: it would just be a better single mechanism.
    cells = [_cell("f1", "http_header_case", [2014169], False, [2012627, 2014169])]
    out = composite_headroom(cells)
    assert out["compositional_flows"] == []
    assert out["near_miss_flows"] == ["f1"]


def test_greedy_cover_picks_minimum_family():
    cover = {
        "split8": {"a", "b"},
        "http_header_case": {"b"},
        "http_header_pad": {"c"},
    }
    # greedy selection order, largest remaining coverage first
    assert greedy_cover({"a", "b", "c"}, cover) == ["split8", "http_header_pad"]


def test_greedy_cover_returns_none_when_a_sid_is_untouchable():
    assert greedy_cover({"a", "z"}, {"split8": {"a"}}) is None


# ---------- real report ----------

@pytest.fixture(scope="module")
def real_cells():
    if not REAL.exists():
        pytest.skip(f"missing {REAL}")
    return json.load(open(REAL))["cells"]


@pytest.mark.parametrize("bar", ["valid_evasion", "valid_evasion_endpoint"])
def test_real_report_composite_headroom_is_zero_under_both_bars(real_cells, bar):
    """2026-10-13 measurement: only 16 of the 40 flows carry an in-threat-model
    SID (the other 24 alert only on BitTorrent DHT, which P11.6 put outside the
    C2 threat model), and on all 16 a single mechanism already clears the bar.
    So the compositional set is empty. This is a PROOF of zero, not a gap."""
    out = composite_headroom(real_cells, bar=bar)
    assert out["composite_headroom"] == 0
    assert out["compositional_flows"] == []
    assert out["flows_evaluated"] == 16