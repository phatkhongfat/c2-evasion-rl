import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "controls"))

from sid_action_matrix import build_matrix, flow_headroom_from_cells

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


# ---------- pure function over synthetic cells ----------

def test_same_action_set_on_both_sids_gives_no_headroom():
    # Two mechanisms both clear both SIDs -> the per-SID winning sets are
    # identical, so picking one costs nothing and there is nothing to learn.
    cells = [
        _cell("f1", "split8", [], True, [2019471, 2019486]),
        _cell("f1", "http_header_case", [], True, [2019471, 2019486]),
    ]
    out = flow_headroom_from_cells(cells)
    assert out["headroom"] == 0
    assert out["reason"] == "identical action sets"


def test_disjoint_action_sets_create_headroom():
    # split8 leaves 2019486 (so it cleared 2019471); http_header_case leaves
    # 2019471 (so it cleared 2019486). The two SIDs want opposite mechanisms.
    cells = [
        _cell("f1", "split8", [2019486], True, [2019471, 2019486]),
        _cell("f1", "http_header_case", [2019471], True, [2019471, 2019486]),
    ]
    out = flow_headroom_from_cells(cells)
    assert out["headroom"] == 1
    assert set(out["per_sid_actions"]) == {"2019471", "2019486"}
    assert out["per_sid_actions"]["2019471"] == ["split8"]
    assert out["per_sid_actions"]["2019486"] == ["http_header_case"]


def test_identical_mechanism_on_both_sids_is_not_headroom():
    # split8 clears 2019471 but leaves 2019486 -> different residual sets, but
    # only one mechanism, so there is nothing to *choose*.
    cells = [_cell("f1", "split8", [2019486], True, [2019471, 2019486])]
    out = flow_headroom_from_cells(cells)
    assert out["headroom"] == 0
    assert out["reason"] == "single mechanism"


def test_flow_with_no_baseline_alert_is_skipped():
    cells = [_cell("f1", "split8", [], True, [2019471])]
    cells[0]["baseline_alert"] = False
    out = flow_headroom_from_cells(cells)
    assert out["skipped_no_baseline"] is True
    assert out["headroom"] == 0


# ---------- real report shape ----------

@pytest.fixture(scope="module")
def real_cells():
    if not REAL.exists():
        pytest.skip(f"missing {REAL}")
    return json.load(open(REAL))["cells"]


def test_real_report_loads_and_has_expected_shape(real_cells):
    assert len(real_cells) == 600
    assert {"flow_id", "mech", "sids", "baseline_sids",
            "valid_evasion", "valid_evasion_endpoint"} <= set(real_cells[0])


def test_real_report_gate_s1_is_false_under_both_bars(real_cells):
    m = build_matrix(real_cells, bar="valid_evasion")
    assert m["n_flows"] == 40
    assert m["flows_multi_sid"] == 0
    assert m["gate_s1_pass"] is False
    assert m["gate_s2_pass"] is False

    m2 = build_matrix(real_cells, bar="valid_evasion_endpoint")
    assert m2["gate_s1_pass"] is False
    assert m2["best_single"] == 40
    assert m2["headroom"] == 0


def test_real_report_only_sid_is_fakeav_c2(real_cells):
    m = build_matrix(real_cells, bar="valid_evasion")
    assert m["sids_seen"] == [2012627]