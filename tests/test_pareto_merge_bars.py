"""Pareto oracle over MULTIPLE sweep reports + explicit bar selection.

The extended corpus was measured in two passes: p13_v8 (noop /
http_header_case / split8) and p13_v9 (query_param_prepend).  Neither file
alone holds the post-P14 action space, so the oracle has to merge cells across
reports and be told which validity column is the bar.

Bar choice matters and must be explicit, not implicit: `valid_evasion_endpoint`
is the v1 bar (single-request, pre-D7); `valid_evasion_endpoint_q` is the D7
CL-aware per-request bar; `valid_evasion_query` is the D5 query-parsed bar.
Selecting the bar by number after seeing results would be a moved goalpost --
selecting it by NAME in the CLI is just parameterisation.
"""
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "controls"))

from pareto_cost_oracle import merge_cells, bar_map  # noqa: E402


def _cells(flow_id, mech, **kw):
    base = {"flow_id": flow_id, "mech": mech, "baseline_alert": True,
            "evaded": False, "semantics_ok": True, "valid_evasion": False,
            "valid_evasion_endpoint": False,
            "valid_evasion_endpoint_q": False, "valid_evasion_query": False,
            "sids": [], "baseline_sids": [2012533]}
    base.update(kw)
    return base


def test_merge_cells_unions_reports_with_no_overlap(tmp_path):
    a = {"cells": [_cells("f1", "noop"), _cells("f1", "split8", evaded=True,
                                               valid_evasion_endpoint=True)]}
    b = {"cells": [_cells("f1", "query_param_prepend", evaded=True,
                          valid_evasion_endpoint=True,
                          valid_evasion_endpoint_q=True,
                          valid_evasion_query=True)]}
    pa, pb = tmp_path / "a.json", tmp_path / "b.json"
    pa.write_text(json.dumps(a))
    pb.write_text(json.dumps(b))
    cells = merge_cells([str(pa), str(pb)])
    assert {(c["flow_id"], c["mech"]) for c in cells} == {
        ("f1", "noop"), ("f1", "split8"), ("f1", "query_param_prepend")}


def test_merge_cells_dedupes_and_prefers_the_first_report(tmp_path):
    dup = tmp_path / "d.json"
    dup.write_text(json.dumps({"cells": [
        _cells("f1", "split8", evaded=True, valid_evasion_endpoint=True),
        _cells("f1", "split8", evaded=True, valid_evasion_endpoint=True),
    ]}))
    other = tmp_path / "o.json"
    other.write_text(json.dumps({"cells": [
        _cells("f1", "split8", evaded=False, valid_evasion_endpoint=False),
        _cells("f2", "noop"),
    ]}))
    cells = merge_cells([str(dup), str(other)])
    assert len(cells) == 2, cells                      # (f1,split8), (f2,noop)
    f1 = [c for c in cells if c["flow_id"] == "f1"][0]
    assert f1["valid_evasion_endpoint"] is True        # first report wins


def test_merge_cells_rejects_a_duplicate_from_a_different_flow_mech_pair(tmp_path):
    # A report that re-measures the SAME pair with a DIFFERENT baseline_alert
    # is a contradiction, not a union: refuse loudly instead of picking one.
    x = tmp_path / "x.json"
    x.write_text(json.dumps({"cells": [_cells("f1", "split8", baseline_alert=True)]}))
    y = tmp_path / "y.json"
    y.write_text(json.dumps({"cells": [_cells("f1", "split8", baseline_alert=False)]}))
    try:
        merge_cells([str(x), str(y)])
    except ValueError as e:
        assert "f1" in str(e) and "split8" in str(e)
    else:
        raise AssertionError("contradicting duplicate must raise")


def test_bar_map_endpoint_v1_only_sees_v1_column():
    cells = [_cells("f1", "query_param_prepend", valid_evasion_endpoint=False,
                    valid_evasion_endpoint_q=True, valid_evasion_query=True)]
    ep = bar_map(cells, "valid_evasion_endpoint")
    assert ep[("f1", "query_param_prepend")] is False


def test_bar_map_query_column():
    cells = [_cells("f1", "query_param_prepend", valid_evasion_endpoint=False,
                    valid_evasion_endpoint_q=True, valid_evasion_query=True)]
    q = bar_map(cells, "valid_evasion_query")
    assert q[("f1", "query_param_prepend")] is True


def test_bar_map_missing_column_is_false_not_keyerror():
    cells = [{"flow_id": "f1", "mech": "noop"}]       # no validity keys at all
    m = bar_map(cells, "valid_evasion_query")
    assert m[("f1", "noop")] is False