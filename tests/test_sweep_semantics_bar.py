"""The sweep must declare which semantics bar produced semantics_ok.

A sweep written before commit 40fffdf records the OLD relaxed rule in that
column; if its ceiling is quoted as if it were the strict bar, every number
downstream is wrong.  Recording the bar and refusing unknown bars closes that
hole.
"""
import json
import pathlib
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "controls"))


def test_sweep_records_semantics_bar():
    src = (REPO / "controls" / "surrogate_sweep_14mech.py").read_text()
    assert '"semantics_bar"' in src


def test_ceiling_report_refuses_sweep_without_bar(tmp_path):
    import ceiling_report

    stale = {"rows": [{"flow_idx": 0, "framing": "http", "mech": "split8",
                       "semantics_ok": True, "real_alert": False,
                       "masked_out": False}]}
    p = tmp_path / "stale.json"
    p.write_text(json.dumps(stale))
    try:
        ceiling_report.load(p)
    except ValueError as exc:
        assert "semantics_bar" in str(exc)
    else:
        raise AssertionError("a sweep without a declared bar must be refused")
