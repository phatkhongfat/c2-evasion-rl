"""Unit tests for the two-sweep diff helper (synthetic fixtures only).

The v4 sweep reports that this helper is meant to compare are produced by
long-running, Snort-heavy jobs.  The helper's contract is therefore pinned
here against in-memory report dicts that reproduce the production schema
exactly (see snort_validation/reports/ceiling_v3_expert.json), so the test
never opens a report file and never invokes Snort.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "controls"))

from compare_sweeps import diff_sweeps  # noqa: E402

FLOW_A = "cap|10.0.0.1:4001->8.8.8.8:80|tcp"
FLOW_B = "cap|10.0.0.1:4002->8.8.8.8:80|tcp"
FLOW_C = "cap|10.0.0.1:4003->8.8.8.8:80|tcp"


def _cell(flow_id, mech, valid):
    """One cell with the full production schema (extra keys must not break it)."""
    return {
        "flow_id": flow_id,
        "framing": "http",
        "mech": mech,
        "baseline_alert": True,
        "evaded": not valid,
        "semantics_ok": True,
        "valid_evasion": valid,
        "sids": [2016413],
        "baseline_sids": [2016413],
    }


def _report(cells, **extra):
    """A sweep report shaped like ceiling_v3_expert.json."""
    return {
        "ownership": "both",
        "split": "test",
        "scorer": "fixed_6_fixes",
        "conf": "shipped",
        "bar": "c2_semantics.bytes_equal_semantics",
        "cells": cells,
        "best_per_framing": {},
        "ceiling_valid_evasion": 0,
        "n_flows": 3,
        "wall_s": 1.0,
        **extra,
    }


def test_by_mech_counts_closures():
    first = _report([_cell(FLOW_A, "split8", True),
                     _cell(FLOW_B, "split8", True),
                     _cell(FLOW_C, "split8", False),
                     _cell(FLOW_C, "split_slow", True)])
    reasm = _report([_cell(FLOW_A, "split8", False),
                     _cell(FLOW_B, "split8", False),
                     _cell(FLOW_C, "split8", False),
                     _cell(FLOW_C, "split_slow", True)])
    d = diff_sweeps(first, reasm)

    assert d["by_mech"]["split8"]["first"] == 2
    assert d["by_mech"]["split8"]["reassemble"] == 0
    assert d["by_mech"]["split8"]["closed_by_reassembly"] == [FLOW_A, FLOW_B]
    assert d["by_mech"]["split8"]["opened_by_reassembly"] == []

    assert d["by_mech"]["split_slow"]["first"] == 1
    assert d["by_mech"]["split_slow"]["reassemble"] == 1
    assert d["by_mech"]["split_slow"]["closed_by_reassembly"] == []


def test_fast_splits_die_under_reassembly_but_split_slow_survives():
    # The reassembly claim: restoring the byte stream inside the window kills
    # the fast splits; split_slow holds the tail past the timeout and survives.
    first = _report([_cell(FLOW_A, "split8", True),
                     _cell(FLOW_A, "split24", True),
                     _cell(FLOW_A, "split_slow", True)])
    reasm = _report([_cell(FLOW_A, "split8", False),
                     _cell(FLOW_A, "split24", False),
                     _cell(FLOW_A, "split_slow", True)])
    d = diff_sweeps(first, reasm)

    assert d["by_mech"]["split8"]["reassemble"] < d["by_mech"]["split8"]["first"]
    assert d["by_mech"]["split24"]["reassemble"] < d["by_mech"]["split24"]["first"]
    assert d["by_mech"]["split_slow"]["reassemble"] > 0


def test_opened_by_reassembly_is_reported():
    first = _report([_cell(FLOW_A, "overlap8", False)])
    reasm = _report([_cell(FLOW_A, "overlap8", True)])
    d = diff_sweeps(first, reasm)

    assert d["by_mech"]["overlap8"]["opened_by_reassembly"] == [FLOW_A]
    assert d["by_mech"]["overlap8"]["closed_by_reassembly"] == []


def test_mech_absent_from_one_sweep_is_handled():
    first = _report([_cell(FLOW_A, "split8", True), _cell(FLOW_A, "ttl", False)])
    reasm = _report([_cell(FLOW_A, "ttl", False), _cell(FLOW_A, "noop", True)])
    d = diff_sweeps(first, reasm)

    # mech only in `first`: every prior evasion is closed.
    assert d["by_mech"]["split8"]["first"] == 1
    assert d["by_mech"]["split8"]["reassemble"] == 0
    assert d["by_mech"]["split8"]["closed_by_reassembly"] == [FLOW_A]
    # mech only in `reasm`: counted as an opening.
    assert d["by_mech"]["noop"]["first"] == 0
    assert d["by_mech"]["noop"]["reassemble"] == 1
    assert d["by_mech"]["noop"]["opened_by_reassembly"] == [FLOW_A]
    # a mech with no valid evasions in either sweep still appears.
    assert d["by_mech"]["ttl"] == {"first": 0, "reassemble": 0,
                                   "closed_by_reassembly": [],
                                   "opened_by_reassembly": []}


def test_by_flow_mirrors_closures():
    first = _report([_cell(FLOW_A, "split8", True), _cell(FLOW_B, "split8", True)])
    reasm = _report([_cell(FLOW_A, "split8", False), _cell(FLOW_B, "split8", True)])
    d = diff_sweeps(first, reasm)

    assert d["by_flow"]["split8"] == [FLOW_A]
    for m in d["by_mech"]:
        assert d["by_flow"][m] == d["by_mech"][m]["closed_by_reassembly"]


def test_does_not_mutate_inputs():
    first = _report([_cell(FLOW_A, "split8", True)])
    reasm = _report([_cell(FLOW_A, "split8", False)])
    snapshot = (repr(first), repr(reasm))
    diff_sweeps(first, reasm)
    assert (repr(first), repr(reasm)) == snapshot
