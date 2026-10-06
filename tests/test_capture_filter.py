"""Capture filtering, so a leave-one-capture-out run is expressible.

The pooled split puts both captures in train AND test, so no result from it
supports a cross-capture claim.  These tests pin the filter that makes an
honest capture-disjoint run possible, and pin the confound the report must
disclose.
"""
import pathlib
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))

from hidden_defender_env import load_corpus  # noqa: E402

CAPTURE_HTTP = "botnet-capture-20110811-neris"   # framing == "http"
CAPTURE_NERIS = "botnet-capture-20110819-bot"    # framing == "neris"


def test_capture_filter_returns_only_that_capture():
    flows = load_corpus("all", capture=CAPTURE_HTTP)
    assert flows, "expected flows for the http capture"
    assert {f["capture"] for f in flows} == {CAPTURE_HTTP}


def test_loco_directions_are_disjoint():
    a = {f["flow_id"] for f in load_corpus("all", capture=CAPTURE_HTTP)}
    b = {f["flow_id"] for f in load_corpus("all", capture=CAPTURE_NERIS)}
    assert a and b, "both captures must have flows"
    assert not (a & b), "a flow must never be in both LOCO directions"


def test_split_all_spans_both_splits():
    n_all = len(load_corpus("all"))
    n_train = len(load_corpus("train"))
    n_test = len(load_corpus("test"))
    assert n_all == n_train + n_test


def test_unknown_filter_is_an_error():
    import pytest
    with pytest.raises(ValueError):
        load_corpus("all", capture="does-not-exist")


def test_capture_is_confounded_with_framing():
    """Documentation of the confound: this is why LOCO cannot isolate capture."""
    a = {f["framing"] for f in load_corpus("all", capture=CAPTURE_HTTP)}
    b = {f["framing"] for f in load_corpus("all", capture=CAPTURE_NERIS)}
    assert a == {"http"} and b == {"neris"}
