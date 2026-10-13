import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "controls"))

from sid_diversity import summarize

P2P = {2008581, 2008583, 2008585}


def test_single_sid_flows_are_counted_but_not_multi():
    per = {"f1": [2012627], "f2": [2012627]}
    s = summarize(per, P2P)
    assert s["flows_alerting"] == 2
    assert s["flows_multi_sid"] == 0
    assert s["max_sids_per_flow"] == 1


def test_p2p_sids_are_excluded_before_counting():
    per = {"f1": [2008581, 2008583], "f2": [2012627]}
    s = summarize(per, P2P)
    assert s["flows_alerting"] == 1
    assert s["flows_multi_sid"] == 0
    # reports the SIDs actually removed, not the whole exclusion constant
    assert s["excluded_p2p_sids"] == [2008581, 2008583]


def test_two_in_model_sids_on_one_flow_is_the_gate():
    per = {"f1": [2019471, 2019486]}
    s = summarize(per, P2P)
    assert s["flows_multi_sid"] == 1
    assert s["gate_s1_pass"] is True


def test_empty_input_is_not_a_pass():
    assert summarize({}, P2P)["gate_s1_pass"] is False


def test_measured_shape_is_the_real_distribution():
    """Regression guard for the 2026-10-13 measurement: on the current ruleset
    only 16 of 40 flows carry an in-threat-model SID, and the distribution is
    {1: 16, 0: 24} -- no flow has >=2. Guard S1 must therefore be False."""
    per = {f"f{i}": [2008581, 2008583] for i in range(24)}
    per.update({f"g{i}": [2012627] for i in range(16)})
    s = summarize(per, P2P)
    assert s["flows_alerting"] == 16
    assert s["gate_s1_pass"] is False
    assert s["threat_model_denominator"] == 16
    assert s["n_flows"] == 40