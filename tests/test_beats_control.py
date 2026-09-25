"""Tests for beating the corrupt-all control (the thing we must actually do).

Two defects motivated this file:

1.  ``snort_bandit`` documents the break-even corruption cost as
    ``EVASION_BONUS / ACTION_MAX_PACKETS`` (10/32 = 0.3125).  That divisor is
    the width of the ACTION space, not the number of packets that actually
    carry a payload and can therefore be corrupted.  On real captures only
    ~0.6-10.5 packets per flow are corruptable, so the real break-even is
    3-10x higher and every cost we ever swept (0.2-1.0) made "corrupt
    everything" the reward-optimal action.  Hence ``deterministic_mean_corrupt``
    == ``corrupt_all_mean_corrupt`` on all three cross-capture reports: the
    policy had nothing to learn.

2.  ``aggregate_results.rows_from_cross`` recomputes ``deterministic_evaded``
    as ``round(evasion_pct * n_flows / 100)`` instead of reading the measured
    integer.  A 1-percentage-point rounding error moves the count, and the
    stale summary then disagrees with the report it was built from.
"""
import json
import sys
from pathlib import Path

import numpy as np
import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))

from snort_bandit import (  # noqa: E402
    ACTION_MAX_PACKETS,
    CORRUPT_COST,
    EVASION_BONUS,
    break_even_cost,
    corrupt_targets,
    policy_beats_control,
)
from aggregate_results import rows_from_cross  # noqa: E402


# --------------------------------------------------------------------------
# 1. break-even cost must be derived from ACHIEVABLE corruption, not action width
# --------------------------------------------------------------------------

def test_break_even_uses_corruptable_count_not_action_width():
    """The 0.3125 figure assumed 32 corruptable packets; real flows have ~3."""
    a_flow_with_3_payload_pkts = 3
    assert break_even_cost(a_flow_with_3_payload_pkts) == pytest.approx(
        EVASION_BONUS / 3, rel=1e-6)
    # and it must NOT be the old action-space-derived constant
    assert break_even_cost(3) != pytest.approx(EVASION_BONUS / ACTION_MAX_PACKETS)


def test_break_even_rises_when_fewer_packets_are_corruptable():
    assert break_even_cost(1) > break_even_cost(4) > break_even_cost(20)


def test_default_cost_makes_corrupt_all_suboptimal_on_a_real_capture():
    """20110819-bot corrupts 10.5 packets/flow under corrupt-all.

    At the shipped default cost, corrupting all 10.5 must net out NEGATIVE,
    otherwise the reward prefers the control and the policy cannot beat it.
    """
    n_corruptable = 10.5
    net = EVASION_BONUS - CORRUPT_COST * n_corruptable
    assert net <= 0, (
        f"corrupt-all nets {net:+.2f} at cost {CORRUPT_COST}; the cost penalty "
        f"is too weak for the policy to ever prefer a sparse plan")


def test_zero_corruptable_flow_is_unreachable_not_a_div_by_zero():
    """A flow with no payload cannot be corrupted at any price.

    ``inf`` is the correct answer: no cost makes blanket corruption break even
    when there is nothing to corrupt.  What must NOT happen is a ZeroDivision
    or a NaN that would silently poison a cost sweep.
    """
    result = break_even_cost(0)
    assert result == float("inf")
    assert not np.isnan(result)
    # a negative count is nonsense, not a negative price
    assert break_even_cost(-5) == float("inf")


# --------------------------------------------------------------------------
# 2. aggregator must trust the measurement, not re-derive it from a percentage
# --------------------------------------------------------------------------

def test_rows_from_cross_preserves_measured_counts(tmp_path):
    report = {
        "capture": "cap-a", "flows": 24, "corrupt_cost": 0.6,
        "deterministic_pct": 16.666666, "deterministic_mean_corrupt": 0.62,
        "deterministic_evaded": 4,        # measured
        "baseline_detected": 23,
        "random_evaded": 2,
        "corrupt_all_evaded": 4,
        "corrupt_all_mean_corrupt": 0.62,
    }
    p = tmp_path / "cross_capture_cap-a.json"
    p.write_text(json.dumps(report))

    row = rows_from_cross([p], "stratosphere")[0]
    # round(16.666666 * 24 / 100) == 4, so use a case where the two DISAGREE:
    assert row["deterministic_evaded"] == 4


def test_rows_from_cross_does_not_reround_through_percentage(tmp_path):
    """With 50 flows the percentage is coarse: 6.0% -> 3, but 6.1% -> 3.05 -> 3.

    The decisive case is a percentage that rounds to a DIFFERENT integer than
    the measured count.  3 evaded of 50 = 6.0%, and the float arithmetic
    6.0*50/100 == 3.0, so instead force a value where re-derivation breaks:
    4 evaded of 50 = 8.0%, but if the report stored 8.4 the old code yields 4.2
    -> 4. Use a true disagreement: measured 5, stored pct 8.0 -> old gives 4.
    """
    report = {
        "capture": "cap-b", "flows": 50, "corrupt_cost": 0.6,
        "deterministic_pct": 8.0,
        "deterministic_mean_corrupt": 1.5,
        "deterministic_evaded": 5,        # the truth
        "baseline_detected": 50,
    }
    p = tmp_path / "cross_capture_cap-b.json"
    p.write_text(json.dumps(report))

    row = rows_from_cross([p], "ctu13")[0]
    assert row["deterministic_evaded"] == 5, (
        "aggregator re-derived the count from the rounded percentage; it must "
        "carry the measured integer through unchanged")


def test_cross_row_carries_the_control_columns(tmp_path):
    """The whole point is comparing against corrupt-all, so the control must
    survive aggregation instead of being dropped."""
    report = {
        "capture": "cap-c", "flows": 24, "corrupt_cost": 0.6,
        "deterministic_pct": 100.0, "deterministic_mean_corrupt": 2.88,
        "deterministic_evaded": 24, "baseline_detected": 24,
        "corrupt_all_evaded": 24, "corrupt_all_mean_corrupt": 2.88,
        "corrupt_all_pct": 100.0,
    }
    p = tmp_path / "cross_capture_cap-c.json"
    p.write_text(json.dumps(report))
    row = rows_from_cross([p], "stratosphere")[0]
    assert row["corrupt_all_evaded"] == 24
    assert row["corrupt_all_mean_corrupt"] == 2.88


# --------------------------------------------------------------------------
# 3. the pass/fail gate itself
# --------------------------------------------------------------------------

def test_beats_control_requires_fewer_corruptions_not_merely_equal_evasion():
    """Equal eviction with equal corruption is a TIE, not a win."""
    same = policy_beats_control(policy_evaded=24, n_flows=24,
                               policy_mean_corrupt=2.88,
                               control_mean_corrupt=2.88)
    assert same["beats"] is False
    assert same["verdict"] == "tie"


def test_beats_control_flags_a_real_win():
    """The greedy probe found 24/24 at 2.00 vs the control's 24/24 at 2.88."""
    win = policy_beats_control(policy_evaded=24, n_flows=24,
                               policy_mean_corrupt=2.00,
                               control_mean_corrupt=2.88)
    assert win["beats"] is True
    assert win["verdict"] == "beats"
    assert win["corrupt_saved"] == pytest.approx(0.88, rel=1e-6)


def test_beats_control_penalises_losing_on_evasion():
    """Fewer corruptions does not excuse evicting fewer flows."""
    loss = policy_beats_control(policy_evaded=22, n_flows=24,
                                policy_mean_corrupt=1.0,
                                control_mean_corrupt=10.5)
    assert loss["beats"] is False
    assert loss["verdict"] == "loses"
