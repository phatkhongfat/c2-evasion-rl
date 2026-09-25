#!/usr/bin/env python3
"""Grading the policy against the corrupt-all control.

Kept dependency-free (stdlib only) because two very different callers need it:
the bandit, which has torch and scapy loaded anyway, and
``aggregate_results``, which is a pure-JSON reporting tool that must stay
runnable without the ML stack.

The control corrupts the maximum reachable packet set, so no sparse subset can
evade a flow the control misses.  Beating the control therefore has exactly one
available direction: evict at least as many flows, while corrupting strictly
fewer packets.  Anything else is a tie or a loss.
"""
from __future__ import annotations

#: Verdicts, worst to best, as returned in the "verdict" key.
VERDICTS = ("loses", "tie", "beats")


def policy_beats_control(*, policy_evaded: int, n_flows: int,
                         policy_mean_corrupt: float,
                         control_mean_corrupt: float,
                         control_evaded: int | None = None) -> dict:
    """Grade the policy against the corrupt-all control.

    ``control_evaded`` defaults to ``n_flows`` -- the ceiling, i.e. assuming the
    control evades every flow it possibly can.  Grade against that unless the
    control's measured count is known, because a policy that matches the
    ceiling while corrupting fewer packets is the strongest possible result.

    Args:
        policy_evaded: flows the policy evaded (measured integer).
        n_flows: flows evaluated, the denominator for both sides.
        policy_mean_corrupt: mean corrupted packets/flow under the policy.
        control_mean_corrupt: same, under corrupt-all.
        control_evaded: flows the control evaded, if measured.

    Returns:
        dict with ``beats`` (strict win), ``verdict`` in VERDICTS, and the
        input counts plus ``corrupt_saved`` for reporting.
    """
    if control_evaded is None:
        control_evaded = n_flows
    if policy_evaded < control_evaded:
        verdict = "loses"
    elif policy_mean_corrupt < control_mean_corrupt:
        verdict = "beats"
    else:
        verdict = "tie"
    return {
        "beats": verdict == "beats",
        "verdict": verdict,
        "policy_evaded": policy_evaded,
        "control_evaded": control_evaded,
        "n_flows": n_flows,
        "policy_mean_corrupt": policy_mean_corrupt,
        "control_mean_corrupt": control_mean_corrupt,
        "corrupt_saved": control_mean_corrupt - policy_mean_corrupt,
    }
