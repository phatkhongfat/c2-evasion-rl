"""Regression test for the PPO training-report schema (P1, 2026-10-11).

Bug: ``train_hidden_defender_ppo.py`` wrote ``"evaded": len(counter.solved)``
-- the CUMULATIVE distinct-flows-solved count across every epoch.  With the
train corpus reshuffled each epoch the cumulative set grows past ``n_flows``
by design (an RS64 run wrote evaded=638 while n_flows=64), so the report's
``evaded`` field violated the invariant ``evaded <= n_flows`` and the
cross-check verifier (controls/verify_report_claims.py) went red.

Fix: ``evaded`` is the PER-EPOCH number (``len(counter.epoch_solved)``);
``distinct_flows_solved_cumulative`` keeps the cumulative count under its
already-correct name.

These assertions pin the invariants the verifier relies on, so a future
regression to the cumulative number fails here first.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ai_agent"))
sys.path.insert(0, str(ROOT / "snort_validation"))

REPORTS = ROOT / "snort_validation" / "reports"


def _load(name):
    return json.loads((REPORTS / name).read_text(encoding="utf-8"))


def test_surrogate_report_evaded_is_per_epoch_not_cumulative():
    t = _load("ppo_hidden_defender.json")
    assert t["n_flows"] == 128
    assert t["scorer"] == "replica"
    # the load-bearing invariant: evaded is a per-epoch count, so it can
    # never exceed the number of flows in the epoch.
    assert t["evaded"] <= t["n_flows"]
    assert t["evasion_pct"] >= 90.0
    assert t["queries"] == t["epochs"] * t["n_flows"]


def test_surrogate_report_keeps_cumulative_field_separate():
    """The cumulative count must stay under its own (correctly named) key,
    never folded back into `evaded`."""
    t = _load("ppo_hidden_defender.json")
    if "distinct_flows_solved_cumulative" in t:
        # cumulative is allowed to exceed n_flows (corpus reshuffled per epoch)
        assert t["distinct_flows_solved_cumulative"] >= t["evaded"]


def test_realsnort_report_evaded_is_per_epoch():
    t2 = _load("ppo_realsnort_train.json")
    assert t2["evaded"] <= t2["n_flows"]
    assert t2["queries"] == t2["epochs"] * t2["n_flows"]
    assert t2["evasion_pct"] >= 90.0
