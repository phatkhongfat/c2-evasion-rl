"""The probe validator must accept a known-good P3-style report and reject
tampered ones.  A validator that cannot fail is not a check."""
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path("/root/.hermes/c2-evasion-rl")
sys.path.insert(0, str(REPO / "controls"))
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))

from validate_div_probe import validate_pair  # noqa: E402

GOOD = REPO / "snort_validation/reports/ppo_v3_both_test_s42.json"
GOOD_TRAIN = REPO / "snort_validation/reports/ppo_v3_train_s42.json"


def test_known_good_p3_report_passes():
    problems = validate_pair(GOOD_TRAIN, GOOD)
    assert problems == [], f"good report flagged: {problems}"


def test_tampered_valid_count_is_rejected(tmp_path):
    d = json.loads(GOOD.read_text())
    d["valid_evasion"] = d["valid_evasion"] - 1      # aggregate != per-flow sum
    p = tmp_path / "bad.json"
    p.write_text(json.dumps(d))
    problems = validate_pair(GOOD_TRAIN, p)
    assert any("aggregate" in x for x in problems)


def test_missing_baseline_control_is_rejected(tmp_path):
    d = json.loads(GOOD.read_text())
    d["baseline_alert_pct"] = 97.5                   # control must be 100
    p = tmp_path / "bad.json"
    p.write_text(json.dumps(d))
    problems = validate_pair(GOOD_TRAIN, p)
    assert any("baseline" in x for x in problems)


def test_semantics_break_is_rejected(tmp_path):
    d = json.loads(GOOD.read_text())
    d["semantics_breaks"] = 1
    p = tmp_path / "bad.json"
    p.write_text(json.dumps(d))
    problems = validate_pair(GOOD_TRAIN, p)
    assert any("semantics" in x for x in problems)


def test_train_report_self_consistency_is_enforced(tmp_path):
    t = json.loads(GOOD_TRAIN.read_text())
    t["queries"] = t["epochs"] * t["n_flows"] + 1    # impossible
    p = tmp_path / "bad_train.json"
    p.write_text(json.dumps(t))
    problems = validate_pair(p, GOOD)
    assert any("queries" in x for x in problems)


def test_p3_report_not_required_to_have_diversity_coef():
    """The diversity_coef self-declaration is a P4-only requirement: the P3
    train reports predate the flag, and the validator must not retroactively
    fail them (they are the positive control)."""
    problems = validate_pair(GOOD_TRAIN, GOOD)
    assert problems == [], f"P3 positive control flagged: {problems}"
