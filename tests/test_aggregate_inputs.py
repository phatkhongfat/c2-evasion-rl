"""Tests for which files the aggregator is allowed to read as evidence.

Defect 3 (this file):  ``aggregate_results.main`` filtered the
``--cross-capture`` glob by *filename substring* only::

    cross_paths = [p for p in cross_paths if "summary" not in Path(p).name]

The glob ``cross_capture_*.json`` also matches ``cross_capture_eval.json``,
which is a different report shape entirely (``baseline_evasion`` /
``agent_evasion``, no ``deterministic_pct``).  That row failed the
required-field check and the script exited 1 *without writing anything* -- so
the committed ``cross_capture_summary.json`` silently stayed at whatever an
older run produced.  That stale file is what quoted ``baseline_detected=0``
for neris-20110811 when the per-capture report, the frozen noop control and
the PPO eval all measured 24/24.

Substring filtering cannot be made correct by adding more substrings: a new
report file will eventually match the glob again.  Selection must be decided
by SCHEMA, so the rule is: a path is cross-capture evidence iff it carries the
measurement keys a cross-capture row is built from.
"""
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))

from aggregate_results import (  # noqa: E402
    CROSS_REQUIRED_KEYS,
    is_cross_capture_report,
    select_cross_paths,
)


# --------------------------------------------------------------------------
# 1. selection is by schema, not by filename
# --------------------------------------------------------------------------

def test_a_valid_cross_capture_report_is_selected(tmp_path):
    p = tmp_path / "cross_capture_whatever-i-want.json"
    p.write_text(json.dumps({
        "capture": "cap-a", "flows": 24, "corrupt_cost": 0.6,
        "deterministic_pct": 16.666666, "deterministic_mean_corrupt": 0.62,
        "deterministic_evaded": 4, "baseline_detected": 23,
    }))
    assert is_cross_capture_report(p) is True
    assert select_cross_paths([p]) == [p]


def test_cross_capture_eval_is_rejected_despite_matching_the_glob(tmp_path):
    """The exact file that made the real run exit 1 without writing."""
    p = tmp_path / "cross_capture_eval.json"
    p.write_text(json.dumps({
        "train_capture": "ctu13", "eval_capture": "ctu13",
        "eval_size": 16, "baseline_evasion": 1.0,
        "agent_evasion": 1.0, "delta_pp": 0.0, "model": "bandit",
    }))
    assert is_cross_capture_report(p) is False
    assert select_cross_paths([p]) == []


def test_summary_and_any_derived_file_are_rejected(tmp_path):
    """The old substring rule only knew about "summary"; schema knows all."""
    p = tmp_path / "cross_capture_summary.json"
    p.write_text(json.dumps({
        "n_captures": 3, "mean_evasion_pct": 62.5,
        "summary": [{"capture": "cap-a", "evasion_pct": 87.5}],
    }))
    assert is_cross_capture_report(p) is False


def test_an_arbitrary_new_derived_file_is_rejected(tmp_path):
    """Regression guard against re-growing the substring allowlist."""
    for name in ("cross_capture_mean.json", "cross_capture_best.json",
                 "cross_capture_v2.json", "cross_capture.json"):
        p = tmp_path / name
        p.write_text(json.dumps({"some": "other", "shape": True}))
        assert is_cross_capture_report(p) is False, name


# --------------------------------------------------------------------------
# 2. a report missing ONE measurement key is not evidence
# --------------------------------------------------------------------------

def test_every_required_key_is_actually_required(tmp_path):
    base = {
        "capture": "cap-a", "flows": 24, "corrupt_cost": 0.6,
        "deterministic_pct": 100.0, "deterministic_mean_corrupt": 2.88,
        "deterministic_evaded": 24,
    }
    assert set(CROSS_REQUIRED_KEYS) <= set(base)
    for key in CROSS_REQUIRED_KEYS:
        partial = dict(base)
        partial.pop(key)
        p = tmp_path / f"cross_capture_missing_{key}.json"
        p.write_text(json.dumps(partial))
        assert is_cross_capture_report(p) is False, (
            f"{key} is read into the row but was not required for selection")


def test_a_required_key_present_but_null_is_rejected(tmp_path):
    """``null`` is a failed run, not a measurement of zero."""
    p = tmp_path / "cross_capture_null.json"
    p.write_text(json.dumps({
        "capture": "cap-a", "flows": 24, "corrupt_cost": 0.6,
        "deterministic_pct": None, "deterministic_mean_corrupt": 2.88,
        "deterministic_evaded": 24,
    }))
    assert is_cross_capture_report(p) is False


def test_a_zero_count_is_accepted(tmp_path):
    """win13 legitimately measured 0/24 -- zero is data, not absence."""
    p = tmp_path / "cross_capture_zero.json"
    p.write_text(json.dumps({
        "capture": "cap-c", "flows": 24, "corrupt_cost": 0.6,
        "deterministic_pct": 0.0, "deterministic_mean_corrupt": 0.0,
        "deterministic_evaded": 0, "baseline_detected": 24,
    }))
    assert is_cross_capture_report(p) is True


# --------------------------------------------------------------------------
# 3. unreadable / non-JSON input must not crash the aggregator
# --------------------------------------------------------------------------

def test_malformed_json_is_skipped_not_raised(tmp_path):
    p = tmp_path / "cross_capture_broken.json"
    p.write_text("{not json at all")
    assert is_cross_capture_report(p) is False
    assert select_cross_paths([p]) == []


def test_missing_file_is_skipped_not_raised(tmp_path):
    p = tmp_path / "cross_capture_absent.json"
    assert is_cross_capture_report(p) is False


# --------------------------------------------------------------------------
# 4. the real reports on disk
# --------------------------------------------------------------------------

REPORTS = REPO / "snort_validation" / "reports"


def test_real_cross_capture_reports_are_all_selected():
    found = select_cross_paths(sorted(REPORTS.glob("cross_capture_*.json")))
    names = {p.name for p in found}
    assert names == {
        "cross_capture_botnet-capture-20110810-neris.json",
        "cross_capture_botnet-capture-20110811-neris.json",
        "cross_capture_capture-win13.json",
    }, f"expected exactly the 3 per-capture reports, got {sorted(names)}"


def test_committed_summary_agrees_with_the_per_capture_reports():
    """The bug this file exists for, asserted against the real artifacts.

    ``cross_capture_summary.json`` is generated, so it may legitimately sit at
    whatever an old run produced -- but it must never *disagree* with the
    per-capture reports it summarises, or a reader has no way to tell which is
    the measurement.  Regenerate the summary and compare.
    """
    from aggregate_results import build_cross_summary

    truth = {}
    for p in select_cross_paths(sorted(REPORTS.glob("cross_capture_*.json"))):
        d = json.loads(p.read_text())
        truth[d["capture"]] = d

    summary_path = REPORTS / "cross_capture_summary.json"
    committed = json.loads(summary_path.read_text())
    for entry in committed["summary"]:
        src = truth[entry["capture"]]
        assert entry["baseline_detected"] == src["baseline_detected"], (
            f"{entry['capture']}: summary says baseline_detected="
            f"{entry['baseline_detected']} but the per-capture report measured "
            f"{src['baseline_detected']}")
        assert entry["deterministic_evaded"] == src["deterministic_evaded"], (
            f"{entry['capture']}: summary says {entry['deterministic_evaded']} "
            f"evaded but the report measured {src['deterministic_evaded']}")

    # And the value we will write must itself be self-consistent.
    fresh = build_cross_summary(
        [{"capture": d["capture"], "n_flows": d["flows"],
          "corrupt_cost": d["corrupt_cost"],
          "evasion_pct": d["deterministic_pct"],
          "mean_corrupt": d["deterministic_mean_corrupt"],
          "deterministic_evaded": d["deterministic_evaded"],
          "baseline_detected": d["baseline_detected"],
          "corrupt_all_evaded": d.get("corrupt_all_evaded"),
          "corrupt_all_mean_corrupt": d.get("corrupt_all_mean_corrupt")}
         for d in truth.values()])
    for entry in fresh["summary"]:
        src = truth[entry["capture"]]
        assert entry["baseline_detected"] == src["baseline_detected"]
        assert entry["deterministic_evaded"] == src["deterministic_evaded"]