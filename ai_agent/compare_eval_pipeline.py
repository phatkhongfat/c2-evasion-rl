#!/usr/bin/env python3
"""Compare the pre-fix and post-fix evaluation and write the comparison report.

Reads ``ppo_masked_test.json`` (pre-fix) and ``ppo_masked_test_FIXED.json``
(post-fix) and, when present, ``overfit_check_FIXED.json``.  Every number in the
output is read from an artefact, never typed by hand.
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
R = REPO / "snort_validation/reports"

OLD = R / "ppo_masked_test.json"
NEW = R / "ppo_masked_test_FIXED.json"
OVERFIT = R / "overfit_check_FIXED.json"
OUT = R / "eval_comparison_FIXED.json"


def load(p):
    return json.loads(p.read_text()) if p.exists() else None


def main() -> int:
    old, new, of = load(OLD), load(NEW), load(OVERFIT)
    if new is None:
        raise SystemExit(f"missing {NEW}")

    # Cross-check: the fixed report must agree with its own progress JSONL.
    prog = R / ".eval_fixed_progress.jsonl"
    if prog.exists():
        rows = [json.loads(l) for l in prog.read_text().splitlines() if l.strip()]
        assert len(rows) == new["n_flows"], (len(rows), new["n_flows"])
        assert sum(r["valid_evasion"] for r in rows) == new["valid_evasion"]

    old_actions = old.get("actions_chosen", {}) if old else {}
    old_diversity = len(old_actions)

    # Flows the old pipeline claimed to evade, by framing, for the delta view.
    per_frame = new["per_framing"]

    result = {
        "source_files": {
            "prefix": str(OLD.relative_to(REPO)), "postfix": str(NEW.relative_to(REPO)),
            "overfit": (str(OVERFIT.relative_to(REPO)) if of else None),
        },
        "prefix": {
            "scorer": old.get("scorer"), "n_flows": old.get("n_flows"),
            "valid_evasion": old.get("valid_evasion"),
            "valid_evasion_pct": old.get("valid_evasion_pct"),
            "mechanism_diversity": old_diversity, "actions_chosen": old_actions,
        } if old else None,
        "postfix": {
            "scorer": new["scorer"], "pipeline": new["pipeline"],
            "n_flows": new["n_flows"], "valid_evasion": new["valid_evasion"],
            "valid_evasion_pct": new["valid_evasion_pct"],
            "baseline_alerted": new["baseline_alerted"],
            "baseline_alert_pct": new["baseline_alert_pct"],
            "semantics_breaks": new["semantics_breaks"],
            "mechanism_diversity": new["mechanism_diversity"],
            "actions_chosen": new["actions_chosen"],
            "per_framing": per_frame,
        },
        "delta": {
            "valid_evasion_pct_pp": (
                round(new["valid_evasion_pct"] - old["valid_evasion_pct"], 1)
                if old else None),
            "mechanism_diversity_change": new["mechanism_diversity"] - old_diversity,
            "learned_more_than_two_actions": new["mechanism_diversity"] > 2,
        },
        "overfit_check": ({
            "split": of["split"], "sample_size": of["sample_size"],
            "valid_evasion_pct": of["valid_evasion_pct"],
            "test_valid_evasion_pct": new["valid_evasion_pct"],
            "generalisation_gap_pp": round(
                of["valid_evasion_pct"] - new["valid_evasion_pct"], 1),
        } if of else None),
        "answers": {
            "does_rl_still_evade_under_byte_equality": new["valid_evasion"] > 0,
            "evaded_flows": new["valid_evasion"],
            "did_it_learn_more_than_two_actions": new["mechanism_diversity"] > 2,
            "distinct_actions_used": new["mechanism_diversity"],
        },
    }
    OUT.write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))
    print(f"[+] {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
