#!/usr/bin/env python3
"""Integrity validation for a diversity-probe report pair (train JSON + eval JSON).

Nine invariant checks; returns a list of human-readable problems (empty = OK).
The eval report is the fixed_6_fixes pipeline output (real Snort, two-stream
byte bar); the checks re-derive every aggregate from the per-flow rows so a
hand-edited or truncated report cannot pass.

The positive control is the P3 pair (lambda=0): a validator that cannot accept
a known-good report is worthless, and one that cannot reject a tampered report
is worse.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ai_agent"))
sys.path.insert(0, str(ROOT / "snort_validation"))


def validate_pair(train_json: Path, eval_json: Path) -> list:
    problems = []
    t = json.loads(Path(train_json).read_text())
    d = json.loads(Path(eval_json).read_text())
    rows = d.get("per_flow", [])

    # -- eval-side aggregates re-derived from per-flow rows ------------------
    n = d.get("n_flows")
    if n != len(rows):
        problems.append(f"n_flows {n} != per_flow rows {len(rows)}")
    valid = sum(bool(r["valid_evasion"]) for r in rows)
    if valid != d.get("valid_evasion"):
        problems.append(f"aggregate valid_evasion {d.get('valid_evasion')} != per-flow sum {valid}")
    for r in rows:
        recomputed = (not r["alert"]) and r["semantics_ok"]
        if bool(r["valid_evasion"]) != recomputed:
            problems.append(
                f"per-flow valid_evasion inconsistent with alert/semantics: {r['flow_id'][:40]}")
            break
    # control: every flow must alert at baseline (all-positive corpus)
    if d.get("baseline_alert_pct") != 100.0:
        problems.append(f"baseline control {d.get('baseline_alert_pct')}% != 100.0")
    if d.get("semantics_breaks") != 0:
        problems.append(f"semantics_breaks {d.get('semantics_breaks')} != 0")
    if d.get("scorer") != "real_snort":
        problems.append(f"scorer {d.get('scorer')!r} != 'real_snort'")
    # chosen action names must exist in the shipped 15-action space
    from hidden_defender_env import ACTION_NAMES
    bad_actions = [r["action"] for r in rows if r["action"] not in ACTION_NAMES]
    if bad_actions:
        problems.append(f"unknown actions chosen: {sorted(set(bad_actions))}")

    # -- train-side self-consistency ------------------------------------------
    if t.get("queries") != t.get("epochs") * t.get("n_flows"):
        problems.append(
            f"train queries {t.get('queries')} != epochs*n_flows "
            f"{t.get('epochs')}*{t.get('n_flows')}")
    if t.get("evaded", 10**9) > t.get("n_flows", 0):
        problems.append(f"train evaded {t.get('evaded')} > n_flows {t.get('n_flows')}")
    # diversity_coef is required only for P4 probe reports (P3 predates the flag)
    if "v3div" in Path(eval_json).name and "diversity_coef" not in t:
        problems.append("P4 train report missing diversity_coef key")
    return problems


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: validate_div_probe.py TRAIN.json EVAL.json")
        return 2
    problems = validate_pair(Path(sys.argv[1]), Path(sys.argv[2]))
    if problems:
        print("FAIL:")
        for p in problems:
            print(" -", p)
        return 1
    print("OK: all invariant checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
