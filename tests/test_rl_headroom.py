"""TDD: controls/rl_headroom.py — best_single / oracle / headroom + obs
separability diagnostic from a ceiling sweep report."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "controls"))


def _fixture(tmp_path):
    # 3 flows: f1 only split8 wins; f2 only split_slow wins; f3 both win.
    cells = []

    def add(fid, framing, mech, valid):
        cells.append({"flow_id": fid, "framing": framing, "mech": mech,
                      "evaded": valid, "semantics_ok": True,
                      "valid_evasion": valid, "baseline_alert": True})

    add("f1", "dns", "split8", True);   add("f1", "dns", "split_slow", False)
    add("f2", "dns", "split8", False);  add("f2", "dns", "split_slow", True)
    add("f3", "http", "split8", True);  add("f3", "http", "split_slow", True)
    p = tmp_path / "sweep.json"
    p.write_text(json.dumps({"ownership": "client", "cells": cells,
                             "n_flows": 3}))
    return p


def test_best_single_oracle_headroom(tmp_path):
    from rl_headroom import summarize
    s = summarize(_fixture(tmp_path))
    assert s["best_single"] == {"mech": "split8", "valid": 2}
    assert s["oracle"] == 3
    assert s["headroom"] == 1


def test_per_flow_required_mechs(tmp_path):
    from rl_headroom import summarize
    s = summarize(_fixture(tmp_path))
    # flows where ONLY the slow mechanism wins vs only the fast one
    assert s["flows_only_split_slow"] == ["f2"]
    assert s["flows_only_split8"] == ["f1"]


def test_unique_winner_sets_counts_distinct_structures(tmp_path):
    from rl_headroom import summarize
    s = summarize(_fixture(tmp_path))
    # {split8}, {split_slow}, {split8, split_slow} = 3 distinct winner sets
    assert s["unique_winner_sets"] == 3
