#!/usr/bin/env python3
"""RL substantive-claim verdict (P5, plan 2026-10-12_112442).

Question: does ANY measured regime on corpus v3fixed give an RL policy room to
beat the best FIXED mechanism (headroom = oracle - best_single > 0)?  If not,
no honest "RL beats fixed heuristic" claim exists on this corpus, and the
thesis must say so instead of overclaiming.

Regimes measured (all real Snort, fixed_6_fixes scoring, two-stream byte bar):
  R1 ownership=both, ET Open full      -> P3 evals + ceiling reports
  R2 ownership=client, ET Open full    -> ceiling_v3_client_{test,train}.json
  R3 mixed-tier client (http flows under httpinspect conf, dns/irc under full)
                                       -> ceiling_v3_client_httpinspect_*.json
                                          merged in ceiling_v3_mixed_test.json
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "controls"))

from rl_headroom import summarize  # noqa: E402

REPORTS = ROOT / "snort_validation" / "reports"


def merge_matrix(full_path: Path, httpinspect_path: Path) -> dict:
    """Mixed-tier matrix: http flows take httpinspect cells, dns/irc full-conf."""
    full = json.loads(Path(full_path).read_text())
    hi = json.loads(Path(httpinspect_path).read_text())
    hi_ids = {c["flow_id"] for c in hi["cells"]}
    cells = [c for c in full["cells"] if c["flow_id"] not in hi_ids] + hi["cells"]
    return {"ownership": full["ownership"], "n_flows": len({c["flow_id"] for c in cells}),
            "conf": "mixed (http -> httpinspect, dns/irc -> full ET)", "cells": cells}


def integrity(cells: list) -> str:
    base = {}
    for c in cells:
        base.setdefault(c["flow_id"], c["baseline_alert"])
    noop_evaded = sum(c["evaded"] for c in cells if c["mech"] == "noop")
    return (f"baseline alerted {sum(base.values())}/{len(base)} | "
            f"noop evaded {noop_evaded}")


def main() -> int:
    rows = []

    # R2: client, full conf
    for split in ("test", "train"):
        p = REPORTS / f"ceiling_v3_client_{split}.json"
        s = summarize(p)
        d = json.loads(p.read_text())
        rows.append((f"R2 client/full ({split})", s, integrity(d["cells"])))

    # R3: mixed tier (test)
    merged = merge_matrix(REPORTS / "ceiling_v3_client_test.json",
                          REPORTS / "ceiling_v3_client_httpinspect_test.json")
    dst = REPORTS / "ceiling_v3_mixed_test.json"
    dst.write_text(json.dumps(merged, indent=1))
    rows.append(("R3 mixed-tier client (test)", summarize(dst), integrity(merged["cells"])))

    print(f"{'regime':38s} best_single  oracle  headroom  winner_sets  integrity")
    any_headroom = False
    for name, s, ig in rows:
        hr = s["headroom"]
        any_headroom |= hr > 0
        print(f"{name:38s} {s['best_single']['mech']}={s['best_single']['valid']:2d}  "
              f"{s['oracle']:5d}  {hr:7d}  {s['unique_winner_sets']:11d}  {ig}")

    print()
    if any_headroom:
        print("VERDICT: headroom exists in at least one regime -> train RL there (Phase 3/5).")
        return 0
    print("VERDICT: NO-CLAIM. In every measured regime best_single == oracle:")
    print("a constant mechanism is optimal, so no policy can beat the best fixed")
    print("heuristic on this corpus. An honest 'RL beats fixed' claim requires a")
    print("corpus with SID families whose match geometry differs (see verdict doc).")
    return 10


if __name__ == "__main__":
    sys.exit(main())
