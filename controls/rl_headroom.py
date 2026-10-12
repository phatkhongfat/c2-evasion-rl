#!/usr/bin/env python3
"""RL headroom from a ceiling sweep: best_single vs oracle, and which flows
require which mechanism.  headroom = oracle - best_single is the maximum a
per-flow-selecting policy can gain over the best fixed mechanism.
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path


def summarize(sweep_path: Path) -> dict:
    d = json.loads(Path(sweep_path).read_text())
    per_mech = Counter()
    winners = {}
    for c in d["cells"]:
        per_mech[c["mech"]] += bool(c["valid_evasion"])
        if c["valid_evasion"]:
            winners.setdefault(c["flow_id"], set()).add(c["mech"])
    n_flows = d.get("n_flows") or len({c["flow_id"] for c in d["cells"]})
    best_mech, best_n = max(per_mech.items(), key=lambda kv: kv[1])
    oracle = len(winners)
    only = {}
    for fid, ms in winners.items():
        if len(ms) == 1:
            only.setdefault(next(iter(ms)), []).append(fid)
    return {
        "sweep": Path(sweep_path).name,
        "ownership": d.get("ownership"),
        "n_flows": n_flows,
        "per_mech_valid": dict(per_mech.most_common()),
        "best_single": {"mech": best_mech, "valid": best_n},
        "oracle": oracle,
        "headroom": oracle - best_n,
        "flows_only_split8": sorted(only.get("split8", [])),
        "flows_only_split_slow": sorted(only.get("split_slow", [])),
        "unique_winner_sets": len({frozenset(ms) for ms in winners.values()}),
    }


def separability(matrix_path: Path, corpus_path: Path) -> dict:
    """Diagnostic: can (obs, framing) separate flows by their required winner
    set?  Reports per-feature mean gap between the two largest winner groups.
    Not a gate -- informs whether an obs-conditioned policy CAN beat a constant.
    """
    import pickle

    ROOT = Path(__file__).resolve().parents[1]
    for sub in ("snort_validation", "ai_agent"):
        p = str(ROOT / sub)
        if p not in sys.path:
            sys.path.insert(0, p)

    d = json.loads(Path(matrix_path).read_text())
    winners = {}
    for c in d["cells"]:
        if c["valid_evasion"]:
            winners.setdefault(c["flow_id"], set()).add(c["mech"])
    data = pickle.load(open(corpus_path, "rb"))
    flows = {f["flow_id"]: f for f in data["test"] + data["train"]}
    groups = {}
    for fid, ms in winners.items():
        groups.setdefault(frozenset(ms), []).append(fid)
    top2 = sorted(groups.values(), key=len, reverse=True)[:2]
    if len(top2) < 2:
        return {"separable_signal": None, "note": "fewer than 2 winner groups"}
    import numpy as np
    a = np.array([flows[f]["obs"] for f in top2[0] if f in flows])
    b = np.array([flows[f]["obs"] for f in top2[1] if f in flows])
    if not len(a) or not len(b):
        return {"separable_signal": None, "note": "winner flows missing from corpus"}
    gap = np.abs(a.mean(0) - b.mean(0))
    return {"group_sizes": [len(top2[0]), len(top2[1])],
            "obs_feature_mean_gap": [round(float(x), 3) for x in gap]}


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: rl_headroom.py SWEEP.json [CORPUS.pkl]")
        return 2
    s = summarize(Path(sys.argv[1]))
    print(json.dumps(s, indent=1))
    if len(sys.argv) > 2:
        print(json.dumps(separability(Path(sys.argv[1]), Path(sys.argv[2])), indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
