#!/usr/bin/env python3
"""RL headroom from a ceiling sweep: best_single vs oracle, and which flows
require which mechanism.  headroom = oracle - best_single is the maximum a
per-flow-selecting policy can gain over the best fixed mechanism.

P12: the tool summarises under a SELECTABLE semantics bar (``--bar``).  The
default stays ``valid_evasion`` (the byte bar) so every already-reported number
is unchanged; ``valid_evasion_endpoint`` summarises the second declared bar.

P12 defect fixes folded in here:

* ``main()`` used bare ``sys.argv[1]``/``argv[2]``.  ``SWEEP.json --corpus X``
  therefore tried to open the literal path ``--corpus`` and raised
  ``FileNotFoundError`` AFTER a partial summary had already printed.  Replaced
  with argparse.
* There was no empty-baseline filter, so a flow with nothing to evade (no
  baseline alert) counted as a free evasion and inflated BOTH ``oracle`` and
  ``best_single``.  ``--require-baseline`` (default ON on the CLI) drops such
  cells and reports ``flows_dropped_no_baseline`` so the filter is visible
  rather than silent.  A flow with nothing to evade cannot contribute to an
  evasion benchmark.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

BARS = ("valid_evasion", "valid_evasion_endpoint")


def summarize(sweep_path: Path, bar: str = "valid_evasion",
              require_baseline: bool = False) -> dict:
    """Headroom under ONE bar.

    ``bar`` names the per-cell key that decides a win (``valid_evasion`` or
    ``valid_evasion_endpoint``).  ``require_baseline`` drops cells whose
    ``baseline_alert`` is falsy -- see the module docstring.  It defaults to
    False here so existing callers keep their current numbers; the CLI defaults
    it ON.
    """
    if bar not in BARS:
        raise ValueError(f"unknown bar {bar!r}; expected one of {BARS}")
    d = json.loads(Path(sweep_path).read_text())
    cells = d["cells"]

    dropped = 0
    if require_baseline:
        all_flows = {c["flow_id"] for c in cells}
        cells = [c for c in cells if c.get("baseline_alert")]
        dropped = len(all_flows - {c["flow_id"] for c in cells})

    per_mech = Counter()
    winners = {}
    for c in cells:
        if c.get(bar, False):
            per_mech[c["mech"]] += 1
            winners.setdefault(c["flow_id"], set()).add(c["mech"])

    if require_baseline:
        n_flows = len({c["flow_id"] for c in cells})
    else:
        n_flows = d.get("n_flows") or len({c["flow_id"] for c in cells})

    if per_mech:
        best_mech, best_n = max(per_mech.items(), key=lambda kv: kv[1])
    else:
        # Degenerate input (every cell dropped / no wins) must summarise, not
        # raise on max() of an empty sequence.
        best_mech, best_n = None, 0

    oracle = len(winners)
    only = {}
    for fid, ms in winners.items():
        if len(ms) == 1:
            only.setdefault(next(iter(ms)), []).append(fid)
    return {
        "sweep": Path(sweep_path).name,
        "bar": bar,
        "ownership": d.get("ownership"),
        "n_flows": n_flows,
        "flows_dropped_no_baseline": dropped,
        "per_mech_valid": dict(per_mech.most_common()),
        "best_single": {"mech": best_mech, "valid": best_n},
        "oracle": oracle,
        "headroom": oracle - best_n,
        "flows_only_split8": sorted(only.get("split8", [])),
        "flows_only_split_slow": sorted(only.get("split_slow", [])),
        "unique_winner_sets": len({frozenset(ms) for ms in winners.values()}),
    }


def separability(matrix_path: Path, corpus_path: Path,
                 bar: str = "valid_evasion") -> dict:
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
        if c.get(bar, False):
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


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="best_single / oracle / headroom from a ceiling sweep")
    ap.add_argument("sweep", help="ceiling sweep report JSON")
    ap.add_argument("corpus_pos", nargs="?", default=None,
                    help="optional corpus pickle for the separability diagnostic")
    ap.add_argument("--corpus", default=None,
                    help="corpus pickle (flag form of the optional positional)")
    ap.add_argument("--bar", default="valid_evasion", choices=BARS,
                    help="which per-cell verdict decides a win (default: the "
                         "byte bar, so existing numbers are unchanged)")
    ap.add_argument("--require-baseline", dest="require_baseline",
                    action=argparse.BooleanOptionalAction, default=True,
                    help="drop cells whose flow has no baseline alert "
                         "(default: on); --no-require-baseline to disable")
    return ap


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    s = summarize(Path(args.sweep), args.bar, args.require_baseline)
    print(json.dumps(s, indent=1))
    corpus = args.corpus or args.corpus_pos
    if corpus:
        print(json.dumps(
            separability(Path(args.sweep), Path(corpus), args.bar), indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
