"""Max valid evasion achievable per flow, over all 14 mechanisms.

Reads a sweep produced under the STRICT bar and reports, per framing, how many
flows have at least one mechanism that evades real Snort with semantics intact
and is not masked out.  That count is the ceiling: no policy can score above it
on the same flows, so a policy at 40% against a 40% ceiling is not undertrained.
"""
from __future__ import annotations

import argparse
import collections
import json
from pathlib import Path

BAR = "c2_semantics.bytes_equal_semantics"


def load(path: Path) -> dict:
    d = json.loads(path.read_text())
    if d.get("semantics_bar") != BAR:
        raise ValueError(
            f"{path.name} has no usable semantics_bar (declared "
            f"{d.get('semantics_bar')!r}, need {BAR!r}); re-run it.")
    return d


def ceiling(d: dict) -> dict:
    by_flow: dict = collections.defaultdict(list)
    for r in d["rows"]:
        if r.get("real_alert") is None:
            continue                      # mechanism could not be applied
        by_flow[r["flow_idx"]].append(r)

    agg: dict = {}
    for rows in by_flow.values():
        framing = rows[0]["framing"]
        ok = [r["mech"] for r in rows
              if r.get("semantics_ok") and not r.get("masked_out")
              and not r["real_alert"]]
        slot = agg.setdefault(framing, {"flows": 0, "reachable": 0,
                                        "mechs": collections.Counter()})
        slot["flows"] += 1
        slot["reachable"] += bool(ok)
        for m in ok:
            slot["mechs"][m] += 1

    return {
        fr: {"flows": v["flows"],
             "reachable": v["reachable"],
             "ceiling_pct": round(100.0 * v["reachable"] / v["flows"], 1),
             "viable_mech_counts": dict(v["mechs"].most_common())}
        for fr, v in agg.items()
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("sweep", type=Path)
    args = ap.parse_args()
    res = ceiling(load(args.sweep))
    print(json.dumps(res, indent=2))
    print()
    for fr, v in sorted(res.items()):
        print(f"{fr}: {v['reachable']}/{v['flows']} flows reachable "
              f"= {v['ceiling_pct']}%")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
