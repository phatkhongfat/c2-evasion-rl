#!/usr/bin/env python3
"""Per-mech and per-flow diff between two ceiling sweep reports.

The eval harness writes a sweep as JSON with a top-level ``cells`` list; each
cell records one (flow_id, mech) trial with a boolean ``valid_evasion`` (the
byte-preserving, IDS-silent bar).  Comparing two sweeps -- e.g. the shipped
Snort config against a ``stream5_tcp: policy last`` variant -- answers the
question "which evasions did the second configuration close, and which did it
open?" without eyeballing 560-row JSON files.

``diff_sweeps`` is pure: it reads only the report dicts it is handed and never
touches the filesystem or Snort, so it is unit-testable on synthetic fixtures.
"""
from __future__ import annotations


def _valid(report: dict) -> dict:
    """{mech: {flow_id: bool}} of valid_evasion across a sweep's cells.

    A mech/flow pair missing from a sweep is treated as "no valid evasion"
    (absent -> False), so a mech that only exists in one report still diffs
    cleanly against the other.
    """
    out: dict[str, dict[str, bool]] = {}
    for c in report["cells"]:
        out.setdefault(c["mech"], {})[c["flow_id"]] = bool(c.get("valid_evasion"))
    return out


def diff_sweeps(first: dict, reasm: dict) -> dict:
    """Compare two sweeps; return per-mech counts and per-flow closures.

    ``first`` is the baseline sweep (e.g. shipped conf) and ``reasm`` the
    variant (e.g. reassembly policy last).  For each mechanism the result
    carries the valid-evasion count in each sweep plus the flow_ids the variant
    *closed* (evaded before, not after) and *opened* (the reverse).
    """
    a, b = _valid(first), _valid(reasm)
    mechs = sorted(set(a) | set(b))
    by_mech = {
        m: {
            "first": sum(a.get(m, {}).values()),
            "reassemble": sum(b.get(m, {}).values()),
            "closed_by_reassembly": sorted(
                fid for fid, v in a.get(m, {}).items()
                if v and not b.get(m, {}).get(fid, False)
            ),
            "opened_by_reassembly": sorted(
                fid for fid, v in b.get(m, {}).items()
                if v and not a.get(m, {}).get(fid, False)
            ),
        }
        for m in mechs
    }
    return {
        "by_mech": by_mech,
        "by_flow": {m: by_mech[m]["closed_by_reassembly"] for m in mechs},
    }


def main(argv: list[str] | None = None) -> int:
    """CLI: ``compare_sweeps.py FIRST.json REASM.json`` prints the diff as JSON."""
    import argparse
    import json
    from pathlib import Path

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("first", type=Path, help="baseline sweep report (JSON)")
    ap.add_argument("reassemble", type=Path, help="variant sweep report (JSON)")
    args = ap.parse_args(argv)

    diff = diff_sweeps(json.loads(args.first.read_text()),
                       json.loads(args.reassemble.read_text()))
    print(json.dumps(diff, indent=1))
    print()
    print(f"{'mech':16s} {'first':>6s} {'reasm':>6s}  closed")
    for m, v in diff["by_mech"].items():
        print(f"{m:16s} {v['first']:6d} {v['reassemble']:6d}  "
              f"{len(v['closed_by_reassembly'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
