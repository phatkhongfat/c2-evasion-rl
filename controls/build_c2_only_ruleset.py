#!/usr/bin/env python3
"""Derive the P2P-filtered C2 ruleset from the harvested ET-Open C2 ruleset.

The benchmark ruleset `snort_validation/et_open_c2/et_open_c2.rules` was built by
keeping every ET-Open rule that ever fired on the corpus. That harvest swept in
102 P2P/BitTorrent rules (classtype:policy-violation, e.g. SIDs
2008581/2008583/2008585) that are not C2 and violate the project's threat model
(see docs/THREAT_MODEL.md). On the 40-flow test split, 24 of 40 flows alert ONLY
via those BitTorrent rules and have no C2 baseline at all.

This script makes that removal reproducible and reviewable: it drops every rule
line whose classtype is in the drop set, leaving every other line (rules, blank
lines, comments) byte-for-byte untouched. The derived ruleset is 15 MB, so we do
NOT commit it -- it is regenerated on demand instead.

Pure filtering lives in `filter_rules`; the CLI just wires it to files.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Collection, Iterable

ROOT = Path(__file__).resolve().parents[1]

# classtype values that are not C2 and violate the threat model.
DEFAULT_DROP_CLASSTYPES: tuple[str, ...] = ("policy-violation",)

# Captures the classtype token wherever it appears in the line, stopping at the
# `;` that always terminates a Snort rule option. Anchoring on `;`/whitespace
# keeps the match exact: `policy-violation-extra` is NOT `policy-violation`.
_CLASSTYPE_RE = re.compile(r"classtype:([^;\s]+)")


def filter_rules(
    lines: Iterable[str], drop_classtypes: Collection[str]
) -> list[str]:
    """Return `lines` minus any rule line whose classtype is dropped.

    A line is dropped when it carries a `classtype:<value>;` option whose
    `<value>` is in `drop_classtypes`. The classtype is matched anywhere in the
    line, not at a fixed column. Lines without a classtype -- including comment
    and blank lines -- are kept verbatim, as is input order.
    """
    drop = set(drop_classtypes)
    kept: list[str] = []
    for line in lines:
        match = _CLASSTYPE_RE.search(line)
        if match is not None and match.group(1) in drop:
            continue
        kept.append(line)
    return kept


def default_input() -> Path:
    return ROOT / "snort_validation/et_open_c2/et_open_c2.rules"


def default_output() -> Path:
    return ROOT / "snort_validation/et_open_c2/et_open_c2_nop2p.rules"


def _main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--rules", type=Path, default=default_input(),
                    help="source ruleset to filter")
    ap.add_argument("--out", type=Path, default=default_output(),
                    help="destination for the filtered ruleset")
    ap.add_argument("--drop-classtype", action="append", dest="drop_classtypes",
                    default=None,
                    help="classtype to drop (repeatable); default: policy-violation")
    args = ap.parse_args()

    drop = args.drop_classtypes or list(DEFAULT_DROP_CLASSTYPES)

    if not args.rules.exists():
        sys.exit(f"ERROR: source ruleset not found: {args.rules}")

    # keepends=True preserves line terminators so the output is byte-identical
    # to a straight deletion of the dropped lines.
    with args.rules.open("r", errors="surrogateescape", newline="") as fh:
        lines = fh.readlines()
    kept = filter_rules(lines, drop)
    dropped = len(lines) - len(kept)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", errors="surrogateescape", newline="") as fh:
        fh.writelines(kept)

    print(
        f"dropped {dropped} rule line(s) with classtype in {sorted(drop)}; "
        f"kept {len(kept)}/{len(lines)} lines -> {args.out}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
