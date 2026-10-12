#!/usr/bin/env python3
"""Diversity headroom: flows where mechanisms disagree, per ceiling report.

Reads existing ceiling sweep reports (real Snort) and counts, for each report,
how many test flows have >=2 mechanisms with DIFFERENT valid_evasion verdicts.
Zero disagreement => a constant policy is optimal => diversity=1 is data-capped.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "snort_validation" / "reports"

SOURCES = [
    ("expert_full_both", "ceiling_v3_expert.json"),
    ("naive_both", "ceiling_v3_naive.json"),
    ("splitslow_full_both", "ceiling_v3_splitslow_fixed.json"),
]


def headroom(path: Path) -> dict:
    d = json.loads(path.read_text())
    per_flow = {}
    for c in d["cells"]:
        # `noop` is the negative control (fails by design on every valid
        # positive); counting it would report disagreement where no real
        # mechanism choice exists.  Headroom is among candidate mechanisms.
        if c["mech"] == "noop":
            continue
        per_flow.setdefault(c["flow_id"], {})[c["mech"]] = bool(c["valid_evasion"])
    disagree = 0
    for mechs in per_flow.values():
        if len(set(mechs.values())) > 1:
            disagree += 1
    return {
        "report": path.name,
        "ownership": d.get("ownership"),
        "conf": d.get("conf"),
        "n_flows": len(per_flow),
        "disagreement_flows": disagree,
        "mechs_counted": sorted({m for v in per_flow.values() for m in v}),
    }


def main() -> int:
    out = [headroom(REPORTS / name) for _tag, name in SOURCES
           if (REPORTS / name).exists()]
    dst = REPORTS / "diversity_headroom_v3.json"
    dst.write_text(json.dumps(out, indent=2))
    print(json.dumps(out, indent=2))
    print(f"[+] {dst}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
