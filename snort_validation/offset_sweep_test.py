#!/usr/bin/env python3
"""Decisive experiment: is the RIGHT OFFSET flow-dependent?

The mechanism-level benchmark came out saturated: split8, prepend4, prepend8 and
prepend12 each solved 16/16 test flows, so no learner can beat a constant and RL
has nothing to learn.  The fix is to parameterise the action space over the
fragmentation offset, which turns the task back into a real search problem --
but only if the winning offset actually varies per flow.

This sweeps offset 0..15 for split and prepend on the 16 held-out flows with the
real snort binary and reports how many distinct offsets are needed to cover the
set.  If one offset solves everything the RL framing stays dead; if the set is
spread out, parameterising the action space is the right move.
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

REPO = Path("/root/.hermes/c2-evasion-rl")
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))

from hidden_defender_env import apply_mech, load_corpus, payloads_of, semantics_intact  # noqa: E402
from snort_batch_service import SnortBatchService  # noqa: E402

REPORTS = REPO / "snort_validation/reports"
OFFSETS = list(range(1, 17))


def mutate(pkts, mech, off):
    """Delegate to the same code path the env and baselines use."""
    return apply_mech(pkts, f"{mech}{off}")


def main() -> int:
    flows = load_corpus("test")
    n = len(flows)
    combos = [(i, m, o) for i in range(n) for m in ("split", "prepend")
              for o in OFFSETS]
    svc = SnortBatchService(batch_size=48)
    res = {}
    for s in range(0, len(combos), 48):
        chunk = combos[s:s + 48]
        items = [(mutate(flows[i]["packets"], m, o), k)
                 for k, (i, m, o) in enumerate(chunk)]
        verdicts = svc.verdicts(items)
        for k, (i, m, o) in enumerate(chunk):
            orig = payloads_of(flows[i]["packets"])
            mut = mutate(flows[i]["packets"], m, o)
            sem = semantics_intact(orig, mut)
            res[(i, m, o)] = (not verdicts.get(k, True), sem)
        print(f"    scored {s + len(chunk)}/{len(combos)}")

    report = {}
    for mech in ("split", "prepend"):
        per_flow = {}
        for i in range(n):
            good = [o for o in OFFSETS if res[(i, mech, o)][0] and res[(i, mech, o)][1]]
            per_flow[i] = good
        cover = Counter()
        for good in per_flow.values():
            if good:
                cover[good[0]] += 1
        n_solved = sum(1 for g in per_flow.values() if g)
        all_common = set.intersection(*[set(g) for g in per_flow.values() if g]) if n_solved else set()
        union = set.union(*[set(g) for g in per_flow.values() if g]) if n_solved else set()
        report[mech] = {
            "flows_solved_by_some_offset": n_solved,
            "per_flow_good_offsets": {str(k): v for k, v in per_flow.items()},
            "offsets_that_work_on_every_flow": sorted(all_common),
            "distinct_offsets_needed": len(union),
            "first_offset_histogram": dict(cover),
        }
        print(f"\n[*] {mech}: {n_solved}/{n} flows solvable")
        print(f"    offsets working on EVERY flow: {sorted(all_common)}")
        print(f"    distinct offsets across all flows: {sorted(union)} "
              f"({len(union)})")
        widths = [len(v) for v in per_flow.values() if v]
        print(f"    good offsets per flow: min={min(widths)} max={max(widths)} "
              f"mean={sum(widths) / len(widths):.1f}")

    (REPORTS / "offset_sweep_test.json").write_text(json.dumps(report, indent=2))
    print(f"\n[+] {REPORTS / 'offset_sweep_test.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
