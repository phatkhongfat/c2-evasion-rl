#!/usr/bin/env python3
"""Does `frag3 policy last` restore a real search problem?

With `policy first` (the shipped conf) Snort inspects only the first fragment,
so ANY prepend or ANY split hides the pattern -- every offset evades, a
constant action is optimal, and there is nothing for a learner to discover.

`policy last` is how fragment inspection is normally deployed: reassemble the
datagram fully, then inspect.  This script measures the same offset sweep under
that policy.  If discrimination appears here, the benchmark was measuring a
configuration artifact rather than attacker skill.
"""
from __future__ import annotations

import json
import re
import sys
from collections import Counter
from pathlib import Path

REPO = Path("/root/.hermes/c2-evasion-rl")
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))

from hidden_defender_env import apply_mech, load_corpus, payloads_of, semantics_intact  # noqa: E402
from snort_batch_service import SnortBatchService  # noqa: E402

REPORTS = REPO / "snort_validation/reports"
SRC_CONF = REPO / "snort_validation/et_open_c2/snort_et_c2.conf"
OFFSET_SETS = {"split": [8, 16, 24, 32, 40, 48, 56, 64],
               "prepend": [1, 2, 4, 8, 12, 16, 24, 32, 48, 64, 96, 128]}


def make_conf(policy: str) -> Path:
    text = SRC_CONF.read_text()
    text = re.sub(r"frag3_engine: policy (first|last)",
                  f"frag3_engine: policy {policy}", text)
    out = Path(f"/tmp/snort_frag3_{policy}.conf")
    out.write_text(text)
    return out


def sweep(conf, flows, n, batch_size=48):
    combos = [(i, m, o) for i in range(n) for m in OFFSET_SETS
              for o in OFFSET_SETS[m]]
    svc = SnortBatchService(conf=conf, batch_size=batch_size)
    res = {}
    for s in range(0, len(combos), batch_size):
        chunk = combos[s:s + batch_size]
        items = []
        for k, (i, m, o) in enumerate(chunk):
            items.append((apply_mech(flows[i]["packets"], f"{m}{o}"), k))
        verdicts = svc.verdicts(items)
        for k, (i, m, o) in enumerate(chunk):
            mut = apply_mech(flows[i]["packets"], f"{m}{o}")
            sem = semantics_intact(payloads_of(flows[i]["packets"]), mut)
            res[(i, m, o)] = (not verdicts.get(k, True), sem)
    return res, svc.stats()


def summarise(res, flows, n, policy):
    out = {}
    for mech in OFFSET_SETS:
        per_flow = {i: [o for o in OFFSET_SETS[mech]
                        if res[(i, mech, o)][0] and res[(i, mech, o)][1]]
                    for i in range(n)}
        solved = [i for i in range(n) if per_flow[i]]
        solvable_any = {i: any(res[(i, mech, o)][0] and res[(i, mech, o)][1]
                              for o in OFFSET_SETS[mech]) for i in range(n)}
        common = (set.intersection(*[set(per_flow[i]) for i in solved])
                  if solved else set())
        cover = Counter(per_flow[i][0] for i in solved)
        widths = [len(per_flow[i]) for i in solved] or [0]
        out[mech] = {
            "flows_solvable_by_some_offset": sum(solvable_any.values()),
            "offsets_working_on_every_solvable_flow": sorted(common),
            "first_offset_histogram": {str(k): v for k, v in cover.items()},
            "good_offsets_per_flow": {"min": min(widths), "max": max(widths),
                                      "mean": round(sum(widths) / len(widths), 1)},
        }
        print(f"\n[*] policy {policy} / {mech}")
        print(f"    flows solvable by SOME offset: "
              f"{sum(solvable_any.values())}/{n}")
        print(f"    offsets working on EVERY solvable flow: {sorted(common)}")
        print(f"    good offsets per flow: min={min(widths)} max={max(widths)} "
              f"mean={sum(widths) / len(widths):.1f}")
        print(f"    first-offset histogram: {dict(cover)}")
    return out


def main() -> int:
    flows = load_corpus("test")
    n = len(flows)
    report = {}
    for policy in ("first", "last"):
        conf = make_conf(policy)
        print(f"[*] sweeping policy={policy} ...", flush=True)
        res, stats = sweep(conf, flows, n)
        print(f"    {stats}")
        report[policy] = {"snort_stats": stats,
                          "mechanisms": summarise(res, flows, n, policy)}
    out = REPORTS / "frag3_policy_comparison.json"
    out.write_text(json.dumps(report, indent=2))
    print(f"\n[+] {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
