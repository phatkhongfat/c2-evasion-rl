#!/usr/bin/env python3
"""Why do the other 16 mechanisms fail on the real Snort binary?

`verdicts_chunked` cannot number 680 queries (qid must stay inside
198.51.100.0/24), so chunk manually at 250 and renumber per chunk, mapping the
local qid back to (flow_idx, mech) through an index list.

For every (flow, mechanism) pair we also record whether the mutation preserved
C2 semantics, so "did not evade" can be separated into:
  * INVALID  -- broke the C2 command, so it is not an evasion at all
  * CAUGHT   -- semantics intact, Snort still alerted
"""
from __future__ import annotations

import collections
import json
import pathlib
import sys
import time

REPO = pathlib.Path("/root/.hermes/c2-evasion-rl")
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))

from hidden_defender_env import (HiddenDefenderEnv, ACTION_NAMES,  # noqa: E402
                                apply_mech, semantics_intact)
from c2_semantics import client_ip_of  # noqa: E402
from snort_batch_service import SnortBatchService  # noqa: E402

OUT = pathlib.Path(REPO / "snort_validation/reports/p16d_mech_sweep_real_snort.json")
CHUNK = 250


def main() -> int:
    t0 = time.time()
    env = HiddenDefenderEnv(split="test", seed=42, real_snort=False)
    flows = env._flows

    items, index, sem_ok_map = [], [], {}
    for fi, f in enumerate(flows):
        pkts = list(f["packets"])
        cid = client_ip_of(f.get("flow_id"))
        for mech in ACTION_NAMES:
            cand = pkts if mech == "noop" else apply_mech(
                pkts, mech, cid, ownership="client")
            qid = len(items)
            index.append((fi, mech))
            sem_ok_map[qid] = bool(semantics_intact(pkts, cand, cid)) \
                if mech != "noop" else True
            items.append((cand, qid))

    print(f"[*] {len(flows)} flows x {len(ACTION_NAMES)} mechs = "
          f"{len(items)} queries, chunk={CHUNK}", flush=True)

    svc = SnortBatchService(batch_size=CHUNK, keep_artifacts=True)
    detected = {}
    for start in range(0, len(items), CHUNK):
        chunk = items[start:start + CHUNK]
        local = [(pkts, i) for i, (pkts, _q) in enumerate(chunk)]
        res = svc.verdicts(local)
        for local_q, det in res.items():
            detected[start + local_q] = bool(det)
        print(f"  chunk {start//CHUNK + 1}: "
              f"{min(CHUNK, len(items)-start)} queries "
              f"({time.time()-t0:.0f}s)", flush=True)

    # ---- aggregate -----------------------------------------------------
    evaded = collections.Counter()
    caught = collections.Counter()
    invalid = collections.Counter()
    oracle = 0
    per_flow = collections.defaultdict(list)
    for qid, (fi, mech) in enumerate(index):
        if not sem_ok_map[qid]:
            invalid[mech] += 1
            per_flow[fi].append((mech, "invalid"))
            continue
        if detected.get(qid):
            caught[mech] += 1
            per_flow[fi].append((mech, "caught"))
        else:
            evaded[mech] += 1
            per_flow[fi].append((mech, "evaded"))

    for fi, rows in per_flow.items():
        if any(r[1] == "evaded" for r in rows):
            oracle += 1

    n = len(flows)
    valid_best = max((evaded[m] for m in ACTION_NAMES), default=0)
    out = {
        "n_flows": n,
        "n_mechs": len(ACTION_NAMES),
        "engine": "snort 2.9.20 real binary",
        "ruleset": "snort_et_c2.conf (ET Open C2 full)",
        "evaded": dict(evaded),
        "caught": dict(caught),
        "invalid_semantics": dict(invalid),
        "oracle_flows": oracle,
        "oracle_pct": round(100.0 * oracle / n, 1),
        "best_single_mech": max(evaded.items(), key=lambda kv: kv[1])[0]
        if evaded else None,
        "best_single": valid_best,
        "headroom_pp": round(100.0 * (oracle - valid_best) / n, 2),
        "svc_stats": svc.stats(),
        "elapsed_s": round(time.time() - t0, 1),
    }
    OUT.write_text(json.dumps(out, indent=2))

    print()
    print(f"{'mechanism':22s} {'evaded':>7s} {'caught':>7s} {'invalid':>8s}")
    for m in ACTION_NAMES:
        print(f"{m:22s} {evaded[m]:7d} {caught[m]:7d} {invalid[m]:8d}")
    print()
    print(f"oracle        : {oracle}/{n} = {out['oracle_pct']}%")
    print(f"best_single   : {out['best_single_mech']} = {valid_best}/{n}")
    print(f"headroom      : {out['headroom_pp']} pp")
    print(f"snort calls   : {svc.stats()['snort_calls']}  "
          f"({svc.stats()['ms_per_flow']} ms/query)")
    print(f"[+] {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())