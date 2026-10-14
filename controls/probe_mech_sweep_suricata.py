#!/usr/bin/env python3
"""Same 17-mechanism sweep as probe_mech_sweep_real_snort.py, on SURICATA 7.0.3.

`suricata_runner.run_suricata` costs ~25.7 s per pcap, so 40 flows x 17
mechanisms = 680 queries would be 4.8 h.  Suricata processes a whole capture in
one pass and eve.json carries src/dst, so the same trick the Snort batch service
uses applies: rewrite each query to its own 198.51.100.x address, drop all 680
candidates into ONE pcap, run Suricata once, and map every alert back to its
query by address (direction-independent, same as the Snort service).

Reads the ruleset/yaml the ground-truth loader uses, so the numbers are directly
comparable with suricata_g1b / p16b reports.
"""
from __future__ import annotations

import collections
import json
import pathlib
import re
import sys
import tempfile
import time

REPO = pathlib.Path("/root/.hermes/c2-evasion-rl")
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))

from hidden_defender_env import (HiddenDefenderEnv, ACTION_NAMES,  # noqa: E402
                                apply_mech, semantics_intact)
from c2_semantics import client_ip_of  # noqa: E402
from snort_batch_service import SnortBatchService, QUERY_NET  # noqa: E402
from suricata_runner import run_suricata  # noqa: E402

RULES = REPO / "snort_validation/et_open_c2/suricata.rules"
YAML = REPO / "snort_validation/suricata.yaml"
OUT = REPO / "snort_validation/reports/p16d_mech_sweep_suricata.json"
_QIP = re.compile(re.escape(QUERY_NET) + r"(\d{1,3})\b")


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
            sem_ok_map[qid] = True if mech == "noop" \
                else bool(semantics_intact(pkts, cand, cid))
            items.append((cand, qid))

    n_q = len(items)
    CHUNK = 250
    n_chunks = (n_q + CHUNK - 1) // CHUNK
    print(f"[*] {len(flows)} flows x {len(ACTION_NAMES)} mechs = {n_q} "
          f"queries -> {n_chunks} suricata pass(es) of <= {CHUNK}", flush=True)

    tmp = pathlib.Path(tempfile.mkdtemp(prefix="suri_sweep_"))
    svc = SnortBatchService(workdir=tmp, keep_artifacts=True)
    detected = set()
    sids = collections.defaultdict(set)

    for start in range(0, n_q, CHUNK):
        part = items[start:start + CHUNK]
        # renumber so every query lands on its own 198.51.100.x address
        local = [(pkts, i) for i, (pkts, _q) in enumerate(part)]
        pcap = tmp / f"sweep_{start//CHUNK}.pcap"
        svc._write_batch_pcap(local, pcap)
        logdir = tmp / f"log_{start//CHUNK}"
        run_suricata(pcap, RULES, YAML, logdir)
        eve = logdir / "eve.json"
        if not eve.exists():
            raise SystemExit(f"[!] no eve.json in {logdir} -- cannot score, "
                             f"refusing to report 'clean'")
        for line in eve.read_text(errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            al = rec.get("alert")
            if not al:
                continue
            for key in ("src_ip", "dest_ip", "src_ip", "dst_ip"):
                m = _QIP.search(str(rec.get(key, "")))
                if m:
                    q = int(m.group(1)) - 1
                    detected.add(start + q)
                    sids[start + q].add(int(al.get("signature_id", -1)))
                    break
        print(f"  chunk {start//CHUNK + 1}/{n_chunks}: "
              f"{len(part)} queries ({time.time()-t0:.0f}s)", flush=True)

    evaded = collections.Counter()
    caught = collections.Counter()
    invalid = collections.Counter()
    per_flow = collections.defaultdict(list)
    for qid, (fi, mech) in enumerate(index):
        if not sem_ok_map[qid]:
            invalid[mech] += 1
            per_flow[fi].append(mech)
            continue
        if qid in detected:
            caught[mech] += 1
        else:
            evaded[mech] += 1
            per_flow[fi].append(mech)

    n = len(flows)
    # A flow counts toward the oracle if some VALID mechanism evaded on it.
    evaded_q = {qid for qid in range(n_q)
                if sem_ok_map[qid] and qid not in detected}
    oracle = len({index[q][0] for q in evaded_q})

    valid_best = max((evaded[m] for m in ACTION_NAMES), default=0)
    best_mech = max(evaded.items(), key=lambda kv: kv[1])[0] if evaded else None
    out = {
        "engine": "suricata 7.0.3",
        "ruleset": str(RULES.relative_to(REPO)),
        "n_flows": n, "n_mechs": len(ACTION_NAMES), "n_queries": n_q,
        "evaded": dict(evaded), "caught": dict(caught),
        "invalid_semantics": dict(invalid),
        "oracle_flows": oracle, "oracle_pct": round(100.0 * oracle / n, 1),
        "best_single_mech": best_mech, "best_single": valid_best,
        "headroom_pp": round(100.0 * (oracle - valid_best) / n, 2),
        "elapsed_s": round(time.time() - t0, 1),
    }
    OUT.write_text(json.dumps(out, indent=2))

    print()
    print(f"{'mechanism':22s} {'evaded':>7s} {'caught':>7s} {'invalid':>8s}")
    for m in ACTION_NAMES:
        print(f"{m:22s} {evaded[m]:7d} {caught[m]:7d} {invalid[m]:8d}")
    print()
    print(f"oracle      : {oracle}/{n} = {out['oracle_pct']}%")
    print(f"best_single : {best_mech} = {valid_best}/{n}")
    print(f"headroom    : {out['headroom_pp']} pp")
    print(f"[+] {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())