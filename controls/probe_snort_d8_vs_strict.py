"""Re-aggregate the real-Snort sweep under D8 (lenient) vs byte-equality.

No engine re-run is needed for the gate change itself: probe_mech_sweep_
real_snort.py already sends every one of the 680 queries to Snort and only
drops the invalid ones at aggregation time (:74-77). This replays the same
queries so both gates can be scored from one pass, and writes the raw
per-query verdicts so the aggregation can be redone without Snort again.

Note the queries ARE regenerated here (packets must be rebuilt), so this is a
second Snort pass -- but it is one pass for both gates, not one per gate.
"""
import collections
import json
import pathlib
import sys
import time

ROOT = pathlib.Path("/root/.hermes/c2-evasion-rl")
sys.path[:0] = [str(ROOT), str(ROOT / "ai_agent"), str(ROOT / "snort_validation")]

from hidden_defender_env import (HiddenDefenderEnv, ACTION_NAMES,  # noqa: E402
                                apply_mech, semantics_intact)
from c2_semantics import client_ip_of, semantics_ok_reward  # noqa: E402
from snort_batch_service import SnortBatchService  # noqa: E402

CHUNK = 250


def main() -> int:
    t0 = time.time()
    env = HiddenDefenderEnv(split="test", seed=42, real_snort=False)
    flows = env._flows

    items, index, d8, strict = [], [], {}, {}
    for fi, f in enumerate(flows):
        pkts = list(f["packets"])
        cid = client_ip_of(f.get("flow_id"))
        for mech in ACTION_NAMES:
            cand = pkts if mech == "noop" else apply_mech(
                pkts, mech, cid, ownership="client")
            qid = len(items)
            index.append((fi, mech))
            d8[qid] = True if mech == "noop" else bool(
                semantics_ok_reward(pkts, cand, cid))
            strict[qid] = True if mech == "noop" else bool(
                semantics_intact(pkts, cand, cid))
            items.append((cand, qid))

    print(f"[*] {len(flows)} flows x {len(ACTION_NAMES)} mechs = "
          f"{len(items)} queries, chunk={CHUNK}", flush=True)

    svc = SnortBatchService(batch_size=CHUNK, keep_artifacts=True)
    detected = {}
    for start in range(0, len(items), CHUNK):
        chunk = items[start:start + CHUNK]
        res = svc.verdicts([(p, i) for i, (p, _q) in enumerate(chunk)])
        for lq, det in res.items():
            detected[start + lq] = bool(det)
        print(f"  chunk {start // CHUNK + 1}: "
              f"{min(CHUNK, len(items) - start)} queries "
              f"({time.time() - t0:.0f}s)", flush=True)

    def agg(gate):
        ev = collections.Counter()
        ca = collections.Counter()
        inv = collections.Counter()
        per_flow = collections.defaultdict(list)
        for qid, (fi, mech) in enumerate(index):
            if not gate[qid]:
                inv[mech] += 1
                per_flow[fi].append("invalid")
                continue
            hit = detected.get(qid, True)
            ca[mech] += int(hit)
            ev[mech] += int(not hit)
            per_flow[fi].append("caught" if hit else "evaded")
        oracle = sum(1 for r in per_flow.values() if "evaded" in r)
        return ev, ca, inv, oracle

    for name, gate in (("STRICT byte-equality", strict), ("D8 lenient", d8)):
        ev, ca, inv, oracle = agg(gate)
        best = max((ev[m] for m in ACTION_NAMES), default=0)
        print(f"\n=== {name} ===")
        print(f"oracle={oracle}/{len(flows)} = {100 * oracle / len(flows):.1f}%"
              f"  best_single={best}")
        print(f"{'mech':22s} {'evaded':>7s} {'caught':>7s} {'invalid':>8s}")
        for m in ACTION_NAMES:
            if ev[m] or ca[m] or inv[m]:
                print(f"{m:22s} {ev[m]:7d} {ca[m]:7d} {inv[m]:8d}")

    out = ROOT / "snort_validation/reports/p17_raw_snort_d8.json"
    out.write_text(json.dumps({
        "n_flows": len(flows), "n_mechs": len(ACTION_NAMES),
        "engine": "snort 2.9.20 real binary",
        "ruleset": "snort_et_c2.conf (ET Open C2 full)",
        "index": [[fi, m] for fi, m in index],
        "detected": {str(k): v for k, v in detected.items()},
        "gate_d8": {str(k): v for k, v in d8.items()},
        "gate_strict": {str(k): v for k, v in strict.items()},
    }, indent=1))
    print(f"\nwrote {out.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())