"""Surrogate-vs-reality audit, flow by flow.

The aggregate evasion rate can match while the two scorers disagree about *which*
flows evade -- and that disagreement is what makes a surrogate-trained policy
misleading. For each flow this applies one mechanism, then scores the SAME
mutated packets through both the RealRulesReplica surrogate and the real Snort
binary, and reports the confusion matrix rather than just the totals.

Real Snort costs ~10 s per flow, so keep --n-flows small.

Scoring API (see hidden_defender_env.py):
    flow = env._flows[env._idx]; flow["packets"], flow["replica"].verdict(pkts)
    mutate with apply_mech(pkts, mech); real verdict via SnortBatchService
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "ai_agent"))
sys.path.insert(0, str(ROOT / "snort_validation"))

from hidden_defender_env import (  # noqa: E402
    ACTION_NAMES, HiddenDefenderEnv, apply_mech, payloads_of, semantics_intact,
)
from snort_batch_service import SnortBatchService  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n-flows", type=int, default=8)
    ap.add_argument("--split", default="train")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--out", default=str(ROOT / "snort_validation" / "reports"
                                         / "surrogate_vs_real_snort.json"))
    args = ap.parse_args()

    env = HiddenDefenderEnv(split=args.split, seed=args.seed, real_snort=False)
    svc = SnortBatchService(batch_size=1)

    rows = []
    for idx in range(min(args.n_flows, len(env._flows))):
        env._idx = idx                      # noqa: SLF001
        flow = env._flows[idx]              # noqa: SLF001
        mask = env._compute_action_mask()   # noqa: SLF001
        allowed = [a for a, ok in enumerate(mask) if ok]
        if not allowed:
            continue
        # prefer the mechanism the trained policy converged on per protocol
        preferred = {"http": "http_header_pad", "neris": "split8"}
        want = preferred.get(flow.get("framing"))
        mech = (want if want in [ACTION_NAMES[a] for a in allowed]
                else ACTION_NAMES[allowed[0]])

        pkts = apply_mech(flow["packets"], mech)
        sem = semantics_intact(payloads_of(flow["packets"]), pkts)

        replica_alert = bool(flow["replica"].verdict(pkts))
        real_alert = bool(svc.verdicts_chunked([(pkts, 0)]).get(0, True))

        rows.append({
            "idx": idx,
            "framing": flow.get("framing"),
            "flow_id": (flow.get("meta") or {}).get("id", idx),
            "mech": mech,
            "semantics_ok": bool(sem),
            "replica_alert": replica_alert,
            "real_alert": real_alert,
            "agree": replica_alert == real_alert,
        })
        print(f"  flow {idx:2d} {str(flow.get('framing')):6s} {mech:16s} "
              f"replica_alert={replica_alert!s:5s} real_alert={real_alert!s:5s} "
              f"{'OK' if replica_alert == real_alert else '<<< DISAGREE'}", flush=True)

    agree = sum(1 for r in rows if r["agree"])
    disagree = [r for r in rows if not r["agree"]]
    # surrogate said "safe" while real Snort alerted -> the dangerous false negative
    false_safe = [r for r in disagree if r["real_alert"]]

    out = {
        "n_flows": len(rows),
        "n_agree": agree,
        "agreement_pct": round(100.0 * agree / len(rows), 1) if rows else None,
        "surrogate_false_safe": len(false_safe),
        "replica_alerted": sum(1 for r in rows if r["replica_alert"]),
        "real_alerted": sum(1 for r in rows if r["real_alert"]),
        "rows": rows,
    }
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(out, indent=2))

    print(f"\n[*] agreement replica vs real Snort: {agree}/{len(rows)} "
          f"({out['agreement_pct']}%)")
    print(f"[*] surrogate said SAFE but Snort ALERTED: {len(false_safe)}")
    print(f"[+] {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
