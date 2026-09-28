"""Which of the 14 mechanisms does the surrogate get wrong?

The 8-flow audit only exercised the two mechanisms the trained policy converged
on (http_header_pad, split8). This sweeps ALL 14 across many flows, scoring the
same mutated packets through both the RealRulesReplica surrogate and the real
Snort binary, so we learn *where* the surrogate diverges rather than just that
it agreed on a convenient subset.

Cost: one real Snort call per (flow, mechanism) at ~10 s. 14 x 16 = 224 calls
is roughly 40 minutes. Results are appended to the JSON after every cell so a
timeout never loses the sweep.

The dangerous cell is surrogate_says_safe_and_real_alerts: that is the
false negative which would train the policy toward a mechanism that does not
actually evade.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
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
    ap.add_argument("--n-flows", type=int, default=16)
    ap.add_argument("--split", default="train")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--out", default=str(ROOT / "snort_validation" / "reports"
                                         / "surrogate_sweep_14mech.json"))
    args = ap.parse_args()

    env = HiddenDefenderEnv(split=args.split, seed=args.seed, real_snort=False)
    svc = SnortBatchService(batch_size=1)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    rows = []
    if out_path.exists():
        rows = json.loads(out_path.read_text()).get("rows", [])
    done = {(r["flow_idx"], r["mech"]) for r in rows}
    print(f"[*] resuming with {len(rows)} cells already done", flush=True)

    n_flows = min(args.n_flows, len(env._flows))
    t0 = time.time()

    for fidx in range(n_flows):
        flow = env._flows[fidx]  # noqa: SLF001
        framing = flow.get("framing")
        orig = payloads_of(flow["packets"])

        for mech in ACTION_NAMES:
            if (fidx, mech) in done:
                continue
            try:
                pkts = apply_mech(flow["packets"], mech)
            except Exception as exc:  # mechanism cannot be applied to this flow
                rows.append({
                    "flow_idx": fidx, "framing": framing, "mech": mech,
                    "error": f"{type(exc).__name__}: {exc}"[:120],
                    "semantics_ok": False, "replica_alert": None,
                    "real_alert": None, "agree": None, "masked_out": None,
                })
                continue

            sem = bool(semantics_intact(orig, pkts))
            replica_alert = bool(flow["replica"].verdict(pkts))
            real_alert = bool(svc.verdicts_chunked([(pkts, 0)]).get(0, True))

            env._idx = fidx  # noqa: SLF001
            mask = env._compute_action_mask()  # noqa: SLF001
            masked_out = not bool(mask[ACTION_NAMES.index(mech)])

            rows.append({
                "flow_idx": fidx, "framing": framing, "mech": mech,
                "semantics_ok": sem,
                "replica_alert": replica_alert,
                "real_alert": real_alert,
                "agree": replica_alert == real_alert,
                "masked_out": masked_out,
            })
            tag = "OK  " if replica_alert == real_alert else "DIFF"
            print(f"  {tag} flow {fidx:2d} {str(framing):6s} {mech:16s} "
                  f"sem={sem!s:5s} replica_alert={replica_alert!s:5s} "
                  f"real_alert={real_alert!s:5s} masked={masked_out!s:5s}",
                  flush=True)

            out_path.write_text(json.dumps(
                {"n_rows": len(rows), "elapsed_s": round(time.time() - t0),
                 "rows": rows}, indent=2))

    def summarize(rs):
        ok = [r for r in rs if r.get("agree") is not None]
        diff = [r for r in ok if not r["agree"]]
        return {
            "n": len(ok),
            "n_agree": len(ok) - len(diff),
            "n_disagree": len(diff),
            "agreement_pct": round(100.0 * (len(ok) - len(diff)) / len(ok), 1) if ok else None,
            "surrogate_false_safe": sum(1 for r in diff if r["real_alert"]),
            "disagreements": diff,
        }

    compared = [r for r in rows if r.get("agree") is not None]
    eligible = [r for r in compared if r.get("semantics_ok") and not r.get("masked_out")]

    per_mech = {}
    for m in ACTION_NAMES:
        per_mech[m] = summarize([r for r in compared if r["mech"] == m])

    final = {
        "elapsed_s": round(time.time() - t0),
        "overall": summarize(compared),
        "eligible_only": summarize(eligible),
        "per_mechanism": per_mech,
        "rows": rows,
    }
    out_path.write_text(json.dumps(final, indent=2))

    print(f"\n[*] OVERALL {final['overall']['n_agree']}/"
          f"{final['overall']['n']} agree "
          f"({final['overall']['agreement_pct']}%)")
    print(f"[*] surrogate said SAFE but real Snort ALERTED: "
          f"{final['overall']['surrogate_false_safe']}")
    print(f"\n[*] per mechanism (n, disagree, false_safe):")
    for m, s in per_mech.items():
        flag = "  <-- DIVERGES" if s["n_disagree"] else ""
        print(f"    {m:18s} n={s['n']:3d} disagree={s['n_disagree']:3d} "
              f"false_safe={s['surrogate_false_safe']:3d}{flag}")
    print(f"[+] {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
