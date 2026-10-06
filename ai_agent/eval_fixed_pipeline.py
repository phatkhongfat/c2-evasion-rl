#!/usr/bin/env python3
"""Regenerate the held-out evaluation with the 6-fix pipeline.

Produces ``ppo_masked_test_FIXED.json``: for every test flow it scores the
model's chosen action and the unmodified baseline with real Snort, using ONE
PCAP per flow, a dynamically translated source address, client-only mutation,
and the byte-equality semantics bar.  A baseline that does not alert means the
flow is not a valid positive, so the per-flow record keeps both verdicts and
the aggregate reports the baseline alert rate as an integrity control.

Results are appended to a JSONL file as they are produced, so a timeout never
loses completed work.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))

from hidden_defender_env import HiddenDefenderEnv  # noqa: E402
from eval_pipeline import (  # noqa: E402
    bytes_equal_semantics,
    client_ip_of,
    mutate_client_only,
    score_flow_real,
)


def model_decisions(env, model) -> list:
    """Deterministic action the policy picks for each flow, in flow order."""
    obs, _ = env.reset(seed=42)
    out = []
    for _ in range(len(env._flows)):
        mask = env.action_masks()
        action, _ = model.predict(obs, action_masks=mask, deterministic=True)
        obs, _r, _t, _tr, info = env.step(int(action))
        out.append((info["flow_id"], info["action"]))
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default=str(REPO / "models/ppo_hidden_defender.zip"))
    ap.add_argument("--split", default="test")
    ap.add_argument("--out", default=str(REPO / "snort_validation/reports/ppo_masked_test_FIXED.json"))
    ap.add_argument("--progress", default=str(REPO / "snort_validation/reports/.eval_fixed_progress.jsonl"))
    ap.add_argument("--limit", type=int, default=0, help="score only the first N flows (smoke test)")
    ap.add_argument("--no-baseline", action="store_true", help="skip the baseline control")
    ap.add_argument("--capture", default=None,
                    help="restrict evaluation to one capture id")
    ap.add_argument("--ownership", default="client", choices=("client", "both"),
                    help="apply mechanisms to 'client' only (default) or 'both' endpoints")
    args = ap.parse_args()

    from sb3_contrib import MaskablePPO

    env = HiddenDefenderEnv(split=args.split, seed=42, real_snort=False,
                            capture=args.capture, ownership=args.ownership)
    model = MaskablePPO.load(args.model, env=env)
    by_id = {f["flow_id"]: f for f in env._flows}

    decisions = model_decisions(env, model)
    if args.limit:
        decisions = decisions[: args.limit]

    progress = Path(args.progress)
    progress.parent.mkdir(parents=True, exist_ok=True)
    if progress.exists():
        progress.unlink()

    rows = []
    for i, (fid, mech) in enumerate(decisions):
        f = by_id[fid]
        cip = client_ip_of(fid)
        base = None
        if not args.no_baseline:
            base = score_flow_real(f["packets"], cip, attempt_id=i, mech=None)
        act = score_flow_real(f["packets"], cip, attempt_id=100 + i, mech=mech)
        row = {
            "flow_id": fid,
            "framing": f.get("framing", "?"),
            "action": mech,
            "baseline_alert": (base["alert"] if base else None),
            "alert": act["alert"],
            "n_alerts": act["n_alerts"],
            "evaded": act["evaded"],
            "semantics_ok": act["semantics_ok"],
            "valid_evasion": act["valid_evasion"],
            "source_ip": act["source_ip"],
            "source_port": act["source_port"],
            "n_snort_calls": act["n_snort_calls"] + (base["n_snort_calls"] if base else 0),
        }
        rows.append(row)
        with open(progress, "a") as fh:
            fh.write(json.dumps(row) + "\n")
        print(f"[{i + 1}/{len(decisions)}] {fid[:48]:48s} {mech:8s} "
              f"base={'ALERT' if row['baseline_alert'] else 'clear' if row['baseline_alert'] is not None else 'n/a':5s} "
              f"-> {'ALERT' if act['alert'] else 'EVADED'} "
              f"sem={'ok' if act['semantics_ok'] else 'BROKEN'}")

    n = len(rows)
    evaded = sum(r["evaded"] for r in rows)
    valid = sum(r["valid_evasion"] for r in rows)
    baseline_alerted = sum(1 for r in rows if r["baseline_alert"])
    actions = Counter(r["action"] for r in rows)
    frames = Counter(r["framing"] for r in rows)
    per_frame = {}
    for fr in sorted(frames):
        sub = [r for r in rows if r["framing"] == fr]
        per_frame[fr] = {
            "n": len(sub),
            "valid_evasion": sum(r["valid_evasion"] for r in sub),
            "valid_evasion_pct": round(100.0 * sum(r["valid_evasion"] for r in sub) / len(sub), 1),
        }

    result = {
        "method": "maskable_ppo",
        "scorer": "real_snort",
        "pipeline": "fixed_6_fixes",
        "split": args.split,
        "n_flows": n,
        "alerted": sum(r["alert"] for r in rows),
        "evaded": evaded,
        "valid_evasion": valid,
        "valid_evasion_pct": round(100.0 * valid / n, 1) if n else 0.0,
        "semantics_breaks": sum(1 for r in rows if r["evaded"] and not r["semantics_ok"]),
        "baseline_alerted": baseline_alerted,
        "baseline_alert_pct": round(100.0 * baseline_alerted / n, 1) if n else 0.0,
        "mechanism_diversity": len(actions),
        "actions_chosen": dict(actions),
        "framing_counts": dict(frames),
        "per_framing": per_frame,
        "per_flow": rows,
    }
    out = Path(args.out)
    out.write_text(json.dumps(result, indent=2))
    print(f"[*] valid evasion {valid}/{n} = {result['valid_evasion_pct']}%")
    print(f"[*] baseline alerted {baseline_alerted}/{n} = {result['baseline_alert_pct']}%")
    print(f"[*] mechanism diversity: {len(actions)} actions {dict(actions)}")
    print(f"[+] {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
