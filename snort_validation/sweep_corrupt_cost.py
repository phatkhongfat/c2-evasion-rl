#!/usr/bin/env python3
"""Sweep corrupt_cost parameter on the best-performing capture."""
import argparse
import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--capture", default="botnet-capture-20110819-bot")
    ap.add_argument("--flows", type=int, default=24)
    ap.add_argument("--rounds", type=int, default=8)
    ap.add_argument("--batch", type=int, default=96)
    ap.add_argument("--costs", type=float, nargs="+",
                    default=[0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8])
    ap.add_argument("--out", default="snort_validation/reports/sweep_corrupt_cost.json")
    args = ap.parse_args()

    results = []
    for cost in args.costs:
        print(f"[*] corrupt_cost={cost}...", flush=True)
        cmd = [
            sys.executable, str(REPO / "ai_agent" / "snort_bandit.py"),
            "--flows", str(args.flows),
            "--rounds", str(args.rounds),
            "--batch", str(args.batch),
            "--corrupt-cost", str(cost),
            "--capture", args.capture,
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
        if proc.returncode != 0:
            print(f"    ERROR: {proc.stderr[:200]}", flush=True)
            continue

        # Parse last JSON from snort_bandit output
        import re
        matches = re.findall(r'\{[^{}]*"deterministic_pct"[^{}]*\}', proc.stderr + proc.stdout)
        if matches:
            data = json.loads(matches[-1])
            result = {
                "corrupt_cost": cost,
                "evasion_pct": data.get("deterministic_pct", 0),
                "mean_corrupt": data.get("deterministic_mean_corrupt", 0),
                "deterministic_evaded": data.get("deterministic_evaded", 0),
            }
            results.append(result)
            print(f"    -> {result['evasion_pct']:.1f}% evasion", flush=True)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w") as f:
        json.dump({
            "capture": args.capture,
            "flows": args.flows,
            "sweep_results": results,
        }, f, indent=2)

    print(f"[+] wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
