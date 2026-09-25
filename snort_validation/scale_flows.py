#!/usr/bin/env python3
"""Scale n_flows parameter: 24 -> 50 -> 100 -> 200."""
import argparse
import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--capture", default="botnet-capture-20110819-bot")
    ap.add_argument("--corrupt-cost", type=float, default=0.6)
    ap.add_argument("--rounds", type=int, default=8)
    ap.add_argument("--batch", type=int, default=96)
    ap.add_argument("--flow-counts", type=int, nargs="+", default=[24, 50, 100, 200])
    ap.add_argument("--out", default="snort_validation/reports/scale_flows.json")
    args = ap.parse_args()

    results = []
    for n_flows in args.flow_counts:
        print(f"[*] n_flows={n_flows}...", flush=True)
        cmd = [
            sys.executable, str(REPO / "ai_agent" / "snort_bandit.py"),
            "--flows", str(n_flows),
            "--rounds", str(args.rounds),
            "--batch", str(args.batch),
            "--corrupt-cost", str(args.corrupt_cost),
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
                "n_flows": n_flows,
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
            "corrupt_cost": args.corrupt_cost,
            "scale_results": results,
        }, f, indent=2)

    print(f"[+] wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
