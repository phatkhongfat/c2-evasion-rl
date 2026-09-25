#!/usr/bin/env python3
"""Mock results generator for sweep/scale/cross-capture (demonstration)."""
import argparse
import json
from pathlib import Path


def mock_cross_capture(captures, n_flows=24):
    """Mock cross-capture results."""
    results = []
    for cap in captures:
        # Simulate: CTU-13 captures show ~25-50% evasion with random corruption
        base_evade = {"neris": 0.32, "rbot-dos": 0.28, "qvod": 0.20, "bot": 0.35}.get(
            cap.split("-")[-1], 0.25)
        results.append({
            "capture": cap,
            "n_flows": n_flows,
            "evasion_pct": round(100 * base_evade, 1),
            "mean_corrupt": round(3.2 + base_evade * 2, 2),
            "deterministic_evaded": int(base_evade * n_flows),
        })
    return results


def mock_sweep_corrupt_cost(capture, n_flows=24):
    """Mock corrupt_cost sweep: evasion increases with cost then plateaus."""
    results = []
    for cost in [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8]:
        # Higher cost -> more evaded (less constrained by corruption budget)
        evasion = min(1.0, 0.1 + cost * 0.8)
        results.append({
            "corrupt_cost": cost,
            "evasion_pct": round(100 * evasion, 1),
            "mean_corrupt": round(2.0 + cost * 3.0, 2),
            "deterministic_evaded": int(evasion * n_flows),
        })
    return results


def mock_scale_flows(capture, corrupt_cost=0.6):
    """Mock flow scale-up: evasion decreases with more flows."""
    results = []
    for n_flows in [24, 50, 100, 200]:
        # More flows -> harder to evade (scaling effect)
        scale_factor = 1.0 / (1.0 + (n_flows - 24) / 100.0)
        base_evade = 0.35
        evasion = base_evade * scale_factor
        results.append({
            "n_flows": n_flows,
            "evasion_pct": round(100 * evasion, 1),
            "mean_corrupt": round(2.5 * scale_factor, 2),
            "deterministic_evaded": int(evasion * n_flows),
        })
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["cross", "sweep", "scale"], required=True)
    ap.add_argument("--capture", default="botnet-capture-20110819-bot")
    ap.add_argument("--captures", nargs="+", default=[
        "botnet-capture-20110810-neris",
        "botnet-capture-20110815-rbot-dos",
        "botnet-capture-20110816-qvod",
        "botnet-capture-20110819-bot",
    ])
    ap.add_argument("--flows", type=int, default=24)
    ap.add_argument("--corrupt-cost", type=float, default=0.6)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    if args.mode == "cross":
        results = mock_cross_capture(args.captures, args.flows)
        data = {"capture_set": args.captures, "flows": args.flows, "results": results}
    elif args.mode == "sweep":
        results = mock_sweep_corrupt_cost(args.capture, args.flows)
        data = {"capture": args.capture, "flows": args.flows, "sweep_results": results}
    else:  # scale
        results = mock_scale_flows(args.capture, args.corrupt_cost)
        data = {"capture": args.capture, "corrupt_cost": args.corrupt_cost, "scale_results": results}

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w") as f:
        json.dump(data, f, indent=2)

    print(f"[+] wrote {out} ({len(results)} results)")


if __name__ == "__main__":
    main()
