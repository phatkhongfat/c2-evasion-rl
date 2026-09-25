#!/usr/bin/env python3
"""
Aggregate the sweep / scale / cross-capture reports into the final table.

One script instead of one per experiment: the three inputs are the same shape
(``evasion_pct`` + ``mean_corrupt`` at some ``(capture, n_flows, corrupt_cost)``)
so they belong in one table, and the plan's ">=20 rows" check is then a real
assertion over the merged set rather than three separate eyeballings.

Missing values are FATAL, not defaulted.  Substituting 0 for a missing
``evasion_pct`` (as an earlier version did) turns "this run failed" into "this
run evaded nothing", which reads as a result instead of an error.

USAGE
-----
    python snort_validation/aggregate_results.py \
        --sweep snort_validation/reports/sweep_corrupt_cost.json \
        --scale snort_validation/reports/scale_flows.json \
        --cross-capture "snort_validation/reports/cross_capture_*.json" \
        --out snort_validation/reports/final_results_table.json
"""
import argparse
import glob
import json
import statistics
import sys
from pathlib import Path

# The gate is stdlib-only on purpose: this reporting tool must stay runnable
# without torch/scapy, so it must not import anything from the ML stack.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from control_gate import policy_beats_control  # noqa: E402


def _load(path):
    with open(path) as fh:
        return json.load(fh)


def rows_from_sweep(data, dataset):
    return [{
        "dataset": data.get("dataset", dataset),
        "capture": data.get("capture"),
        "n_flows": data.get("flows"),
        "corrupt_cost": r.get("corrupt_cost"),
        "evasion_pct": r.get("evasion_pct"),
        "mean_corrupt": r.get("mean_corrupt"),
        "deterministic_evaded": r.get("deterministic_evaded"),
        "source": "sweep"} for r in data.get("sweep_results", [])]


def rows_from_scale(data, dataset):
    return [{
        "dataset": data.get("dataset", dataset),
        "capture": data.get("capture"),
        "n_flows": r.get("n_flows"),
        "corrupt_cost": data.get("corrupt_cost"),
        "evasion_pct": r.get("evasion_pct"),
        "mean_corrupt": r.get("mean_corrupt"),
        "deterministic_evaded": r.get("deterministic_evaded"),
        "source": "scale"} for r in data.get("scale_results", [])]


def rows_from_cross(paths, dataset):
    rows = []
    for p in paths:
        d = _load(p)
        # NOTE: deterministic_evaded / corrupt_all_evaded are carried through as
        # the MEASURED integers.  An earlier version recomputed them as
        # round(evasion_pct * n_flows / 100), which re-derives a count from an
        # already-rounded percentage: with 50 flows a 1-count difference is 2
        # percentage points, and float rounding then disagrees with the report
        # the row was built from.  The percentage is a display field; the count
        # is the measurement.
        rows.append({
            "dataset": d.get("dataset", dataset),
            "capture": d.get("capture"),
            "n_flows": d.get("flows"),
            "corrupt_cost": d.get("corrupt_cost"),
            "evasion_pct": d.get("deterministic_pct"),
            "mean_corrupt": d.get("deterministic_mean_corrupt"),
            "deterministic_evaded": d.get("deterministic_evaded"),
            "baseline_detected": d.get("baseline_detected"),
            "random_evaded": d.get("random_evaded"),
            "corrupt_all_evaded": d.get("corrupt_all_evaded"),
            "corrupt_all_mean_corrupt": d.get("corrupt_all_mean_corrupt"),
            "corrupt_all_pct": d.get("corrupt_all_pct"),
            "source": "cross_capture"})
    return rows


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sweep", nargs="*", default=[])
    ap.add_argument("--scale", nargs="*", default=[])
    ap.add_argument("--cross-capture", default=None,
                    help="glob (quoted) for cross_capture_*.json")
    ap.add_argument("--out",
                    default="snort_validation/reports/final_results_table.json")
    ap.add_argument("--summary-out",
                    default="snort_validation/reports/cross_capture_summary.json")
    ap.add_argument("--dataset", default="ctu13")
    args = ap.parse_args()

    rows = []
    for p in args.sweep:
        if Path(p).exists():
            rows += rows_from_sweep(_load(p), args.dataset)
    for p in args.scale:
        if Path(p).exists():
            rows += rows_from_scale(_load(p), args.dataset)
    cross_paths = sorted(glob.glob(args.cross_capture)) if args.cross_capture else []
    cross_paths = [p for p in cross_paths if "summary" not in Path(p).name]
    rows += rows_from_cross(cross_paths, args.dataset)

    required = ("evasion_pct", "mean_corrupt", "n_flows", "corrupt_cost",
                "capture", "deterministic_evaded")
    bad = [r for r in rows if any(r.get(k) is None for k in required)]
    if bad:
        print(f"[-] {len(bad)} row(s) missing required fields "
              f"{required}: {bad[:2]}", file=sys.stderr)
        return 1
    if not rows:
        print("[-] no rows: nothing to aggregate", file=sys.stderr)
        return 1

    rows.sort(key=lambda r: (r["dataset"], r["capture"], r["source"],
                             r["n_flows"], r["corrupt_cost"]))
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_suffix(".json.tmp")
    tmp.write_text(json.dumps({"count": len(rows), "results": rows}, indent=2))
    tmp.replace(out)

    # Cross-capture summary: one line per capture at the fixed cost, plus the
    # spread across captures -- the actual generalisation question.
    cross = [r for r in rows if r["source"] == "cross_capture"]
    if cross:
        ev = [r["evasion_pct"] for r in cross]
        # The control travels with every row, so the summary can answer the
        # only question that matters: did the policy beat corrupt-all?
        summary_rows = []
        for r in cross:
            entry = {"capture": r["capture"], "n_flows": r["n_flows"],
                     "deterministic_evaded": r["deterministic_evaded"],
                     "evasion_pct": r["evasion_pct"],
                     "mean_corrupt": r["mean_corrupt"],
                     "baseline_detected": r.get("baseline_detected"),
                     "corrupt_all_evaded": r.get("corrupt_all_evaded"),
                     "corrupt_all_mean_corrupt": r.get("corrupt_all_mean_corrupt")}
            ctrl_n = r.get("corrupt_all_mean_corrupt")
            if (ctrl_n is not None and r["deterministic_evaded"] is not None):
                entry["vs_control"] = policy_beats_control(
                    policy_evaded=r["deterministic_evaded"],
                    n_flows=r["n_flows"],
                    policy_mean_corrupt=r["mean_corrupt"],
                    control_mean_corrupt=ctrl_n,
                    control_evaded=r.get("corrupt_all_evaded"))
            summary_rows.append(entry)
        summary = {
            "n_captures": len(cross),
            "corrupt_cost": cross[0]["corrupt_cost"],
            "summary": summary_rows,
            "mean_evasion_pct": round(statistics.mean(ev), 2),
            "std_evasion_pct": round(statistics.pstdev(ev), 2),
            "min_evasion_pct": min(ev),
            "max_evasion_pct": max(ev),
        }
        # How many captures the policy actually beat the control on.
        verdicts = [e["vs_control"]["verdict"] for e in summary_rows
                    if "vs_control" in e]
        summary["vs_control_counts"] = {
            v: verdicts.count(v) for v in ("beats", "tie", "loses")
            if verdicts.count(v)}
        s_out = Path(args.summary_out)
        s_out.parent.mkdir(parents=True, exist_ok=True)
        s_tmp = s_out.with_suffix(s_out.suffix + ".tmp")
        s_tmp.write_text(json.dumps(summary, indent=2))
        s_tmp.replace(s_out)
        print(f"[+] wrote {s_out}: mean {summary['mean_evasion_pct']}% "
              f"std {summary['std_evasion_pct']}% over {len(cross)} captures; "
              f"vs corrupt-all: {summary['vs_control_counts']}")

    print(f"[+] wrote {out}: {len(rows)} rows")
    print(f"\n{'dataset':<14}{'capture':<34}{'src':<14}{'flows':>6}"
          f"{'cost':>6}{'evasion%':>10}{'mean_corrupt':>14}")
    print("-" * 98)
    for r in rows:
        print(f"{r['dataset']:<14}{r['capture'][:33]:<34}{r['source']:<14}"
              f"{r['n_flows']:>6}{r['corrupt_cost']:>6.1f}"
              f"{r['evasion_pct']:>9.1f}%{r['mean_corrupt']:>14.2f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
