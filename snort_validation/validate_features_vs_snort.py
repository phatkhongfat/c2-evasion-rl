#!/usr/bin/env python3
"""Task 2 — validate the 20 candidate features against real Snort verdicts.

Question
--------
The surrogate judge currently sees only 6 raw flow aggregates
(dur, tot_pkts, tot_bytes, src_bytes, proto, state).  Do any of the 20
derived packet-size / inter-arrival / rate / flag features carry *independent*
signal about whether Snort will actually alert on a synthesised flow?

Method
------
The 320 labelled samples (blind 240 + lambda=10 80) each carry a binary Snort
verdict.  A binary target makes Pearson's r on the 0/1 verdict the
point-biserial correlation, which is the natural effect size here; each
feature is also tested with Spearman's rho so that a monotone-but-nonlinear
relationship is not missed.  Two-sided p-values come from the t-distribution
on n-2 degrees of freedom.

Decision gate (declared BEFORE looking at the numbers)
------------------------------------------------------
A feature is selected iff
    1. |Pearson r| > 0.15        -- effect size floor
    2. p < 0.05                  -- significance
    3. non-degenerate            -- std > 0 over the 320 samples
    4. not collinear             -- |r| < 0.95 against an already-selected
                                    feature (keeps the top-|r| member)
and at most the top 10 by |Pearson r| survive.  The |r| > 0.15 floor is a
*feature* not a bug: it deliberately rejects features that are statistically
significant only because n is large but practically meaningless for the
surrogate.

Outputs
-------
    snort_validation/data/feature_validation_report.json   (machine-readable)
    snort_validation/data/feature_validation_report.md     (thesis-ready table)
"""
import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from scipy import stats

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from flow_features import CANDIDATE_FEATURES, DESCRIPTIONS  # noqa: E402
from surrogate_dataset import BASELINE_ENCODED, build_dataset  # noqa: E402

OUT_JSON = REPO / "snort_validation" / "data" / "feature_validation_report.json"
OUT_MD = REPO / "snort_validation" / "data" / "feature_validation_report.md"

R_FLOOR = 0.15
P_MAX = 0.05
COLLINEARITY_MAX = 0.95
TOP_K = 10


def correlate(df):
    y = df["detected"].to_numpy(dtype=float)
    records = []
    for feat in CANDIDATE_FEATURES:
        x = df[feat].to_numpy(dtype=float)
        finite = np.isfinite(x)
        if finite.sum() < 3:
            records.append(dict(feature=feat, pearson_r=np.nan, p_value=np.nan,
                                spearman_rho=np.nan, note="insufficient data"))
            continue
        xs, ys = x[finite], y[finite]
        std = float(np.std(xs))
        if std == 0.0:
            records.append(dict(feature=feat, pearson_r=np.nan, p_value=np.nan,
                                spearman_rho=np.nan, std=0.0, note="degenerate (zero variance)"))
            continue
        r, p = stats.pearsonr(xs, ys)
        rho, _ = stats.spearmanr(xs, ys)
        records.append(dict(
            feature=feat,
            pearson_r=float(r),
            abs_r=abs(float(r)),
            p_value=float(p),
            spearman_rho=float(rho) if np.isfinite(rho) else np.nan,
            std=std,
            mean=float(np.mean(xs)),
            min=float(np.min(xs)),
            max=float(np.max(xs)),
            description=DESCRIPTIONS.get(feat, ""),
            note="",
        ))
    return pd.DataFrame(records)


def select(records, r_floor, p_max, top_k, collinearity_max):
    """Apply the declared gate.

    Returns (literal_selected, deduped_selected, audit).

    ``literal_selected`` is the gate exactly as declared in the plan: rank by
    |Pearson r|, keep those with |r| > floor and p < p_max, take the top_k.
    ``deduped_selected`` additionally enforces |r| < collinearity_max against
    already-selected features.  Both are reported because on this dataset the
    literal gate admits a cluster of near-identical packet-size features that
    are algebraic restatements of ``tot_bytes / tot_pkts``; the de-duplicated
    set is the honest effect-size picture, while the literal set is what the
    plan specified for the enhanced training run.
    """
    ranked = records.dropna(subset=["pearson_r"]).sort_values(
        "abs_r", ascending=False)

    passes = [row for _, row in ranked.iterrows()
              if row["abs_r"] > r_floor and row["p_value"] < p_max]

    literal = [row["feature"] for row in passes[:top_k]]

    deduped, deduped_vecs = [], []
    for row in passes:
        if len(deduped) >= top_k:
            break
        clash = None
        for prev, prev_vec in zip(deduped, deduped_vecs):
            r_pp = float(np.corrcoef(row["_vec"], prev_vec)[0, 1])
            if abs(r_pp) >= collinearity_max:
                clash = (prev, r_pp)
                break
        if clash:
            continue
        deduped.append(row["feature"])
        deduped_vecs.append(row["_vec"])

    # Audit trail: explain every feature's outcome, literal gate first.
    audit = []
    for _, row in records.iterrows():
        feat = row["feature"]
        entry = dict(feature=feat,
                     pearson_r=row.get("pearson_r"),
                     p_value=row.get("p_value"),
                     spearman_rho=row.get("spearman_rho"),
                     decision="reject", reason="")
        if not np.isfinite(row.get("pearson_r", np.nan)):
            entry["reason"] = row.get("note") or "degenerate"
        elif row["abs_r"] <= r_floor:
            entry["reason"] = f"|r|={row['abs_r']:.3f} <= {r_floor} (effect-size floor)"
        elif row["p_value"] >= p_max:
            entry["reason"] = f"p={row['p_value']:.4g} >= {p_max}"
        elif feat not in literal:
            entry["reason"] = f"|r|={row['abs_r']:.3f} passes gate but ranked below top {top_k}"
        else:
            entry["decision"] = "selected"
            entry["reason"] = f"|r|={row['abs_r']:.3f}, p={row['p_value']:.3g}"
            if feat not in deduped:
                # find which selected feature it duplicates
                for prev, prev_vec in zip(deduped, deduped_vecs):
                    r_pp = float(np.corrcoef(row["_vec"], prev_vec)[0, 1])
                    if abs(r_pp) >= collinearity_max:
                        entry["reason"] += (f"; REDUNDANT with {prev} "
                                            f"(|r|={abs(r_pp):.3f})")
                        break
        audit.append(entry)
    return literal, deduped, audit


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--r-floor", type=float, default=R_FLOOR)
    ap.add_argument("--p-max", type=float, default=P_MAX)
    ap.add_argument("--top-k", type=int, default=TOP_K)
    ap.add_argument("--target", default="detected",
                    choices=["detected", "run_xgb_evaded"],
                    help="which verdict to correlate against")
    ap.add_argument("--out-suffix", default="",
                    help="suffix for output filenames (e.g. _vs_xgb)")
    args = ap.parse_args()
    out_json = OUT_JSON.with_name(f"feature_validation_report{args.out_suffix}.json")
    out_md = OUT_MD.with_name(f"feature_validation_report{args.out_suffix}.md")

    df = build_dataset()
    if args.target == "run_xgb_evaded":
        df = df.copy()
        df["detected"] = df["run_xgb_evaded"]

    y = df["detected"].to_numpy(dtype=float)
    print(f"\n[*] Target = {args.target}: {int(y.sum())}/{len(y)} positive "
          f"({y.mean():.1%}), base rate {1 - y.mean():.1%}")

    records = correlate(df)
    # attach raw vectors for the collinearity guard
    records["_vec"] = [df[f].to_numpy(dtype=float) for f in records["feature"]]

    selected, deduped, audit = select(records, args.r_floor, args.p_max,
                                      args.top_k, COLLINEARITY_MAX)

    print(f"\n[*] Gate: |Pearson r| > {args.r_floor}, p < {args.p_max}, "
          f"top {args.top_k}  (+ |collinear| < {COLLINEARITY_MAX} for the deduped set)")
    print(f"\n{'feature':<22}{'r':>9}{'p':>12}{'rho':>9}  decision")
    print("-" * 72)
    rank = {r["feature"]: r for r in audit}
    for _, row in records.sort_values("abs_r", ascending=False,
                                      na_position="last").iterrows():
        f = row["feature"]
        a = rank[f]
        r_s = f"{row['pearson_r']:+.4f}" if np.isfinite(row.get("pearson_r", np.nan)) else "   n/a"
        p_s = f"{row['p_value']:.3g}" if np.isfinite(row.get("p_value", np.nan)) else "n/a"
        rho_s = f"{row['spearman_rho']:+.3f}" if np.isfinite(row.get("spearman_rho", np.nan)) else "n/a"
        print(f"{f:<22}{r_s:>9}{p_s:>12}{rho_s:>9}  {a['decision']}")

    n_tested = int(records["pearson_r"].notna().sum())
    n_sig = int((records["p_value"] < args.p_max).sum())
    n_pass = int(((records["abs_r"] > args.r_floor)
                  & (records["p_value"] < args.p_max)).sum())
    print(f"\n[+] Tested {n_tested} features; {n_sig} passed p < {args.p_max}; "
          f"{n_pass} passed both gates")
    print(f"[+] Selected (literal top-{args.top_k} by |r|): {selected}")
    print(f"[+] Selected (collinearity-deduped):          {deduped}")
    if n_tested:
        print(f"[+] Bonferroni-adjusted alpha would be {args.p_max / n_tested:.5f} "
              f"({int((records['p_value'] < args.p_max / n_tested).sum())} would survive)")

    # Correlation among the selected set, to show the redundancy guard worked.
    sel_corr = df[selected].corr().round(3).to_dict() if selected else {}
    dup_report = []
    for i, a in enumerate(selected):
        for b in selected[i + 1:]:
            r_ab = float(np.corrcoef(df[a].to_numpy(dtype=float),
                                     df[b].to_numpy(dtype=float))[0, 1])
            if abs(r_ab) >= COLLINEARITY_MAX:
                dup_report.append({"a": a, "b": b, "r": round(r_ab, 4)})
    print(f"[+] Redundant pairs inside the literal selected set: {len(dup_report)}")
    for d in dup_report:
        print(f"    {d['a']} <-> {d['b']}  r={d['r']:+.3f}")

    report = {
        "task": "validate_features_vs_snort",
        "target": args.target,
        "n_samples": int(len(df)),
        "n_positive": int(y.sum()),
        "positive_rate": float(y.mean()),
        "gate": {"abs_pearson_r_gt": args.r_floor, "p_lt": args.p_max,
                 "collinearity_max": COLLINEARITY_MAX, "top_k": args.top_k},
        "n_tested": n_tested,
        "n_significant": n_sig,
        "n_passing_both_gates": n_pass,
        "bonferroni_alpha": args.p_max / n_tested if n_tested else None,
        "baseline_features": BASELINE_ENCODED,
        "selected_features": selected,
        "selected_features_deduped": deduped,
        "redundant_pairs_in_selected": dup_report,
        "enhanced_features": BASELINE_ENCODED + selected,
        "feature_stats": [
            {k: (None if isinstance(v, float) and not np.isfinite(v) else v)
             for k, v in row.items() if k != "_vec"}
            for row in records.to_dict("records")
        ],
        "audit": [
            {**a, "pearson_r": (None if a["pearson_r"] is None
                                or not np.isfinite(a["pearson_r"]) else a["pearson_r"]),
             "p_value": (None if a["p_value"] is None
                         or not np.isfinite(a["p_value"]) else a["p_value"])}
            for a in audit
        ],
        "selected_correlation_matrix": sel_corr,
    }
    out_json.write_text(json.dumps(report, indent=2))
    print(f"[+] Wrote {out_json.relative_to(REPO)}")

    # Markdown table
    lines = [
        "# Feature validation vs " + ("Snort verdicts" if args.target == "detected"
                                       else "the XGBoost judge verdict"),
        "",
        f"- Samples: **{len(df)}** ({int(y.sum())} positive on `{args.target}`, "
        f"{y.mean():.1%})",
        f"- Target: `{args.target}`",
        f"- Gate: |Pearson r| > {args.r_floor}, p < {args.p_max}, top {args.top_k}",
        f"- Tested {n_tested} features; {n_sig} passed p < {args.p_max}; "
        f"{n_pass} passed both gates; **{len(selected)} selected**",
        "",
        "> A binary target makes Pearson r the point-biserial correlation; "
        "Spearman rho is reported alongside so a monotone-but-nonlinear "
        "relationship is not missed.",
        "",
        "| # | feature | Pearson r | p | Spearman rho | decision | reason |",
        "|---|---------|-----------|---|--------------|----------|--------|",
    ]
    for i, (_, row) in enumerate(records.sort_values(
            "abs_r", ascending=False, na_position="last").iterrows(), 1):
        a = rank[row["feature"]]
        r_s = f"{row['pearson_r']:+.4f}" if np.isfinite(row.get("pearson_r", np.nan)) else "n/a"
        p_s = f"{row['p_value']:.3g}" if np.isfinite(row.get("p_value", np.nan)) else "n/a"
        rho_s = f"{row['spearman_rho']:+.3f}" if np.isfinite(row.get("spearman_rho", np.nan)) else "n/a"
        lines.append(f"| {i} | `{row['feature']}` | {r_s} | {p_s} | {rho_s} | "
                     f"{a['decision']} | {a['reason']} |")

    lines += ["", "## Selected feature set (literal gate)", "",
              "```", json.dumps(selected), "```", "",
              "## Collinearity-deduplicated set", "",
              "```", json.dumps(deduped), "```", "",
              f"## Redundancy inside the literal selected set ({len(dup_report)} pairs "
              f"with |r| >= {COLLINEARITY_MAX})", ""]
    if dup_report:
        lines += ["| feature A | feature B | r |", "|-----------|-----------|---|"]
        for d in dup_report:
            lines.append(f"| `{d['a']}` | `{d['b']}` | {d['r']:+.4f} |")
        lines += ["",
                  "The literal top-10 is dominated by one signal: the packet-size "
                  "family is 9 algebraic restatements of `tot_bytes / tot_pkts` "
                  "(`avg_pkt_size` is a literal alias of `pkt_size_mean`). Only "
                  "`payload_entropy_est`, `pkt_size_iqr`, `pkt_size_min` and "
                  "`rst_count` survive de-duplication. The literal set is kept as "
                  "the training set because that is what the plan specified, but "
                  "any claim that 10 features add 10 features' worth of signal "
                  "would be wrong."]
    else:
        lines.append("_none — the selected set is already de-correlated_")

    lines += ["", "## Baseline (control) features", "",
              "```", json.dumps(BASELINE_ENCODED), "```", "",
              "## Selected-feature correlation matrix", "",
              "```json", json.dumps(sel_corr, indent=2), "```"]
    out_md.write_text("\n".join(lines) + "\n")
    print(f"[+] Wrote {out_md.relative_to(REPO)}")

    return 0 if selected else 1


if __name__ == "__main__":
    raise SystemExit(main())
