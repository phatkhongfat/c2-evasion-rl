#!/usr/bin/env python3
"""
Train the Snort surrogate on REAL measured CTU-13 features.

DIFFERENCE FROM THE OLD SURROGATE
---------------------------------
The old surrogate (``train_snort_surrogate.py``) learned from features that
were *reconstructed* from six flow aggregates, against *hand-written* rules.
It scored AUC 0.997 on its own distribution and still transferred terribly
(the λ=5/λ=10 agents evaded real Snort worse than a blind agent).

This trainer uses:
  * features MEASURED from real packets (``extract_ctu13_real_features.py``);
  * labels from REAL Snort with the ET Open C2 ruleset.

VALIDATION
----------
Cross-capture (leave-one-capture-out) evaluation.  A random split would leak:
flows from the same botnet capture are highly correlated, so a random split
inflates AUC and hides exactly the generalisation failure we are trying to
measure.  Leave-one-capture-out answers "does this surrogate predict Snort on
a botnet it has never seen?", which is the question that matters.

USAGE
-----
    python snort_validation/train_real_snort_surrogate.py \
        --data data/ctu13_snort_labeled.parquet \
        --out data/snort_surrogate_real.pkl \
        --report snort_validation/reports/real_surrogate_report.json
"""

import argparse
import json
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, precision_score, recall_score, roc_auc_score
from xgboost import XGBClassifier

REPO = Path(__file__).resolve().parent.parent

# Features chosen by the measured feature-vs-verdict validation
# (reports/real_feature_validation.json).  Only features with a usable effect
# size (|AUC-0.5| >= 0.30 on the first capture) plus the strongest remaining
# behavioural summaries are kept; identifiers (IPs, ports) are excluded on
# purpose so the model cannot key on the specific botnet.
SURROGATE_FEATURES = [
    # strongest separators from validation
    "n_distinct_pkt_sizes",      # AUC 0.949
    "dominant_pkt_size_frac",    # AUC 0.047 (inverted)
    "bwd_bytes",                 # AUC 0.941
    "bwd_pkts",                  # AUC 0.934
    "pkt_size_iqr",              # AUC 0.906
    "syn_count",                 # AUC 0.109 (inverted)
    "pkt_size_max",              # AUC 0.880
    "tot_bytes",                 # AUC 0.879
    "pkt_size_median",           # AUC 0.869
    "proto_id",                  # AUC 0.868
    "pkt_size_mean",             # AUC 0.859
    "pkt_size_std",              # AUC 0.853
    "pkt_size_cv",               # AUC 0.850
    "flags_variety",             # AUC 0.161 (inverted)
    "iat_cv",                    # AUC 0.825, d=+5.06
    "tot_pkts",                  # AUC 0.817
    "fwd_pkts", "fwd_bytes", "hdr_bytes", "byte_ratio",
    "iat_mean", "iat_std", "pkt_rate", "bytes_rate", "flow_duration",
    "payload_entropy", "payload_fraction",
]

XGB_PARAMS = dict(
    n_estimators=400,
    max_depth=5,
    learning_rate=0.05,
    subsample=0.9,
    colsample_bytree=0.9,
    min_child_weight=2,
    reg_lambda=1.0,
    eval_metric="logloss",
    n_jobs=4,
    random_state=42,
)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data/ctu13_snort_labeled.parquet")
    ap.add_argument("--out", default="data/snort_surrogate_real.pkl")
    ap.add_argument("--report", default="snort_validation/reports/real_surrogate_report.json")
    args = ap.parse_args()

    df = pd.read_parquet(args.data)
    feats = [f for f in SURROGATE_FEATURES if f in df.columns]
    missing = [f for f in SURROGATE_FEATURES if f not in df.columns]
    if missing:
        print(f"[!] missing features (skipped): {missing}", file=sys.stderr)
    if "snort_alert" not in df.columns:
        print("[-] data has no snort_alert column", file=sys.stderr)
        return 1

    X = df[feats].to_numpy(dtype=np.float32)
    y = df["snort_alert"].to_numpy(dtype=int)
    X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
    print(f"[*] {len(df):,} flows, {len(feats)} features, "
          f"{y.sum():,} positive ({100.0 * y.mean():.2f}%)")

    # ---------- leave-one-capture-out ----------
    captures = sorted(df["capture"].unique()) if "capture" in df.columns else ["all"]
    fold_results = []
    oof_pred = np.zeros(len(df), dtype=float)
    for cap in captures:
        test_mask = (df["capture"] == cap).to_numpy() if "capture" in df.columns \
            else np.ones(len(df), dtype=bool)
        train_mask = ~test_mask
        if y[test_mask].sum() == 0 or y[train_mask].sum() == 0:
            print(f"[!] {cap}: single-class fold, skipped "
                  f"(pos in test={int(y[test_mask].sum())})")
            continue
        clf = XGBClassifier(**XGB_PARAMS)
        clf.fit(X[train_mask], y[train_mask])
        p = clf.predict_proba(X[test_mask])[:, 1]
        oof_pred[test_mask] = p
        try:
            auc = roc_auc_score(y[test_mask], p)
        except ValueError:
            auc = float("nan")
        thr = 0.5
        yhat = (p >= thr).astype(int)
        fold_results.append({
            "capture": cap,
            "n_test": int(test_mask.sum()),
            "n_pos_test": int(y[test_mask].sum()),
            "auc": round(float(auc), 4) if auc == auc else None,
            "accuracy@0.5": round(float(accuracy_score(y[test_mask], yhat)), 4),
            "precision@0.5": round(float(precision_score(y[test_mask], yhat, zero_division=0)), 4),
            "recall@0.5": round(float(recall_score(y[test_mask], yhat, zero_division=0)), 4),
        })
        print(f"    {cap:<40} n={int(test_mask.sum()):>6} "
              f"pos={int(y[test_mask].sum()):>5} AUC={auc:.4f}")

    # ---------- pooled out-of-fold AUC ----------
    valid = np.array([c is not None for c in [
        f["auc"] for f in fold_results]] + [True] * (len(df) - len(fold_results)))
    mask_eval = np.zeros(len(df), dtype=bool)
    for cap in captures:
        m = (df["capture"] == cap).to_numpy() if "capture" in df.columns \
            else np.ones(len(df), dtype=bool)
        if y[m].sum() > 0 and (~m).sum() > 0:
            mask_eval |= m
    try:
        pooled_auc = float(roc_auc_score(y[mask_eval], oof_pred[mask_eval]))
    except ValueError:
        pooled_auc = float("nan")
    print(f"\n[*] pooled out-of-fold AUC (cross-capture): {pooled_auc:.4f}")

    # ---------- final model on all data ----------
    final = XGBClassifier(**XGB_PARAMS)
    final.fit(X, y)
    train_auc = float(roc_auc_score(y, final.predict_proba(X)[:, 1]))
    print(f"[*] in-sample AUC (all data, for reference only): {train_auc:.4f}")

    # feature importances
    imp = sorted(zip(feats, final.feature_importances_.tolist()),
                 key=lambda t: -t[1])

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": final, "features": feats,
                 "trained_on": str(args.data),
                 "n_train": int(len(df))}, out)
    print(f"[+] surrogate written: {out}")

    report = {
        "data": str(args.data),
        "n_flows": int(len(df)),
        "n_features": len(feats),
        "features": feats,
        "positive_rate": round(float(y.mean()), 4),
        "validation": "leave-one-capture-out (cross-capture)",
        "pooled_out_of_fold_auc": round(pooled_auc, 4) if pooled_auc == pooled_auc else None,
        "in_sample_auc_reference_only": round(train_auc, 4),
        "folds": fold_results,
        "feature_importance": [
            {"feature": f, "importance": round(float(i), 5)} for f, i in imp
        ],
        "ruleset": "ET Open C2 subset (21,374 rules)",
        "note": (
            "In-sample AUC is reported only to expose overfitting: the honest "
            "number is pooled_out_of_fold_auc, measured on captures the model "
            "never trained on."
        ),
    }
    rp = Path(args.report)
    rp.parent.mkdir(parents=True, exist_ok=True)
    with open(rp, "w") as fh:
        json.dump(report, fh, indent=2)
    print(f"[+] report written: {rp}")

    print("\ntop feature importances:")
    for f, i in imp[:12]:
        print(f"  {f:<26} {i:.4f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
