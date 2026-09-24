#!/usr/bin/env python3
"""Task 4 — train the Snort-verdict surrogate, baseline or enhanced.

Two modes, one trainer, so the comparison is apples-to-apples:

    --baseline   6 raw flow features  (dur, tot_pkts, tot_bytes, src_bytes,
                                      proto_encoded, state_encoded)
    --enhanced   6 raw + 10 features selected by validate_features_vs_snort.py

Both modes read the frozen matrices written by
``prepare_enhanced_surrogate_data.py`` and the *same* train/test index arrays,
so the AUC delta is a feature-set delta and nothing else.

The trained model is stamped with ``snort_feature_names_`` before saving.  The
RL environment reads that attribute to build the reward vector in the right
order; without it a 16-feature model would be fed the wrong columns and the
defense-aware reward would be quietly wrong.

Outputs
-------
    data/snort_surrogate.pkl            (--baseline; the path the env defaults to)
    data/snort_surrogate_enhanced.pkl   (--enhanced)
    snort_validation/data/surrogate_training_report{,_enhanced}.json

Exit code is 0 when the mode's own acceptance gate passes:
    baseline: AUC reported only (no gate — it is the control)
    enhanced: AUC >= 0.95 required
"""
import argparse
import json
import sys
from pathlib import Path

import joblib
import numpy as np
from sklearn.metrics import (accuracy_score, average_precision_score,
                             brier_score_loss, confusion_matrix, f1_score,
                             precision_score, recall_score, roc_auc_score)
from xgboost import XGBClassifier

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

DATA = REPO / "data"
VDATA = REPO / "snort_validation" / "data"
XGB_PARAMS = dict(n_estimators=200, max_depth=4, learning_rate=0.1,
                  n_jobs=1, eval_metric="logloss", random_state=42)


def load_matrix(mode):
    name = "surrogate_enhanced.npz" if mode == "enhanced" else "surrogate_baseline.npz"
    path = VDATA / name
    if not path.exists():
        raise SystemExit(
            f"{path} not found — run "
            f"snort_validation/prepare_enhanced_surrogate_data.py first")
    z = np.load(path, allow_pickle=True)
    return (z["X"], z["y"], z["train_idx"], z["test_idx"],
            [str(n) for n in z["feature_names"]])


def metrics(y_true, y_pred, proba):
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return {
        "auc": float(roc_auc_score(y_true, proba)),
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "average_precision": float(average_precision_score(y_true, proba)),
        "brier": float(brier_score_loss(y_true, proba)),
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--enhanced", action="store_true",
                    help="train on 6 baseline + 10 selected features")
    ap.add_argument("--baseline", action="store_true",
                    help="train on the 6 raw features (control)")
    ap.add_argument("--out", default=None, help="override output model path")
    ap.add_argument("--auc-gate", type=float, default=0.95)
    args = ap.parse_args()

    if args.enhanced == args.baseline:
        raise SystemExit("choose exactly one of --baseline / --enhanced")
    mode = "enhanced" if args.enhanced else "baseline"

    X, y, tr, te, names = load_matrix(mode)
    assert len(names) == X.shape[1], (len(names), X.shape)
    print(f"[*] Mode={mode}  X={X.shape}  features={len(names)}")
    print(f"[*] train={len(tr)} test={len(te)}  "
          f"pos_train={int(y[tr].sum())} pos_test={int(y[te].sum())}")

    clf = XGBClassifier(**XGB_PARAMS)
    clf.fit(X[tr], y[tr])
    proba = clf.predict_proba(X[te])[:, 1]
    pred = (proba >= 0.5).astype(int)
    m = metrics(y[te], pred, proba)

    print(f"\n[+] Held-out ({len(te)} samples) metrics:")
    for k in ("auc", "accuracy", "precision", "recall", "f1",
              "average_precision", "brier"):
        print(f"      {k:<18}{m[k]:.4f}")
    print(f"      confusion  TP={m['tp']} FP={m['fp']} TN={m['tn']} FN={m['fn']}")

    imp = sorted(zip(names, clf.feature_importances_),
                 key=lambda t: -t[1])
    print(f"\n[+] Top feature importances:")
    for n, v in imp[:10]:
        print(f"      {n:<22}{v:.4f}")

    # Stamp the feature order onto the model so the env cannot guess wrong.
    clf.snort_feature_names_ = list(names)
    out = Path(args.out) if args.out else (
        DATA / ("snort_surrogate_enhanced.pkl" if args.enhanced
                else "snort_surrogate.pkl"))
    joblib.dump(clf, out)
    print(f"\n[+] Saved {out.relative_to(REPO)} "
          f"(stamped snort_feature_names_, width={len(names)})")

    report = {
        "task": "train_snort_surrogate",
        "mode": mode,
        "model_path": str(out.relative_to(REPO)),
        "n_features": len(names),
        "feature_names": names,
        "n_train": int(len(tr)), "n_test": int(len(te)),
        "pos_train": int(y[tr].sum()), "pos_test": int(y[te].sum()),
        "xgb_params": XGB_PARAMS,
        "metrics": m,
        "feature_importances": {n: float(v) for n, v in imp},
        "auc_gate": args.auc_gate if args.enhanced else None,
        "auc_gate_passed": bool(m["auc"] >= args.auc_gate) if args.enhanced else None,
    }
    rpath = VDATA / f"surrogate_training_report{'_enhanced' if args.enhanced else ''}.json"
    rpath.write_text(json.dumps(report, indent=2))
    print(f"[+] Wrote {rpath.relative_to(REPO)}")

    if args.enhanced and m["auc"] < args.auc_gate:
        print(f"\n[-] GATE FAILED: AUC {m['auc']:.4f} < {args.auc_gate}")
        return 1
    if args.enhanced:
        print(f"\n[+] GATE PASSED: AUC {m['auc']:.4f} >= {args.auc_gate}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
