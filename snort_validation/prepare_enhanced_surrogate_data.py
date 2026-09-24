#!/usr/bin/env python3
"""Task 3 — prepare the enhanced surrogate training set.

Takes the 320 labelled samples and the feature-selection report from Task 2 and
writes two frozen matrices plus a provenance manifest:

    snort_validation/data/surrogate_baseline.npz   6 baseline features
    snort_validation/data/surrogate_enhanced.npz   6 baseline + 10 selected
    snort_validation/data/surrogate_dataset_manifest.json

Why .npz and not "just retrain from the reports"
------------------------------------------------
Freezing the matrices means the baseline and enhanced runs are guaranteed to
be trained and scored on identical rows.  If the retrain reads the reports
again, any later change to the reports (or to a feature definition) silently
invalidates the comparison.  The manifest records the row count, the positive
count, a SHA-256 of each matrix and the exact feature order, so the numbers in
the CHANGELOG can be re-checked.

Splits
------
The 25% held-out test split is stratified and seeded (42) and is written into
the manifest, so the baseline and enhanced AUC are measured on the *same*
80-ish rows.  The split is computed here, once, and both trainers read the
same index arrays.

Leakage note
------------
All 320 rows come from four policy runs whose episodes share the same CTU-13
source flows; a sample from one policy run can therefore have a near-duplicate
in another.  The split is stratified but not grouped, so the held-out AUC is
optimistic relative to a grouped-by-source-flow split.  This is stated in the
manifest and in the CHANGELOG rather than hidden.
"""
import argparse
import hashlib
import json
import sys
from pathlib import Path

import numpy as np
from sklearn.model_selection import train_test_split

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from surrogate_dataset import (  # noqa: E402
    BASELINE_ENCODED, build_dataset, enhanced_feature_names,
    load_selected_features, xy,
)

DATA = REPO / "snort_validation" / "data"
OUT_BASE = DATA / "surrogate_baseline.npz"
OUT_ENH = DATA / "surrogate_enhanced.npz"
OUT_MANIFEST = DATA / "surrogate_dataset_manifest.json"
SEED = 42
TEST_SIZE = 0.25


def sha256(path):
    h = hashlib.sha256()
    h.update(Path(path).read_bytes())
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--selection-report", default=None,
                    help="override the feature-validation report path")
    ap.add_argument("--seed", type=int, default=SEED)
    ap.add_argument("--test-size", type=float, default=TEST_SIZE)
    args = ap.parse_args()

    selected, report = load_selected_features(args.selection_report)
    print(f"[+] Selection report: gate={report['gate']}")
    print(f"[+] Selected {len(selected)} features: {selected}")

    df = build_dataset()
    baseline_names = list(BASELINE_ENCODED)
    enhanced_names = enhanced_feature_names(selected)

    Xb, y = xy(df, baseline_names)
    Xe, y2 = xy(df, enhanced_names)
    assert np.array_equal(y, y2), "baseline and enhanced labels diverged"

    # One split, shared by both matrices.
    idx = np.arange(len(y))
    tr, te = train_test_split(idx, test_size=args.test_size,
                              random_state=args.seed, stratify=y)
    tr, te = np.sort(tr), np.sort(te)

    for name, X in (("baseline", Xb), ("enhanced", Xe)):
        assert np.array_equal(X[tr][:, :len(baseline_names)],
                              Xb[tr]), f"{name}: first 6 cols must be the baseline"
        print(f"[+] {name:<9} X={X.shape}  train={len(tr)}  test={len(te)}  "
              f"pos(train)={int(y[tr].sum())}  pos(test)={int(y[te].sum())}")

    np.savez_compressed(OUT_BASE, X=Xb, y=y, train_idx=tr, test_idx=te,
                        feature_names=np.array(baseline_names, dtype=object))
    np.savez_compressed(OUT_ENH, X=Xe, y=y, train_idx=tr, test_idx=te,
                        feature_names=np.array(enhanced_names, dtype=object))
    print(f"[+] Wrote {OUT_BASE.relative_to(REPO)}")
    print(f"[+] Wrote {OUT_ENH.relative_to(REPO)}")

    manifest = {
        "task": "prepare_enhanced_surrogate_data",
        "n_samples": int(len(df)),
        "n_positive": int(y.sum()),
        "positive_rate": float(y.mean()),
        "source_runs": df["source"].value_counts().to_dict(),
        "baseline_features": baseline_names,
        "selected_features": selected,
        "enhanced_features": enhanced_names,
        "n_baseline": len(baseline_names),
        "n_enhanced": len(enhanced_names),
        "split": {"seed": args.seed, "test_size": args.test_size,
                  "stratified": True, "grouped": False,
                  "n_train": int(len(tr)), "n_test": int(len(te)),
                  "pos_train": int(y[tr].sum()), "pos_test": int(y[te].sum())},
        "leakage_note": (
            "Split is stratified by verdict but NOT grouped by source flow: the "
            "four policy runs draw from the same CTU-13 flow pool, so near-"
            "duplicate flows can straddle the split and held-out AUC is "
            "optimistic relative to a grouped split."),
        "artifacts": {
            "surrogate_baseline.npz": sha256(OUT_BASE),
            "surrogate_enhanced.npz": sha256(OUT_ENH),
        },
        "feature_validation_report": str(
            (Path(args.selection_report) if args.selection_report
             else DATA / "feature_validation_report.json").relative_to(REPO)),
    }
    OUT_MANIFEST.write_text(json.dumps(manifest, indent=2))
    print(f"[+] Wrote {OUT_MANIFEST.relative_to(REPO)}")
    print(f"[+] sha256 baseline {manifest['artifacts']['surrogate_baseline.npz'][:16]}...")
    print(f"[+] sha256 enhanced {manifest['artifacts']['surrogate_enhanced.npz'][:16]}...")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
