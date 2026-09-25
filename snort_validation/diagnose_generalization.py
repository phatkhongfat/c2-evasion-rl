#!/usr/bin/env python3
"""
Diagnose the cross-capture generalisation gap and test concrete remedies.

Three questions this answers:
  1. Is "snort_alert" even ONE concept across captures?  If capture A's
     positives are DNS-query rules and capture B's are trojan-checkin rules,
     the target is inconsistent and no model can generalise -- that is a
     task-definition bug, not overfitting.
  2. Which features are "capture fingerprints" (constant within a capture,
     different across captures)?  Those are what a model latches onto and
     then fails to transfer.
  3. Which remedies actually move the cross-capture AUC, measured not guessed.

Usage:
    python snort_validation/diagnose_generalization.py \
        --data data/ctu13_snort_labeled.parquet \
        --out snort_validation/reports/generalization_diagnosis.json
"""

import argparse
import json
import re
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score
from xgboost import XGBClassifier

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "snort_validation"))
from label_real_flows_with_snort import run_snort_over_capture  # noqa: E402

ALERT_RE = re.compile(
    r"\[\*\*\]\s*\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s*"
    r"(?P<msg>.*?)\s*\[\*\*\].*?"
    r"\{(?P<proto>TCP|UDP|ICMP)\}\s*"
    r"(?P<src>[\d.]+):(?P<sport>\d+)\s*->\s*(?P<dst>[\d.]+):(?P<dport>\d+)"
)

FEATURES = [
    "fwd_pkts", "bwd_pkts", "fwd_bytes", "bwd_bytes", "byte_ratio",
    "pkt_size_mean", "pkt_size_std", "pkt_size_min", "pkt_size_max",
    "pkt_size_median", "pkt_size_iqr", "pkt_size_cv",
    "iat_mean", "iat_std", "iat_min", "iat_max", "iat_cv",
    "pkt_rate", "bytes_rate", "flow_duration",
    "syn_count", "fin_count", "rst_count", "psh_count", "ack_count",
    "urg_count", "flags_variety",
    "payload_bytes", "payload_fraction", "hdr_bytes",
    "payload_mean_len", "payload_max_len", "payload_entropy",
    "proto_id", "is_well_known_port",
    "n_distinct_pkt_sizes", "dominant_pkt_size_frac",
    "tot_pkts", "tot_bytes",
]

BASE_PARAMS = dict(n_estimators=400, max_depth=5, learning_rate=0.05,
                   subsample=0.9, colsample_bytree=0.9, min_child_weight=2,
                   reg_lambda=1.0, eval_metric="logloss", n_jobs=4,
                   random_state=42)


# --------------------------------------------------------------------------
# 1. Is the label one concept?
# --------------------------------------------------------------------------
def rule_composition(root, cache):
    """Per capture: which rules fired, and on how many distinct flows."""
    out = {}
    for pcap in sorted(Path(root).glob("*/botnet-capture-*.pcap")):
        alert_path = run_snort_over_capture(pcap, cache / pcap.stem)
        tuple_sids = defaultdict(set)
        msgs = {}
        if alert_path and alert_path.exists():
            with open(alert_path, errors="ignore") as fh:
                for line in fh:
                    m = ALERT_RE.search(line)
                    if not m:
                        continue
                    d = m.groupdict()
                    key = (d["src"], int(d["sport"]), d["dst"], int(d["dport"]),
                           d["proto"].lower())
                    tuple_sids[key].add(int(d["sid"]))
                    msgs[int(d["sid"])] = d["msg"].strip()
        per_rule = defaultdict(int)
        for key, sids in tuple_sids.items():
            for s in sids:
                per_rule[s] += 1
        out[pcap.stem] = {
            "n_alert_flows": len(tuple_sids),
            "rules": [{"sid": s, "flows": c, "msg": msgs.get(s, "")}
                      for s, c in sorted(per_rule.items(), key=lambda kv: -kv[1])],
        }
        print(f"    {pcap.stem:<40} {len(tuple_sids):>6} alert-flows, "
              f"{len(per_rule)} rules")
    return out


# --------------------------------------------------------------------------
# 2. Which features are capture fingerprints?
# --------------------------------------------------------------------------
def fingerprint_scores(df, feats):
    """eta^2 of each feature w.r.t. capture identity.

    eta^2 = between-capture variance / total variance.  ~0 means the feature
    looks the same in every capture (portable).  ~1 means the feature alone
    identifies the capture (a fingerprint the model can cheat with).
    """
    scores = []
    groups = [g for _, g in df.groupby("capture")]
    for f in feats:
        vals = df[f].to_numpy(dtype=float)
        finite = np.isfinite(vals)
        if finite.sum() < 50:
            continue
        grand = vals[finite].mean()
        ss_total = float(((vals[finite] - grand) ** 2).sum())
        if ss_total <= 0:
            scores.append((f, 0.0))
            continue
        ss_between = 0.0
        for g in groups:
            v = g[f].to_numpy(dtype=float)
            v = v[np.isfinite(v)]
            if len(v) == 0:
                continue
            ss_between += len(v) * (v.mean() - grand) ** 2
        scores.append((f, float(ss_between / ss_total)))
    scores.sort(key=lambda t: -t[1])
    return scores


# --------------------------------------------------------------------------
# 3. Remedies, measured by leave-one-capture-out
# --------------------------------------------------------------------------
def rank_normalize(df, feats):
    """Within-capture percentile rank: removes capture-level location/scale."""
    out = df.copy()
    for f in feats:
        out[f] = df.groupby("capture")[f].rank(pct=True)
    return out


def cv_evaluate(df, feats, params, train_captures=None, label=""):
    X_all = np.nan_to_num(df[feats].to_numpy(dtype=np.float32),
                          nan=0.0, posinf=0.0, neginf=0.0)
    y_all = df["snort_alert"].to_numpy(dtype=int)
    caps = df["capture"].to_numpy()

    oof = np.full(len(df), np.nan)
    folds = []
    for cap in sorted(set(caps)):
        te = caps == cap
        tr = ~te
        if train_captures is not None:
            tr &= np.isin(caps, train_captures)
        if y_all[te].sum() == 0 or tr.sum() == 0 or y_all[tr].sum() == 0:
            folds.append({"capture": cap, "n_test": int(te.sum()),
                          "n_pos": int(y_all[te].sum()), "auc": None,
                          "note": "single-class or empty train"})
            continue
        clf = XGBClassifier(**params)
        clf.fit(X_all[tr], y_all[tr])
        p = clf.predict_proba(X_all[te])[:, 1]
        oof[te] = p
        try:
            auc = float(roc_auc_score(y_all[te], p))
        except ValueError:
            auc = None
        try:
            ap = float(average_precision_score(y_all[te], p))
        except ValueError:
            ap = None
        folds.append({"capture": cap, "n_test": int(te.sum()),
                      "n_pos": int(y_all[te].sum()),
                      "auc": round(auc, 4) if auc else None,
                      "pr_auc": round(ap, 4) if ap else None})

    ev = ~np.isnan(oof)
    pooled = float(roc_auc_score(y_all[ev], oof[ev])) if y_all[ev].sum() > 0 else None
    pooled_pr = float(average_precision_score(y_all[ev], oof[ev])) if y_all[ev].sum() > 0 else None
    aucs = [f["auc"] for f in folds if f["auc"] is not None]
    macro = float(np.mean(aucs)) if aucs else None
    print(f"  {label:<34} pooled={pooled:.4f}  macro={macro:.4f}  "
          f"PR-AUC={pooled_pr:.4f}")
    return {"label": label, "pooled_auc": round(pooled, 4) if pooled else None,
            "macro_auc": round(macro, 4) if macro else None,
            "pooled_pr_auc": round(pooled_pr, 4) if pooled_pr else None,
            "folds": folds}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data/ctu13_snort_labeled.parquet")
    ap.add_argument("--root", default="data/stratosphere/CTU-13-Dataset")
    ap.add_argument("--out", default="snort_validation/reports/generalization_diagnosis.json")
    ap.add_argument("--skip-rules", action="store_true")
    args = ap.parse_args()

    df = pd.read_parquet(args.data)
    feats = [f for f in FEATURES if f in df.columns]
    df = df[df["capture"].notna()].reset_index(drop=True)

    report = {"n_flows": int(len(df)), "features": feats}

    # ---- 1. label consistency ----
    if not args.skip_rules:
        print("[1] rule composition per capture")
        cache = Path(tempfile.mkdtemp(prefix="diagrules_"))
        report["rule_composition"] = rule_composition(args.root, cache)

    # ---- 2. fingerprint features ----
    print("\n[2] capture-fingerprint scores (eta^2 w.r.t. capture identity)")
    fps = fingerprint_scores(df, feats)
    report["fingerprint_eta2"] = [{"feature": f, "eta2": round(e, 4)} for f, e in fps]
    for f, e in fps[:12]:
        print(f"    {f:<26} eta2={e:.4f}")
    print("    ...")
    for f, e in fps[-5:]:
        print(f"    {f:<26} eta2={e:.4f}")

    # ---- 3. remedies ----
    print("\n[3] leave-one-capture-out remedies")
    results = []
    results.append(cv_evaluate(df, feats, BASE_PARAMS, label="A baseline"))

    # B: drop capture fingerprints
    portable = [f for f, e in fps if e < 0.5]
    results.append(cv_evaluate(df, portable, BASE_PARAMS,
                               label=f"B drop fingerprints ({len(portable)}f)"))

    # C: shallower + stronger regularisation
    reg = dict(BASE_PARAMS, max_depth=3, min_child_weight=10,
               reg_lambda=10.0, n_estimators=200)
    results.append(cv_evaluate(df, feats, reg, label="C regularised (d3, l10)"))

    # D: within-capture rank normalisation
    df_rank = rank_normalize(df, feats)
    results.append(cv_evaluate(df_rank, feats, BASE_PARAMS,
                               label="D per-capture rank norm"))

    # E: class weighting
    pos = int(df["snort_alert"].sum())
    neg = len(df) - pos
    bal = dict(BASE_PARAMS, scale_pos_weight=max(neg / max(pos, 1), 1.0))
    results.append(cv_evaluate(df, feats, bal, label="E scale_pos_weight"))

    # F: only train on captures where the ruleset demonstrably fires
    covered = [c for c in df["capture"].unique()
               if int(df[df["capture"] == c]["snort_alert"].sum()) > 0]
    results.append(cv_evaluate(df, feats, BASE_PARAMS, train_captures=covered,
                               label=f"F covered-captures-only ({len(covered)})"))

    # G: combined best guess
    results.append(cv_evaluate(df_rank, portable, dict(
        BASE_PARAMS, max_depth=3, min_child_weight=10, reg_lambda=10.0,
        n_estimators=200, scale_pos_weight=max(neg / max(pos, 1), 1.0)),
        train_captures=covered, label="G combined (B+C+D+E+F)"))

    report["remedies"] = results

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w") as fh:
        json.dump(report, fh, indent=2)
    print(f"\n[+] report written: {out}")

    print("\nsummary (pooled / macro / PR-AUC):")
    for r in results:
        print(f"  {r['label']:<34} {r['pooled_auc']} / {r['macro_auc']} / {r['pooled_pr_auc']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
