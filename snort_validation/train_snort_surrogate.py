#!/usr/bin/env python3
import json, sys
from pathlib import Path
import joblib
import numpy as np
from sklearn.metrics import accuracy_score, roc_auc_score
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier

REPO = Path(__file__).parent.parent
sys.path.insert(0, str(REPO))

FEAT_KEYS = ("dur", "tot_pkts", "tot_bytes", "src_bytes")

def enc(encoder, value, default=0.0):
    try:
        return float(encoder.transform([str(value)])[0])
    except Exception:
        return float(default)

def build_dataset():
    proto = joblib.load(REPO / "data" / "label_encoder_proto.pkl")
    state = joblib.load(REPO / "data" / "label_encoder_state.pkl")
    X, y = [], []
    for pol in ("agent", "random", "baseline"):
        ev = json.loads((REPO/"snort_validation"/"reports"/f"{pol}_evaluation.json").read_text())
        sv = json.loads((REPO/"snort_validation"/"reports"/f"{pol}_snort_validation.json").read_text())
        det = {e["episode"]: e["detected"] for e in sv["episode_results"]}
        for ep in ev["episodes"]:
            f = ep["mutated_features"]
            X.append([float(f.get(k, 0.0)) for k in FEAT_KEYS] +
                     [enc(proto, f.get("proto", "tcp")), enc(state, f.get("state", "CON"))])
            y.append(det[ep["episode_id"]])
    return np.asarray(X, dtype=np.float32), np.asarray(y, dtype=np.int8)

if __name__ == "__main__":
    X, y = build_dataset()
    print(f"[+] Dataset: {X.shape[0]} rows, {int(y.sum())} positive ({y.mean():.1%})")
    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.25, random_state=42, stratify=y)
    clf = XGBClassifier(n_estimators=200, max_depth=4, learning_rate=0.1,
                        n_jobs=1, eval_metric="logloss", random_state=42)
    clf.fit(X_tr, y_tr)
    p = clf.predict_proba(X_te)[:, 1]
    acc = accuracy_score(y_te, (p >= 0.5).astype(int))
    auc = roc_auc_score(y_te, p)
    print(f"[+] Held-out AUC={auc:.3f} Acc={acc:.3f}")
    out = REPO / "data" / "snort_surrogate.pkl"
    joblib.dump(clf, out)
    print(f"[+] Saved {out}")