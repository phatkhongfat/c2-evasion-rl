"""Shared builder for the Snort-verdict surrogate dataset.

Every consumer of the labelled dataset — feature validation, training-data
preparation and the surrogate trainer — must see *identical* rows in
*identical* column order, otherwise a "surrogate improvement" can be an
artefact of two scripts disagreeing about the feature vector.  This module is
the single definition.

Sample provenance (320 labelled rows)
-------------------------------------
The labelled corpus is four policy runs of 80 episodes each, every episode
having been turned into a pcap by ``flow_to_pcap.py`` and judged by Snort:

    reports/agent_evaluation.json      + agent_snort_validation.json
    reports/random_evaluation.json     + random_snort_validation.json
    reports/baseline_evaluation.json   + baseline_snort_validation.json
    reports/agent_evaluation_l10.json  + agent_snort_validation_l10.json

    = 240 "blind" samples + 80 "lambda=10" samples = 320

``agent_evaluation.json`` and ``agent_evaluation_l10.json`` are byte-identical
(the current blind agent *is* the lambda=10 agent, promoted after the sweep),
so the 320 rows are four distinct policy runs, not 320 distinct policies.

Feature vector
--------------
Baseline 6 (raw, the exact vector the XGBoost judge is fed, in env order):
    dur, tot_pkts, tot_bytes, src_bytes, proto_encoded, state_encoded
Enhanced = baseline 6 + the selected candidate features (see
``feature_validation_report.json``).

Candidate features are derived from the **mutated** flow, because the mutated
flow is what was synthesised into a pcap and what Snort actually judged.
"""
import json
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "ai_agent"))
from flow_features import CANDIDATE_FEATURES, derive_flow_features  # noqa: E402

REPORTS = REPO / "snort_validation" / "reports"
DATA = REPO / "data"

BASELINE_FEATURES = ["dur", "tot_pkts", "tot_bytes", "src_bytes"]
BASELINE_ENCODED = BASELINE_FEATURES + ["proto_encoded", "state_encoded"]

# (tag, evaluation json, snort verdict json)
RUNS = [
    ("blind_agent", "agent_evaluation.json", "agent_snort_validation.json"),
    ("random", "random_evaluation.json", "random_snort_validation.json"),
    ("baseline", "baseline_evaluation.json", "baseline_snort_validation.json"),
    ("agent_lambda10", "agent_evaluation_l10.json", "agent_snort_validation_l10.json"),
]


def _load_encoders():
    return (
        joblib.load(DATA / "label_encoder_proto.pkl"),
        joblib.load(DATA / "label_encoder_state.pkl"),
    )


def _encode(encoder, value, default=0.0):
    """Mirror C2EvasionEnv._encode_value exactly."""
    try:
        return float(encoder.transform([str(value)])[0])
    except Exception:
        return float(default)


def build_dataset(verbose=True):
    """Return the 320-row labelled frame with baseline + candidate features.

    Columns: source, episode_id, run_xgb_evaded, detected,
             <BASELINE_ENCODED 6>, <CANDIDATE_FEATURES 20>
    """
    proto_enc, state_enc = _load_encoders()
    rows = []
    for tag, eval_file, snort_file in RUNS:
        ev = json.loads((REPORTS / eval_file).read_text())
        sv = json.loads((REPORTS / snort_file).read_text())
        verdicts = {e["episode"]: int(e["detected"]) for e in sv["episode_results"]}
        for ep in ev["episodes"]:
            ep_id = ep["episode_id"]
            if ep_id not in verdicts:
                continue
            flow = dict(ep["mutated_features"])
            row = {
                "source": tag,
                "episode_id": ep_id,
                "run_xgb_evaded": int(bool(ep.get("evaded_xgboost"))),
                "detected": verdicts[ep_id],
                "dur": float(flow.get("dur", 0.0)),
                "tot_pkts": float(flow.get("tot_pkts", 0.0)),
                "tot_bytes": float(flow.get("tot_bytes", 0.0)),
                "src_bytes": float(flow.get("src_bytes", 0.0)),
                "proto_encoded": _encode(proto_enc, flow.get("proto", "tcp")),
                "state_encoded": _encode(state_enc, flow.get("state", "CON")),
            }
            row.update(derive_flow_features(flow))
            rows.append(row)

    df = pd.DataFrame(rows)
    df = df[["source", "episode_id", "run_xgb_evaded", "detected"]
            + BASELINE_ENCODED + CANDIDATE_FEATURES]
    if verbose:
        print(f"[+] Built {len(df)} labelled samples "
              f"({df['detected'].sum()} Snort-detected, "
              f"{df['detected'].mean():.1%})")
        for tag, _, _ in RUNS:
            sub = df[df["source"] == tag]
            print(f"    {tag:<16} n={len(sub):>3}  detected={sub['detected'].sum():>3} "
                  f"({sub['detected'].mean():.1%})")
    return df


def load_selected_features(report_path=None):
    """Read the selected feature list produced by validate_features_vs_snort.py."""
    path = Path(report_path) if report_path else (
        REPO / "snort_validation" / "data" / "feature_validation_report.json")
    report = json.loads(path.read_text())
    return report["selected_features"], report


def enhanced_feature_names(selected):
    return BASELINE_ENCODED + list(selected)


def xy(df, feature_names):
    """Split a frame into (X float32 array, y int8 array) in column order."""
    missing = [c for c in feature_names if c not in df.columns]
    if missing:
        raise KeyError(f"missing feature columns: {missing}")
    X = df[feature_names].to_numpy(dtype=np.float32)
    y = df["detected"].to_numpy(dtype=np.int8)
    return X, y
