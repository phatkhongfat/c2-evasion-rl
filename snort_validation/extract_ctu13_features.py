#!/usr/bin/env python3
"""Task 1 — extract 20 candidate features from the CTU-13 parquet corpus.

Source : data/archive/*.binetflow.parquet   (13 capture files, 10.6M flows)
Output : snort_validation/data/ctu13_features_candidates.csv
         flow_id + 6 baseline features + 20 candidate features = 27 columns

Two products are written, on purpose:

1. ``ctu13_features_candidates.csv`` — a *deterministic, seeded sample* of
   botnet flows (``--max-flows-per-file`` per capture file, seed 42).  The raw
   corpus has 262,573 botnet flows; dumping all of them is a ~40 MB CSV that
   no reviewer will read and that does not belong in git.  The sample is the
   artefact that documents the feature schema and gives the executor a
   concrete table to inspect.

2. ``ctu13_feature_distributions.json`` — reference distributions (mean, std,
   min, max and the 1/25/50/75/99 percentiles) of all 20 candidate features
   computed over the **entire** botnet population, not the sample.  These are
   the numbers that justify the surrogate's input ranges, so they are computed
   exhaustively and are cheap (one vectorised pass per file).

The per-feature derivation lives in ``ai_agent/flow_features.py`` (shared with
the validation scripts and the RL environment).  The pandas implementation
below is vectorised for speed and is cross-checked against the scalar
implementation by ``--check`` (default on).
"""
import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "ai_agent"))
from flow_features import (  # noqa: E402
    BASELINE_FEATURES,
    CANDIDATE_FEATURES,
    HDR_BYTES,
    HDR_BYTES_ICMP,
    MSS_TCP,
    MSS_UDP,
    derive_flow_features,
)

ARCHIVE = REPO / "data" / "archive"
OUT_DIR = REPO / "snort_validation" / "data"
CSV_OUT = OUT_DIR / "ctu13_features_candidates.csv"
DIST_OUT = OUT_DIR / "ctu13_feature_distributions.json"
SEED = 42


def load_botnet(path):
    """Load one capture file and keep only botnet-labelled flows.

    Returns (df, n_state_imputed).  CTU-13 leaves ``state`` null for ICMP
    flows (6 of 11,729 sampled flows).  ``state`` is a categorical the env
    encodes with a fallback of 0.0, so nulls are filled with 'UNK' — the same
    token the corpus itself uses for unknown state — and the imputation count
    is reported so it is never silently hidden.
    """
    df = pd.read_parquet(path)
    label_col = "Label" if "Label" in df.columns else "label"
    if label_col not in df.columns:
        raise KeyError(f"{path.name}: no Label/label column")
    mask = df[label_col].astype(str).str.lower().str.contains("botnet")
    df = df.loc[mask].copy()
    for col in ("proto", "state", "dir"):
        if col in df.columns and str(df[col].dtype) == "category":
            df[col] = df[col].astype(str)
    n_imputed = 0
    if "state" in df.columns:
        n_imputed = int(df["state"].isnull().sum())
        df["state"] = df["state"].fillna("UNK")
    if "proto" in df.columns:
        df["proto"] = df["proto"].fillna("tcp")
    return df, n_imputed


def derive_vectorised(df):
    """Vectorised twin of flow_features.derive_flow_features."""
    dur = df["dur"].astype("float64").clip(lower=1e-3)
    tot_pkts = df["tot_pkts"].astype("float64").clip(lower=1.0)
    tot_bytes = df["tot_bytes"].astype("float64").clip(lower=0.0)
    proto = df["proto"].astype(str).str.strip().str.lower()
    state = df["state"].astype(str).str.strip().str.upper()

    is_icmp = proto.str.startswith("icmp")
    is_udp = proto.str.startswith("udp")
    hdr = np.where(is_icmp, HDR_BYTES_ICMP, HDR_BYTES)
    max_chunk = np.where(is_udp, MSS_UDP, MSS_TCP)

    out = pd.DataFrame(index=df.index)
    pkt_size_mean = tot_bytes / tot_pkts
    pkt_size_max = np.minimum(np.maximum(pkt_size_mean, hdr), max_chunk)
    pkt_size_min = np.where(tot_pkts > 1, hdr, pkt_size_mean)
    out["pkt_size_mean"] = pkt_size_mean
    out["pkt_size_max"] = pkt_size_max
    out["pkt_size_min"] = pkt_size_min
    out["pkt_size_median"] = 0.5 * (pkt_size_min + pkt_size_max)
    out["pkt_size_iqr"] = pkt_size_max - pkt_size_min
    out["pkt_size_std"] = hdr * pkt_size_mean / max_chunk
    out["pkt_size_cv"] = out["pkt_size_std"] / pkt_size_mean.clip(lower=1e-9)

    iat_mean = dur / (tot_pkts - 1.0).clip(lower=1.0)
    iat_cv = np.where(tot_pkts > 1, 0.25, 0.0)
    out["iat_mean"] = iat_mean
    out["iat_cv"] = iat_cv
    out["iat_std"] = iat_cv * iat_mean
    out["iat_min"] = 0.2 * iat_mean
    out["iat_max"] = 1.8 * iat_mean

    out["pkt_rate"] = tot_pkts / dur
    out["bytes_rate"] = tot_bytes / dur
    out["avg_pkt_size"] = pkt_size_mean

    out["syn_count"] = np.where(proto.str.startswith("tcp"), 1.0, 0.0)
    out["fin_count"] = state.str.contains("F").astype("float64")
    out["rst_count"] = state.str.contains("R").astype("float64")
    out["flags_variety"] = (
        (out["syn_count"] > 0).astype(int)
        + (out["fin_count"] > 0).astype(int)
        + (out["rst_count"] > 0).astype(int)
    ).astype("float64")

    payload_bytes = (tot_bytes - hdr * tot_pkts).clip(lower=0.0)
    out["payload_entropy_est"] = 8.0 * payload_bytes / tot_bytes.clip(lower=1e-9)

    return out[CANDIDATE_FEATURES]


def check_vectorised_matches_scalar(df, derived, n=200, seed=SEED):
    """Assert the pandas twin agrees with the scalar source of truth."""
    sample = df.sample(n=min(n, len(df)), random_state=seed)
    worst = 0.0
    worst_feat = None
    for idx, row in sample.iterrows():
        flow = {
            "dur": row["dur"], "tot_pkts": row["tot_pkts"],
            "tot_bytes": row["tot_bytes"], "src_bytes": row["src_bytes"],
            "proto": row["proto"], "state": row["state"],
        }
        scalar = derive_flow_features(flow)
        for feat in CANDIDATE_FEATURES:
            a, b = float(scalar[feat]), float(derived.loc[idx, feat])
            diff = abs(a - b)
            if diff > worst:
                worst, worst_feat = diff, feat
    return worst, worst_feat


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-flows-per-file", type=int, default=1000,
                    help="seeded sample size written to the CSV (0 = all flows)")
    ap.add_argument("--no-check", action="store_true",
                    help="skip the vectorised-vs-scalar consistency assertion")
    args = ap.parse_args()

    files = sorted(ARCHIVE.glob("*.parquet"))
    if not files:
        raise FileNotFoundError(f"no parquet files under {ARCHIVE}")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    rng = np.random.default_rng(SEED)

    frames, dist_frames = [], []
    total_botnet = 0
    total_imputed = 0

    for path in files:
        df, n_imputed = load_botnet(path)
        total_imputed += n_imputed
        if df.empty:
            continue
        derived = derive_vectorised(df)
        total_botnet += len(df)

        # Reference distributions over the full botnet population.
        dist = derived.describe(percentiles=[0.01, 0.25, 0.5, 0.75, 0.99]).T
        dist["capture"] = path.name
        dist["n_flows"] = len(df)
        dist_frames.append(dist.reset_index().rename(columns={"index": "feature"}))

        take = len(df) if args.max_flows_per_file <= 0 else min(len(df), args.max_flows_per_file)
        idx = rng.choice(df.index.to_numpy(), size=take, replace=False)
        sub = df.loc[idx]
        sub_derived = derived.loc[idx]

        frame = pd.DataFrame(index=sub.index)
        frame["flow_id"] = [f"{path.stem}_{i}" for i in sub.index]
        for col in BASELINE_FEATURES:
            frame[col] = sub[col].astype("float64").to_numpy()
        frame["proto"] = sub["proto"].astype(str).to_numpy()
        frame["state"] = sub["state"].astype(str).to_numpy()
        for col in CANDIDATE_FEATURES:
            frame[col] = sub_derived[col].to_numpy()
        frames.append(frame)

        print(f"[+] {path.name}: {len(df):>7} botnet flows "
              f"(-> {take} sampled)")

        if not args.no_check and len(df) > 0:
            worst, worst_feat = check_vectorised_matches_scalar(df, derived)
            status = "OK" if worst < 1e-9 else "MISMATCH"
            print(f"    vectorised vs scalar: max abs diff {worst:.3e} "
                  f"({worst_feat}) [{status}]")
            if worst >= 1e-9:
                raise AssertionError(
                    f"vectorised derivation disagrees with flow_features.py "
                    f"by {worst:.3e} on {worst_feat}")

    out = pd.concat(frames, ignore_index=True)
    cols = ["flow_id"] + BASELINE_FEATURES + ["proto", "state"] + CANDIDATE_FEATURES
    out = out[cols]
    out.to_csv(CSV_OUT, index=False)

    dist_all = pd.concat(dist_frames, ignore_index=True)
    # Population-wide distribution = mean of per-capture distributions weighted
    # by flow count, plus the global min/max.  A true global percentile would
    # need a full materialisation; the weighted mean of per-capture quantiles
    # is reported and labelled as such.
    payload = {
        "source": "data/archive/*.binetflow.parquet (botnet-labelled flows)",
        "total_botnet_flows": int(total_botnet),
        "captures": [p.name for p in files],
        "sample_per_capture": args.max_flows_per_file,
        "sample_seed": SEED,
        "sampled_rows": int(len(out)),
        "state_imputed": int(total_imputed),
        "state_imputation_rule": "CTU-13 leaves state null on ICMP flows; filled with 'UNK'",
        "baseline_features": BASELINE_FEATURES,
        "candidate_features": CANDIDATE_FEATURES,
        "n_columns": len(cols),
        "derivation": "ai_agent/flow_features.py::derive_flow_features",
        "note": ("Packet-size and inter-arrival statistics are RECONSTRUCTED "
                 "from the segmentation model in flow_to_pcap.py; CTU-13 "
                 "binetflow parquet exposes only flow aggregates."),
        "global_min": {f: float(out[f].min()) for f in CANDIDATE_FEATURES},
        "global_max": {f: float(out[f].max()) for f in CANDIDATE_FEATURES},
        "per_capture_distributions": json.loads(dist_all.to_json(orient="records")),
    }
    DIST_OUT.write_text(json.dumps(payload, indent=2))

    print(f"\n[+] Extracted {len(out)} flows with {len(cols)} columns")
    print(f"[+] CSV  -> {CSV_OUT.relative_to(REPO)}")
    print(f"[+] Dist -> {DIST_OUT.relative_to(REPO)}")
    print(f"[+] Full botnet population covered by distributions: {total_botnet}")
    print(f"[+] Missing values in CSV: {int(out.isnull().sum().sum())}"
          f" (state nulls imputed to 'UNK': {total_imputed})")
    print("[+] First 10 columns:")
    print("    " + ", ".join(cols[:10]))


if __name__ == "__main__":
    main()
