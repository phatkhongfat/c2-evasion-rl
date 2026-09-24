#!/usr/bin/env python3
"""Memory-lean loader for the CTU-13 botnet flow pool.

The original loader concatenates all 13 parquet files (10.6M rows, ~2.3 GB) and
only then filters to botnet rows.  In a 7 GB container that leaves the training
process too little headroom and PPO gets OOM-killed mid-run (observed: killed
at iteration 1, `anon-rss 4.05 GB`).

This module reads only the 7 needed columns per file and filters per-file, so
peak RSS stays ~1.2 GB and the resulting pool is identical in content.  It is
the single definition of the pool; training and evaluation both import it so
they cannot drift apart.
"""
import glob
import os
from typing import Dict, List

import pandas as pd

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ARCHIVE_DIR = os.path.join(REPO, "data", "archive")

REQUIRED = ["dur", "tot_pkts", "tot_bytes", "src_bytes", "proto", "state"]
# Source columns are lowercase in CTU-13, but the original loader also accepted
# the CamelCase variants; keep both so the rename stays a safe no-op.
RENAME = {
    "Dur": "dur", "TotPkts": "tot_pkts", "TotBytes": "tot_bytes",
    "SrcBytes": "src_bytes", "Proto": "proto", "State": "state",
}
READ_COLS = ["dur", "Dur", "proto", "Proto", "state", "State",
             "tot_pkts", "TotPkts", "tot_bytes", "TotBytes",
             "src_bytes", "SrcBytes", "label", "Label"]


def load_malicious_pool(archive_dir: str = ARCHIVE_DIR,
                        verbose: bool = True) -> List[Dict]:
    """Return the botnet flow pool as a list of compact dicts.

    File order is deliberately ``glob.glob`` order, NOT sorted order.  The
    seeded evaluation indexes into this pool (``env.reset(seed=42+i)``), so the
    order decides which flows the 80 episodes use.  The original loader used
    glob order; sorting the files silently reassigned the episodes and made
    every new measurement incomparable to the committed reports (measured: the
    blind agent moved 78/80 -> 76/80 from ordering alone).
    """
    files = glob.glob(os.path.join(archive_dir, "*.parquet"))
    if not files:
        raise FileNotFoundError(f"No .parquet files found in {archive_dir}")

    frames = []
    for path in files:
        available = pd.read_parquet(path).columns.tolist()
        keep = [c for c in READ_COLS if c in available]
        if not any(c in keep for c in ("label", "Label")):
            raise KeyError(f"no label column in {path}")
        if not any(c in keep for c in REQUIRED + list(RENAME)):
            raise KeyError(f"no flow feature columns in {path}")

        chunk = pd.read_parquet(path, columns=keep)
        label_col = "Label" if "Label" in chunk.columns else "label"
        chunk = chunk[
            chunk[label_col].astype(str).str.lower().str.contains("botnet")
        ].copy()
        chunk = chunk.rename(columns=RENAME)
        chunk = chunk[[c for c in REQUIRED if c in chunk.columns]]
        chunk = chunk.dropna(subset=REQUIRED)
        frames.append(chunk)
        del chunk

    df = pd.concat(frames, ignore_index=True)
    del frames
    # Compact to the 6 features with native types so the pool does not carry
    # pandas/numpy scalar objects (which cost ~10x more per record).
    pool = [
        {"dur": float(r.dur), "tot_pkts": float(r.tot_pkts),
         "tot_bytes": float(r.tot_bytes), "src_bytes": float(r.src_bytes),
         "proto": str(r.proto), "state": str(r.state)}
        for r in df.itertuples(index=False)
    ]
    del df
    if verbose:
        print(f"[+] Loaded {len(pool)} malicious samples.")
    return pool
