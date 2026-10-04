#!/usr/bin/env python3
"""Build the hidden-defender corpus: 80 Snort-detected flows, cached to disk.

Flow selection is IDENTICAL to the measured mechanism matrix: load the two
captures that have usable alerts, keep only flows the rules replica detects at
baseline (80 of 80 pooled flows are positives), and record 8 black-box features
per flow.

The features are deliberately defender-blind: protocol, packet counts, byte
counts, payload length statistics.  No rule SIDs, no `depth:`, no pattern
bytes, nothing an attacker could read off the ruleset.  That is what makes the
"hidden defender" formulation honest -- the agent cannot cheat by reading the
rule that it is trying to evade.

Scoring uses RealRulesReplica (0.33 ms/flow, measured 8/8 agreement with the
real Snort binary on both baseline and mutated flows).  The real binary is used
in `ai_agent/verify_against_real_snort.py` to confirm the final numbers.
"""
from __future__ import annotations

import json
import pickle
import sys
from pathlib import Path

import numpy as np

REPO = Path("/root/.hermes/c2-evasion-rl")
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))

from real_packet_env import RealPacketEnv  # noqa: E402
from real_rules_replica import RealRulesReplica  # noqa: E402
from scapy.all import IP, Raw, TCP, UDP  # noqa: E402
from endpoint_model import detect_framing  # noqa: E402

CAPTURES = [("stratosphere", "botnet-capture-20110811-neris"),
            ("ctu13", "botnet-capture-20110819-bot")]

N_TEST = 40
SEED = 42

CORPUS_PKL = REPO / "snort_validation/reports/hidden_defender_corpus.pkl"
CORPUS_JSON = REPO / "snort_validation/reports/hidden_defender_corpus.json"

OBS_DIM = 8
OBS_NAMES = ["is_udp", "n_pkts_norm", "tot_bytes_norm", "n_payload_pkts_norm",
             "payload_mean_norm", "payload_std_norm",
             "payload_max_norm", "payload_min_norm"]


def payloads_of(pkts):
    return [bytes(p[Raw].load) for p in pkts if Raw in p]


def flow_features(pkts) -> list:
    """8 black-box features.  No rule-derived quantity appears here."""
    pays = payloads_of(pkts)
    lens = [len(p) for p in pays]
    n_pkts = len(pkts)
    tot_bytes = sum(len(bytes(p)) for p in pkts)
    proto = 1.0 if any(UDP in p for p in pkts) else 0.0
    mean = float(np.mean(lens)) if lens else 0.0
    std = float(np.std(lens)) if lens else 0.0
    return [
        proto,
        min(n_pkts, 64) / 64.0,
        min(tot_bytes, 20000) / 20000.0,
        min(len(pays), 16) / 16.0,
        min(mean, 2000) / 2000.0,
        min(std, 2000) / 2000.0,
        min(max(lens) if lens else 0, 2000) / 2000.0,
        min(min(lens) if lens else 0, 2000) / 2000.0,
    ]


def build():
    flows = []
    for dataset, capture in CAPTURES:
        env = RealPacketEnv(n_flows=800, batch_size=1, capture=capture,
                            dataset=dataset)
        rep = RealRulesReplica.for_capture(capture, dataset)
        kept = 0
        for key, pkts in env.flows:
            if not rep.verdict(pkts):
                continue          # negatives teach the agent nothing useful
            fid = f"{capture}|{key[0]}:{key[1]}->{key[2]}:{key[3]}|{key[4]}"
            flows.append({
                "flow_id": fid,
                "capture": capture,
                "dataset": dataset,
                "key": key,
                "packets": pkts,
                "obs": flow_features(pkts),
                "framing": detect_framing(b"".join(payloads_of(pkts))),
                "replica": rep,       # kept for scoring, not for features
            })
            kept += 1
        print(f"[*] {capture}: kept {kept} detected flows")
    return flows


def split_flows(flows, seed: int = SEED):
    """Stratified split: keep both captures represented in train and test, so a
    method cannot pass by memorising "which capture is this".

    Test gets exactly ``N_TEST`` flows, drawn proportionally from each capture;
    train keeps every remaining detected flow.  There is deliberately no
    N_TRAIN cap -- a previous version reconciled towards N_TRAIN with two
    opposite `while` loops that cancelled out, so the constant was dead and the
    corpus was silently far larger than it claimed.
    """
    rng = np.random.default_rng(seed)
    by_cap = {}
    for f in flows:
        by_cap.setdefault(f["capture"], []).append(f)
    train, test = [], []
    for group in by_cap.values():
        idx = rng.permutation(len(group))
        n_test_cap = max(1, int(round(len(group) * (N_TEST / len(flows)))))
        for j, i in enumerate(idx):
            (test if j < n_test_cap else train).append(group[i])
    # Proportional rounding can miss N_TEST by a flow or two; trim/pad the
    # largest training group rather than shuffling test membership around.
    while len(test) > N_TEST:
        train.append(test.pop())
    while len(test) < N_TEST:
        biggest = max(by_cap.values(), key=len)
        pool = [f for f in train if f["capture"] == biggest[0]["capture"]]
        if not pool:
            break
        train.remove(pool[0])
        test.append(pool[0])
    rng.shuffle(train)
    rng.shuffle(test)
    return train, test


def main() -> int:
    CORPUS_PKL.parent.mkdir(parents=True, exist_ok=True)
    flows = build()
    if len(flows) < N_TEST:
        print(f"[!] only {len(flows)} flows, need at least {N_TEST}")
        return 1

    train, test = split_flows(flows, seed=SEED)

    # pickle holds scapy packets + replica objects; JSON holds only features so
    # the corpus is inspectable without unpickling anything.
    with open(CORPUS_PKL, "wb") as fh:
        pickle.dump({"train": train, "test": test}, fh)
    meta = {
        "n_train": len(train), "n_test": len(test),
        "obs_dim": OBS_DIM, "obs_names": OBS_NAMES,
        "train_captures": sorted({f["capture"] for f in train}),
        "test_captures": sorted({f["capture"] for f in test}),
        "flow_ids": {"train": [f["flow_id"] for f in train],
                     "test": [f["flow_id"] for f in test]},
    }
    CORPUS_JSON.write_text(json.dumps(meta, indent=2))
    print(f"[*] train={len(train)} test={len(test)}")
    print(f"[*] train captures: {meta['train_captures']}")
    print(f"[*] test  captures: {meta['test_captures']}")
    print(f"[+] {CORPUS_PKL}")
    print(f"[+] {CORPUS_JSON}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
