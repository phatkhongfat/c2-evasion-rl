#!/usr/bin/env python3
"""
Correctness test: batched Snort verdicts must equal per-flow ground truth,
on a MIX of known-positive and known-negative real flows.

Why a mixed test: an all-negative set passes trivially (batch says False,
truth says False) and proves nothing about whether alerts map back to the
right flow.  This test forces real positives in by selecting 5-tuples whose
label is already known from the labeled dataset.

Run:
    /tmp/jev-poc/venv/bin/python -m pytest snort_validation/test_snort_batch_service.py -v
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

import pandas as pd
import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "snort_validation"))

from snort_batch_service import (  # noqa: E402
    SNORT_CONF, SnortBatchService, _load_real_flows,
)

LABELED = REPO / "data" / "ctu13_snort_labeled.parquet"
CAPTURE_DIR = REPO / "data" / "stratosphere" / "CTU-13-Dataset"
CAPTURE = "botnet-capture-20110819-bot"
PCAP = CAPTURE_DIR / "12" / f"{CAPTURE}.pcap"

N_PER_CLASS = 6


def _extract_flows(pcap: Path, wanted: set) -> dict:
    """Pull packets for the given 5-tuples out of a capture."""
    from scapy.all import IP, PcapReader, TCP, UDP

    found: dict = {}
    with PcapReader(str(pcap)) as rd:
        for pkt in rd:
            if IP not in pkt:
                continue
            if TCP in pkt:
                proto, layer = "tcp", TCP
            elif UDP in pkt:
                proto, layer = "udp", UDP
            else:
                continue
            key = (pkt[IP].src, int(pkt[layer].sport), pkt[IP].dst,
                   int(pkt[layer].dport), proto)
            if key in wanted:
                found.setdefault(key, []).append(pkt)
                if len(found) == len(wanted):
                    break
    return found


def _per_flow_truth(flows: list) -> dict:
    """One Snort invocation per flow -- the expensive ground truth."""
    from scapy.all import wrpcap

    out = {}
    with tempfile.TemporaryDirectory(prefix="gt_") as td:
        td = Path(td)
        for i, pkts in enumerate(flows):
            single = td / f"f{i}.pcap"
            wrpcap(str(single), pkts)
            logdir = td / f"l{i}"
            logdir.mkdir(exist_ok=True)
            subprocess.run(["snort", "-c", str(SNORT_CONF), "-r", str(single),
                            "-l", str(logdir), "-q", "-A", "fast"],
                           capture_output=True, text=True, timeout=300)
            hits = 0
            for af in logdir.glob("alert*"):
                hits += len([ln for ln in open(af, errors="ignore")
                             if ln.strip() and not ln.startswith("#")])
            out[i] = hits > 0
    return out


@pytest.fixture(scope="module")
def mixed_flows():
    assert LABELED.exists(), f"missing {LABELED}"
    assert PCAP.exists(), f"missing {PCAP}"

    df = pd.read_parquet(LABELED)
    df = df[df["capture"] == CAPTURE]
    pos = df[df["snort_alert"] == 1]
    neg = df[df["snort_alert"] == 0]
    assert len(pos) >= N_PER_CLASS, "need known-positive flows"

    def keys(frame):
        return {(r.src, int(r.sport), r.dst, int(r.dport), r.proto)
                for r in frame.head(400).itertuples()}

    wanted = keys(pos) | keys(neg)
    got = _extract_flows(PCAP, wanted)

    # keep only keys we actually recovered, balanced by class
    pos_keys = [k for k in got if k in keys(pos)][:N_PER_CLASS]
    neg_keys = [k for k in got if k in keys(neg)][:N_PER_CLASS]
    selected = pos_keys + neg_keys
    assert len(pos_keys) >= 2, "test must contain real positives to be meaningful"
    return [(got[k], k) for k in selected], len(pos_keys)


def test_batch_matches_per_flow_ground_truth(mixed_flows):
    flows, n_pos = mixed_flows
    truth = _per_flow_truth([p for p, _k in flows])

    # a meaningful test MUST contain positives
    assert sum(truth.values()) > 0, (
        "no positive verdicts in the selected set -- the test would pass "
        "vacuously and prove nothing about alert->flow mapping")

    svc = SnortBatchService(batch_size=len(flows))
    got = svc.verdicts_chunked([(pkts, i) for i, (pkts, _k) in enumerate(flows)])

    for i in sorted(truth):
        assert got.get(i) == truth[i], (
            f"flow {i} mismatch: truth={truth[i]} batch={got.get(i)}")
    assert sum(got.values()) == sum(truth.values())
    print(f"\n[PASS] {len(truth)} flows, {sum(truth.values())} positives, "
          f"batch identical to ground truth")
    print(f"[*] {svc.stats()}")
