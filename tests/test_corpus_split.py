#!/usr/bin/env python3
"""Split logic of the hidden-defender corpus builder.

The builder used to reconcile the split with a `while len(train) > N_TRAIN`
loop that moved flows into `test`, immediately undone by a `while
len(test) > N_TEST` loop moving them back.  The two loops cancelled out, so
N_TRAIN never had any effect and the corpus was silently 1153/40 instead of the
160/40 the constant claimed.

These tests pin the behaviour that actually matters:
  * the test split is exactly N_TEST flows,
  * no flow is lost or duplicated,
  * both captures appear in both splits (so "which capture is this" cannot be
    memorised),
  * the split is deterministic for a given seed,
  * the whole detected pool is used -- no N_TRAIN truncation.
"""
from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "snort_validation"))

from build_hidden_defender_corpus import CAPTURES, N_TEST, SEED, split_flows


def _pool(n_neris: int = 698, n_bot: int = 455) -> list[dict]:
    """Stand-in detected flows with the same capture mix as the real corpus."""
    names = [c for _, c in CAPTURES]
    pool = [{"capture": names[0]} for _ in range(n_neris)]
    pool += [{"capture": names[1]} for _ in range(n_bot)]
    return pool


def test_test_split_is_exactly_n_test():
    train, test = split_flows(_pool(), seed=SEED)
    assert len(test) == N_TEST


def test_no_flow_lost_or_duplicated():
    pool = _pool()
    train, test = split_flows(pool, seed=SEED)
    assert len(train) + len(test) == len(pool)


def test_both_captures_in_both_splits():
    train, test = split_flows(_pool(), seed=SEED)
    for split, name in ((train, "train"), (test, "test")):
        caps = {f["capture"] for f in split}
        assert len(caps) == 2, f"{name} is missing a capture: {caps}"


def test_split_is_deterministic_for_a_seed():
    a_train, a_test = split_flows(_pool(), seed=SEED)
    b_train, b_test = split_flows(_pool(), seed=SEED)
    assert [f["capture"] for f in a_train] == [f["capture"] for f in b_train]
    assert [f["capture"] for f in a_test] == [f["capture"] for f in b_test]


def test_whole_pool_is_used_not_truncated_to_n_train():
    """N_TRAIN was a dead constant; the builder must keep every detected flow."""
    pool = _pool()
    train, _test = split_flows(pool, seed=SEED)
    assert len(train) == len(pool) - N_TEST
    assert len(train) > 160, "train split was truncated -- N_TRAIN is back"


def test_splits_are_disjoint():
    pool = _pool()
    for i, f in enumerate(pool):
        f["_i"] = i
    train, test = split_flows(pool, seed=SEED)
    tr_ids = {f["_i"] for f in train}
    te_ids = {f["_i"] for f in test}
    assert not (tr_ids & te_ids)
    assert tr_ids | te_ids == set(range(len(pool)))


def test_real_corpus_sizes_are_1153_40():
    """Guards the shipped corpus against a silent rebuild that shrinks it."""
    import json

    meta = json.loads(
        (REPO / "snort_validation/reports/hidden_defender_corpus.json").read_text()
    )
    assert meta["n_test"] == N_TEST
    assert meta["n_train"] > 160
    assert meta["obs_dim"] == 8
    assert Counter(meta["train_captures"]) is not None
    assert len(meta["train_captures"]) == 2