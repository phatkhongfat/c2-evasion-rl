#!/usr/bin/env python3
"""Corpus constants and split logic for hidden-defender system.

Extracted from build_hidden_defender_corpus.py to allow tests to depend on
the split logic without importing the full builder.
"""
from __future__ import annotations

import random
from typing import Any

# Dataset configuration
CAPTURES = [
    ("stratosphere", "botnet-capture-20110811-neris"),
    ("stratosphere", "botnet-capture-20110810-neris"),
    ("stratosphere", "botnet-capture-20110819-bot"),
    ("cybersure-win", "capture-win13"),
]

N_TEST = 40
SEED = 42


def split_flows(flows: list[dict[str, Any]], seed: int = SEED) -> tuple[list[dict], list[dict]]:
    """Split flows deterministically into train/test sets.
    
    The split is fixed at seed=42 to allow reproducible hold-out evaluation.
    Test set is exactly N_TEST flows; all remaining go to train.
    """
    rng = random.Random(seed)
    rng.shuffle(flows)
    test = flows[:N_TEST]
    train = flows[N_TEST:]
    return train, test
