"""TDD (P6): winner-signature stratification for corpus v4.

The v3fixed corpus has headroom=0 because every test flow alerts through SIDs
with the SAME content-match geometry, so all byte-safe fragmentations win or
lose together (constant split8 = oracle).  To let RL beat the best fixed
mechanism we need flows whose WINNER SETS diverge: flow A only split_slow
clears, flow B only prepend8 clears, etc.

signature_of   : cells -> {flow_id: {winning mechs}}
divergent_flows: keep flows whose signature differs from at least one other
                 flow's (a flow won by ALL candidate mechs carries no
                 per-flow information and is dropped)
stratified_split: split by signature class so train and test BOTH contain
                 every class (otherwise the RL agent never sees the
                 discrimination problem in training).
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "controls"))


def signature_of(cells) -> dict:
    """{flow_id: set of mechs with valid_evasion} from sweep cells."""
    sig = {}
    for c in cells:
        sig.setdefault(c["flow_id"], set())
        if c["valid_evasion"]:
            sig[c["flow_id"]].add(c["mech"])
    return sig


def divergent_flows(sig: dict) -> dict:
    """Flows that DISCRIMINATE between mechanisms.

    A flow is divergent when its winner set is neither empty (unevadable --
    nothing to learn) nor shared by every other flow (a universal winner --
    constant policy is already optimal).  Formally: keep flows whose signature
    is not identical to at least one other signature present in the pool.
    Returns {"flows": [...], "n_classes": int, "signatures": {fid: sorted}}.
    """
    nonempty = {f: s for f, s in sig.items() if s}
    uniq = {frozenset(s) for s in nonempty.values()}
    if len(uniq) < 2:
        return {"flows": [], "n_classes": 0, "signatures": {}}
    # A flow won by a SUPERSET of every other signature (in particular the
    # pool-wide union) discriminates nothing: whatever mechanism you pick,
    # that flow is cleared.  Drop those; keep flows whose winner set is a
    # proper, distinguishing subset.
    union = set().union(*uniq)
    keep = {f: s for f, s in nonempty.items() if s != union}
    return {"flows": sorted(keep),
            "n_classes": len({frozenset(s) for s in keep.values()}),
            "signatures": {f: sorted(s) for f, s in sorted(keep.items())}}


def stratified_split(sig: dict, test_ratio: float = 0.25, seed: int = 42):
    """Split flow_ids so EVERY signature class appears in BOTH train and test.

    Groups flows by exact signature, shuffles within group (seeded), and takes
    ceil(test_ratio * n) per group into test (min 1 when the group has >=2).
    Returns (train_ids, test_ids) as sorted lists.
    """
    import math
    import random

    rng = random.Random(seed)
    groups = {}
    for f, s in sig.items():
        groups.setdefault(frozenset(s), []).append(f)
    train, test = [], []
    for _sig, members in sorted(groups.items(), key=lambda kv: sorted(kv[0])):
        members = sorted(members)
        rng.shuffle(members)
        n_test = max(1, math.ceil(test_ratio * len(members))) if len(members) >= 2 else 0
        test.extend(members[:n_test])
        train.extend(members[n_test:])
    return sorted(train), sorted(test)
