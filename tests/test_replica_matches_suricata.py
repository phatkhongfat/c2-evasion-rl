"""The replica must agree with the committed Suricata verdicts on the 20 frozen flows.

This is the P16c regression gate. Before the reassembly fix it scores 76/100;
after it must be 100/100. If a future change breaks the surrogate's agreement,
this test fails -- the surrogate is what trains the policy, and a surrogate that
disagrees with the real engine teaches the policy the wrong thing.
"""
from __future__ import annotations

import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "ai_agent"), str(ROOT / "snort_validation")]
sys.path.insert(0, str(ROOT / "controls"))

from c2_semantics import client_ip_of, ensure_chain  # noqa: E402
from hidden_defender_env import apply_mech, load_corpus  # noqa: E402
from snort_validation.real_rules_replica import RealRulesReplica  # noqa: E402

from suricata_groundtruth import assert_complete, frozen_flow_ids  # noqa: E402

MECHS = ("noop", "split8", "split24", "http_header_case", "query_param_prepend")
SIDS = (2012627, 2012533)  # FakeAV + Virut, the SIDs the frozen sample was built on


@pytest.fixture(scope="module")
def replica():
    return RealRulesReplica.for_sids(set(SIDS))


@pytest.fixture(scope="module")
def pool():
    """flow_id -> flow. The 16 FakeAV live in the ORIGINAL corpus; the 4 Virut
    only exist in the P13 extended corpus. v3/v3fixed do NOT contain them."""
    out = {}
    for name in ("hidden_defender_corpus.pkl", "corpus_p13_extended.pkl"):
        for split in ("test", "train"):
            for f in load_corpus(split=split,
                                corpus=str(ROOT / "snort_validation/reports" / name)):
                out[f["flow_id"]] = f
    return out


@pytest.fixture(scope="module")
def cases(pool):
    """[(mech, flow_id, packets, ground_truth_evaded)] for every cell."""
    gt = assert_complete(MECHS)
    fids = frozen_flow_ids()
    missing = [f for f in fids if f not in pool]
    assert not missing, f"{len(missing)} frozen flows absent from corpora: {missing[:3]}"
    out = []
    for mech in MECHS:
        for fid in fids:
            cip = client_ip_of(fid)
            pkts = [ensure_chain(p) for p in apply_mech(
                list(pool[fid]["packets"]), mech, cip, ownership="client")]
            out.append((mech, fid, pkts, gt[(mech, fid)]["evaded"]))
    return out


def test_replica_agrees_with_suricata_on_every_cell(replica, cases):
    """verdict() is True = DETECTED, so evaded = NOT verdict()."""
    wrong = []
    for mech, fid, pkts, gt_evaded in cases:
        evaded = not replica.verdict(pkts)  # legacy mode: no home_ip, as the env calls it
        if evaded != gt_evaded:
            wrong.append(
                f"{mech}/{fid[-28:]}: replica_evaded={evaded} suricata_evaded={gt_evaded}")
    assert not wrong, (
        f"{len(wrong)}/{len(cases)} cells disagree with real Suricata:\n  "
        + "\n  ".join(wrong[:8]))


def test_fragmentation_does_not_evade_under_the_replica(replica, cases):
    """G1b(i): an engine with stream reassembly defeats the split family.

    This is the specific behaviour the fix introduces. Asserted separately so a
    failure names the cause instead of just lowering an agreement number.
    """
    for mech in ("noop", "split8", "split24"):
        evaded = [fid for m, fid, pk, _ in cases
                  if m == mech and not replica.verdict(pk)]
        assert not evaded, (
            f"{mech} evades {len(evaded)} flows in the replica: {evaded[:3]}")


def test_non_fragmentation_mechanisms_keep_their_suricata_verdicts(replica, cases):
    """The fix must not disturb the mechanisms that were already correct."""
    gt = assert_complete(("http_header_case", "query_param_prepend"))
    for mech in ("http_header_case", "query_param_prepend"):
        got = {fid for m, fid, pk, _ in cases if m == mech and not replica.verdict(pk)}
        want = {f for f in frozen_flow_ids() if gt[(mech, f)]["evaded"]}
        assert got == want, f"{mech}: replica evades {len(got)}, Suricata {len(want)}"


def test_env_default_reassembles(pool):
    """The training env must score with stream reassembly on by default."""
    from hidden_defender_env import HiddenDefenderEnv
    env = HiddenDefenderEnv(split="test", seed=42, real_snort=False)
    assert env.reassemble is True, (
        "env default must match Suricata semantics -- a per-packet scorer teaches "
        "the policy that fragmentation works, which the real engine refutes")
    assert pool[frozen_flow_ids()[0]]["flow_id"] == frozen_flow_ids()[0]