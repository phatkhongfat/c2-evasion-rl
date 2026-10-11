"""Regression: a mixed pcap suppresses snort alerts, corrupting verdicts.

Measured on eval chunk 0 (32 pairs in one pcap): only 4 alerts were emitted,
and 12 of the 32 verdicts read "not detected" batched while the very same
pairs alert when each is written to its own pcap.  The invariant that pins
this down is simple -- an unmutated flow must be detected, batched or not.
"""

import sys
from pathlib import Path

REPO = Path("/root/.hermes/c2-evasion-rl")
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))

from hidden_defender_env import apply_mech, load_corpus  # noqa: E402
from snort_batch_service import SnortBatchService  # noqa: E402

N = 8


def _noop_verdicts(batch_size):
    flows = load_corpus("test")[:N]
    svc = SnortBatchService(batch_size=batch_size)
    items = [(apply_mech(f["packets"], "noop"), k) for k, f in enumerate(flows)]
    return svc.verdicts(items), flows


def test_unmutated_flows_are_detected_when_batched():
    """If this fails, batching is corrupting verdicts again."""
    verdicts, flows = _noop_verdicts(batch_size=N)
    missed = [i for i in range(len(flows)) if not verdicts.get(i, False)]
    assert not missed, f"snort missed unmutated flows {missed} in a {N}-flow pcap"


def test_batching_agrees_with_isolation_at_n8():
    """Below the suppression threshold the two scoring modes must agree.

    The hazard only appears at 32 pairs per pcap (see module docstring), so
    this is a cheap tripwire against a *different* corruption: a scoring mode
    that drops flows or mis-attributes qids.
    """
    batched, flows = _noop_verdicts(batch_size=N)
    for i, f in enumerate(flows):
        svc = SnortBatchService(batch_size=1)
        alone = svc.verdicts([(apply_mech(f["packets"], "noop"), 0)])[0]
        assert alone, f"flow {i} not detected even in isolation"
        assert batched.get(i, False) == alone, (
            f"flow {i}: batched={batched.get(i)} isolated={alone}"
        )


def test_score_matrix_scores_isolated_by_default():
    """The fix is the default, so no caller can silently re-batch the matrix."""
    import inspect

    from eval_all_real_snort import score_matrix

    assert inspect.signature(score_matrix).parameters["batch_size"].default == 1
