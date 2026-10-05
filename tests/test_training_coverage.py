"""Training must visit the whole corpus, not the first n_steps flows forever."""
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "ai_agent"))

from hidden_defender_env import HiddenDefenderEnv  # noqa: E402


def test_reset_shuffles_the_training_order():
    env = HiddenDefenderEnv(split="train", seed=42)
    first = [f["flow_id"] for f in env._flows]
    env.reset()
    after = [f["flow_id"] for f in env._flows]
    assert after != first, "reset() must reshuffle the training corpus"
    assert sorted(after) == sorted(first), "shuffle must not drop or duplicate flows"


def test_shuffle_is_seed_reproducible():
    a = HiddenDefenderEnv(split="train", seed=7)
    a.reset()
    b = HiddenDefenderEnv(split="train", seed=7)
    b.reset()
    assert [f["flow_id"] for f in a._flows] == [f["flow_id"] for f in b._flows]


def test_test_split_is_never_shuffled():
    env = HiddenDefenderEnv(split="test", seed=42)
    first = [f["flow_id"] for f in env._flows]
    env.reset()
    assert [f["flow_id"] for f in env._flows] == first, "test order must stay frozen"
