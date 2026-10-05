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


def test_epoch_rate_never_exceeds_one_hundred_percent():
    """The reported epoch rate must be a rate, not a cumulative count.

    With a reshuffled corpus, distinct flows solved accumulate across epochs
    and dividing that total by n_flows produced an impossible 105.9% (and
    tripped the TARGET early-stop at epoch 6).  The rate is now per-epoch.
    """
    from train_hidden_defender_ppo import QueryCounter

    c = QueryCounter()
    n_flows = 256

    # epoch 1: 200 of 256 flows solved
    c.new_epoch()
    for i in range(n_flows):
        c.queries += 1
        c.epoch_queries += 1
        if i < 200:
            c.solved.add(f"f{i}")
            c.epoch_solved.add(f"f{i}")
    rate = 100.0 * len(c.epoch_solved) / n_flows
    assert rate <= 100.0, "a per-epoch rate can never exceed 100%"

    # epoch 2: a disjoint 200 flows -- cumulative would be 400/256 = 156%
    c.new_epoch()
    for i in range(200, 400):
        c.queries += 1
        c.epoch_queries += 1
        c.solved.add(f"f{i}")
        c.epoch_solved.add(f"f{i}")
    rate2 = 100.0 * len(c.epoch_solved) / n_flows
    assert rate2 <= 100.0, "cumulative counting leaked into the epoch rate"
    assert len(c.solved) == 400, "cumulative set must still accumulate"
    assert c.epoch_queries == 200, "per-epoch query count must reset"
    assert c.queries == 456, "total queries must not reset"
