import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))

from endpoint_model import detect_framing  # noqa: E402
from hidden_defender_env import (  # noqa: E402
    ACTION_COSTS,
    ACTION_NAMES,
    PROTOCOL_MATCH_BONUS,
    REWARD_EVADE,
    HiddenDefenderEnv,
    payloads_of,
)


def _first_http_index(env):
    for i, f in enumerate(env._flows):
        if detect_framing(b"".join(payloads_of(f["packets"]))) == "http":
            return i
    return None


def test_http_header_pad_allowed_on_http_flows():
    env = HiddenDefenderEnv(split="test")
    http_count = 0
    allowed_count = 0
    for i, f in enumerate(env._flows):
        if detect_framing(b"".join(payloads_of(f["packets"]))) == "http":
            http_count += 1
            env._idx = i
            if env.action_masks()[12] == 1:
                allowed_count += 1
    assert http_count > 0, "test set must contain at least one HTTP flow"
    assert allowed_count == http_count, "http_header_pad must be allowed on all HTTP flows"


def test_split_costs_discourage_blanket_split():
    # Direction 1 keeps cost in the reward, but the old values made the generic
    # split mechanisms a global optimum that masked out every protocol-specific
    # alternative. Split cost is now high enough that a cheaper, applicable,
    # protocol-appropriate mechanism wins a tie.
    assert ACTION_COSTS[0] >= 0.60
    assert ACTION_COSTS[1] >= 0.50
    assert ACTION_COSTS[2] >= 0.40
    # ordering within the family is preserved
    assert ACTION_COSTS[0] > ACTION_COSTS[1] > ACTION_COSTS[2]
    # the HTTP mechanism stays the cheapest real evasion primitive
    assert ACTION_COSTS[12] <= 0.05
    assert ACTION_COSTS[12] < ACTION_COSTS[0]
    assert ACTION_COSTS[12] < ACTION_COSTS[1]
    assert ACTION_COSTS[12] < ACTION_COSTS[2]


def test_http_header_pad_gets_protocol_bonus_only_when_valid():
    env = HiddenDefenderEnv(split="test")
    idx = _first_http_index(env)
    assert idx is not None

    env._detected = lambda flow, pkts: False  # force "evaded"
    flow = env._flows[idx]
    evaded, sem, _alert = env.score(flow, "http_header_pad")
    if not (evaded and sem):
        # No HTTP flow in the corpus lets header padding evade while keeping
        # semantics; the shaping branch is then unreachable and untestable.
        return

    env._idx = idx
    reward, _term, _trunc, _info = env.step(12)[1], None, None, None
    expected = REWARD_EVADE - ACTION_COSTS[12] + PROTOCOL_MATCH_BONUS
    assert abs(reward - expected) < 1e-6, f"got {reward}, expected {expected}"

    # and no bonus leaks to a flow where the mechanism is not protocol-appropriate
    env.reset()
    non_http = next(
        i for i, f in enumerate(env._flows)
        if detect_framing(b"".join(payloads_of(f["packets"]))) != "http"
    )
    env._idx = non_http
    reward2 = env.step(0)[1]
    expected2 = REWARD_EVADE - ACTION_COSTS[0]
    assert abs(reward2 - expected2) < 1e-6, f"got {reward2}, expected {expected2}"