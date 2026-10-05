import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))

from endpoint_model import detect_framing  # noqa: E402
from hidden_defender_env import (  # noqa: E402
    ACTION_COSTS,
    ACTION_NAMES,
    PROTOCOL_APPROPRIATE,
    PROTOCOL_MATCH_BONUS,
    REWARD_ALERTED,
    REWARD_BREAK_SEMANTICS,
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


def test_protocol_bonus_applies_to_the_whole_appropriate_family():
    """The bonus must reward every protocol-appropriate mechanism, not one action."""
    assert "http_header_pad" in PROTOCOL_APPROPRIATE["http"]
    assert "length_wrapper" in PROTOCOL_APPROPRIATE["http"]
    assert "split8" in PROTOCOL_APPROPRIATE["neris"]
    assert "split16" in PROTOCOL_APPROPRIATE["neris"]
    assert "split24" in PROTOCOL_APPROPRIATE["neris"]
    # a mechanism that is wrong for the framing gets nothing
    assert "http_header_pad" not in PROTOCOL_APPROPRIATE.get("neris", ())


def test_bonus_is_zero_when_evasion_or_semantics_fails():
    assert PROTOCOL_MATCH_BONUS > 0
    assert PROTOCOL_MATCH_BONUS < abs(REWARD_EVADE) / 10, "bonus must stay a nudge, not a driver"

    # The bonus is gated on a REAL valid evasion: an appropriate mechanism that
    # still alerts, or that breaks the command, must get no bonus.
    env = HiddenDefenderEnv(split="test")
    neris = next(i for i, f in enumerate(env._flows) if f.get("framing") == "neris")
    split8 = ACTION_NAMES.index("split8")
    corrupt8 = ACTION_NAMES.index("corrupt8")

    env._detected = lambda flow, pkts: True          # defender still fires
    env._idx = neris
    alerted = env.step(split8)[1]
    assert abs(alerted - (REWARD_ALERTED - ACTION_COSTS[split8])) < 1e-6, \
        "no bonus may be granted when the flow is still detected"

    env._detected = lambda flow, pkts: False         # alert dodged, command broken
    env._idx = neris
    broken = env.step(corrupt8)[1]
    assert abs(broken - (REWARD_BREAK_SEMANTICS - ACTION_COSTS[corrupt8])) < 1e-6, \
        "no bonus may be granted when semantics are broken"
