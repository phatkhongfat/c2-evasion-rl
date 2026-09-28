"""Direction 2: Protocol-aware action masking.

Test that:
1. HTTP flows can use http_header_pad (action 12)
2. Neris flows cannot use http_header_pad (action 12)
3. All flows can use protocol-agnostic mechanisms (noop, split, prepend, etc.)
4. Environment respects the mask in reset() via an action_mask
"""

import sys
sys.path.insert(0, "ai_agent")
sys.path.insert(0, "snort_validation")

import numpy as np
from hidden_defender_env import HiddenDefenderEnv, ACTION_NAMES


def test_action_mask_http_flow():
    """HTTP flows should allow http_header_pad (action 12)."""
    env = HiddenDefenderEnv(split="train", real_snort=False)
    obs, info = env.reset()
    
    # Verify mask exists
    assert "action_mask" in info, f"Missing action_mask in reset() info. Keys: {list(info.keys())}"
    mask = info["action_mask"]
    
    # Check current flow framing
    current_flow = env._flows[env._idx]
    framing = current_flow.get("framing", "unknown")
    
    # If it's HTTP, action 12 (http_header_pad) should be allowed (mask[12] == True)
    if framing == "http":
        assert mask[12] == 1, f"HTTP flow should allow http_header_pad (action 12), but mask={mask}"
        print(f"✓ HTTP flow allows http_header_pad (action 12)")
    else:
        print(f"⊘ First flow is {framing}, skipping HTTP check")


def test_action_mask_neris_flow():
    """Neris flows should NOT allow http_header_pad (action 12)."""
    env = HiddenDefenderEnv(split="train", real_snort=False)
    env.reset()

    # Advance the flow index to a Neris flow.  Do NOT call reset() here -- reset()
    # sets _idx back to 0, which silently re-checks the first (HTTP) flow and
    # makes this test pass for the wrong reason.
    for i in range(min(10, len(env._flows))):
        env._idx = i
        if env._flows[i].get("framing", "unknown") == "neris":
            mask = env.action_masks()
            assert mask[12] == 0, f"Neris flow should NOT allow http_header_pad (action 12), but mask={mask}"
            assert mask[3] == 0 and mask[4] == 0 and mask[5] == 0, (
                f"Neris flow should block prepend4/8/12, but mask={mask}")
            assert mask[11] == 1, f"Neris flow must still allow noop, but mask={mask}"
            print(f"✓ Neris flow (idx={i}) blocks http_header_pad + prepend, allows noop")
            return

    raise AssertionError("No Neris flows found in first 10 — test cannot verify masking")


def test_action_masks_tracks_current_flow():
    """action_masks() must reflect the CURRENT flow, not a cached one."""
    env = HiddenDefenderEnv(split="train", real_snort=False)
    env.reset()

    http = next(i for i, f in enumerate(env._flows) if f.get("framing") == "http")
    neris = next(i for i, f in enumerate(env._flows) if f.get("framing") == "neris")

    env._idx = http
    m_http = env.action_masks()
    env._idx = neris
    m_neris = env.action_masks()

    assert m_http[12] == 1, "HTTP should allow http_header_pad"
    assert m_neris[12] == 0, "Neris should not allow http_header_pad"
    assert list(m_http) != list(m_neris), "mask must differ by protocol"
    print("✓ action_masks() is per-flow, not cached")


def test_action_mask_all_flows_allow_noop():
    """All flows should allow noop (action 11)."""
    env = HiddenDefenderEnv(split="train", real_snort=False)
    obs, info = env.reset()
    
    mask = info["action_mask"]
    assert mask[11] == 1, f"All flows should allow noop (action 11), but mask={mask}"
    print(f"✓ All flows allow noop (action 11)")


def test_action_mask_format():
    """Action mask should be a list/array of length 14."""
    env = HiddenDefenderEnv(split="train", real_snort=False)
    obs, info = env.reset()
    
    mask = info["action_mask"]
    assert isinstance(mask, (list, np.ndarray)), f"action_mask must be list/array, got {type(mask)}"
    assert len(mask) == 14, f"action_mask must have 14 elements, got {len(mask)}"
    assert all(m in [0, 1] for m in mask), f"action_mask must contain only 0/1, got {mask}"
    print(f"✓ action_mask format valid: {mask}")


if __name__ == "__main__":
    test_action_mask_format()
    test_action_mask_all_flows_allow_noop()
    test_action_mask_http_flow()
    test_action_mask_neris_flow()
    print("\n✓ All Direction 2 masking tests passed!")
