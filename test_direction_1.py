#!/usr/bin/env python3
"""Test Direction 1: action cost penalties reduce reward for expensive mechanisms."""

import sys
from pathlib import Path

REPO = Path("/root/.hermes/c2-evasion-rl")
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))

import numpy as np
from hidden_defender_env import HiddenDefenderEnv, ACTION_NAMES, ACTION_COSTS

def test_direction_1():
    """Verify action costs are subtracted from rewards correctly."""
    env = HiddenDefenderEnv(split="train", real_snort=False, seed=42)
    obs, info = env.reset()
    
    print("=" * 70)
    print("TEST: Direction 1 — Action Cost Penalties")
    print("=" * 70)
    
    # Test a few actions on the first flow
    test_actions = [0, 11, 12]  # split8 (0.5 cost), noop (0.0 cost), http_header_pad (0.05 cost)
    
    results = []
    for action_idx in test_actions:
        # Reset to same flow
        obs, info = env.reset()
        
        # Take action
        obs, reward, terminated, truncated, step_info = env.step(action_idx)
        
        action_name = ACTION_NAMES[action_idx]
        action_cost = ACTION_COSTS[action_idx]
        evaded = step_info["evaded"]
        sem_ok = step_info["semantics_ok"]
        alert = step_info["alert"]
        
        # Compute base reward
        if evaded and sem_ok:
            base_reward = 10.0
        elif evaded and not sem_ok:
            base_reward = -10.0
        else:
            base_reward = -1.0
        
        expected_reward = base_reward - action_cost
        
        results.append({
            "action": action_name,
            "cost": action_cost,
            "evaded": evaded,
            "sem_ok": sem_ok,
            "alert": alert,
            "base_reward": base_reward,
            "action_cost": action_cost,
            "expected_reward": expected_reward,
            "actual_reward": reward,
        })
    
    # Print results
    print("\nAction Cost Test Results:")
    print("-" * 70)
    print(f"{'Action':<18} {'Cost':<6} {'Base':<8} {'Expected':<10} {'Actual':<10} {'Match':<6}")
    print("-" * 70)
    
    all_match = True
    for r in results:
        match = abs(r["expected_reward"] - r["actual_reward"]) < 0.001
        match_str = "✓" if match else "✗"
        all_match = all_match and match
        
        print(
            f"{r['action']:<18} {r['cost']:<6.2f} {r['base_reward']:<8.1f} "
            f"{r['expected_reward']:<10.2f} {r['actual_reward']:<10.2f} {match_str:<6}"
        )
    
    print("-" * 70)
    print(f"\nCost Ranking (should increase):")
    for r in sorted(results, key=lambda x: x["cost"]):
        print(f"  {r['action']:<18}: {r['cost']:.2f} → reward {r['actual_reward']:+.2f}")
    
    if all_match:
        print("\n✓ Direction 1 PASSED: All rewards = base_reward - action_cost")
    else:
        print("\n✗ Direction 1 FAILED: Reward mismatch detected")
        return False
    
    print("\nInterpretation:")
    print("  • Cheap actions (noop, http_header_pad) lose less reward")
    print("  • Expensive actions (split8) lose more reward for same base outcome")
    print("  • RL should learn to prefer cheap mechanisms when both evade equally")
    
    return True

if __name__ == "__main__":
    try:
        success = test_direction_1()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\n✗ ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
