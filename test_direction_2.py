#!/usr/bin/env python3
"""Test Direction 2: protocol-aware action masking."""

import sys
from pathlib import Path

REPO = Path("/root/.hermes/c2-evasion-rl")
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))

import numpy as np
from hidden_defender_env import HiddenDefenderEnv, ACTION_NAMES

def test_direction_2():
    """Verify action masks block protocol-inapplicable actions."""
    env = HiddenDefenderEnv(split="train", real_snort=False, seed=42)
    
    print("=" * 70)
    print("TEST: Direction 2 — Protocol-Aware Action Masking")
    print("=" * 70)
    
    # Scan train set to find flows of different protocols
    flows = env._flows
    protocol_flows = {}
    
    for i, flow in enumerate(flows[:20]):  # Check first 20
        framing = flow.get("framing", "unknown")
        if framing not in protocol_flows:
            protocol_flows[framing] = i
    
    print(f"\nProtocols found in first 20 flows: {list(protocol_flows.keys())}")
    print()
    
    results = []
    for protocol, flow_idx in protocol_flows.items():
        env._idx = flow_idx
        mask = env._compute_action_mask()
        
        # Identify masked actions
        masked = [i for i, m in enumerate(mask) if m == 0]
        allowed = [i for i, m in enumerate(mask) if m == 1]
        
        results.append({
            "protocol": protocol,
            "flow_idx": flow_idx,
            "mask": mask,
            "allowed": [ACTION_NAMES[i] for i in allowed],
            "masked": [ACTION_NAMES[i] for i in masked],
        })
        
        print(f"Protocol: {protocol}")
        print(f"  Allowed ({len(allowed)}): {', '.join(results[-1]['allowed'][:8])}...")
        print(f"  Masked ({len(masked)}): {', '.join(results[-1]['masked']) if results[-1]['masked'] else '(none)'}")
        print()
    
    # Verify expectations
    print("-" * 70)
    print("Verification:")
    all_ok = True
    
    for r in results:
        proto = r["protocol"]
        masked_set = set(r["masked"])
        
        if proto == "http":
            # HTTP should NOT mask http_header_pad or length_wrapper
            if "http_header_pad" in masked_set:
                print(f"✗ {proto}: http_header_pad should be ALLOWED")
                all_ok = False
            else:
                print(f"✓ {proto}: http_header_pad ALLOWED")
        elif proto in ("neris", "irc", "length2"):
            # Non-HTTP should mask http_header_pad
            if "http_header_pad" not in masked_set:
                print(f"✗ {proto}: http_header_pad should be MASKED")
                all_ok = False
            else:
                print(f"✓ {proto}: http_header_pad MASKED")
        
        if proto == "neris":
            # Neris should mask prepend actions
            prepends = {"prepend4", "prepend8", "prepend12"}
            prepend_masked = prepends & masked_set
            if not prepend_masked:
                print(f"✗ {proto}: prepend actions should be MASKED")
                all_ok = False
            else:
                print(f"✓ {proto}: prepend actions MASKED: {prepend_masked}")
    
    print("-" * 70)
    if all_ok:
        print("\n✓ Direction 2 PASSED: Action masks work correctly by protocol")
    else:
        print("\n✗ Direction 2 FAILED: Mask verification failed")
        return False
    
    print("\nInterpretation:")
    print("  • HTTP flows can use http_header_pad (natural, no suspicion)")
    print("  • Binary protocols (Neris) cannot use prepend (breaks parser)")
    print("  • RL will only choose applicable actions per flow protocol")
    
    return True

if __name__ == "__main__":
    try:
        success = test_direction_2()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\n✗ ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
