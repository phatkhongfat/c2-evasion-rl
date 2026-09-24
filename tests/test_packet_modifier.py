#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'ai_agent'))

import numpy as np
from packet_modifier import PacketModifier


def test_apply_actions_basic():
    """Test basic action application."""
    modifier = PacketModifier(base_ttl=64)
    
    # Input: 2 packets
    packets = [
        ("src", 100, 0.0),
        ("dst", 200, 0.5)
    ]
    
    # Actions: [ttl_delta, frag_flag, padding_bytes, overlap_offset]
    actions = [
        np.array([5.0, 1.0, 50.0, 0.0]),  # +5 TTL, fragment, +50 padding
        np.array([-3.0, 0.0, 10.0, 20.0])  # -3 TTL, no frag, +10 padding, +20 overlap
    ]
    
    modified = modifier.apply_actions(packets, actions)
    
    assert len(modified) == 2
    assert modified[0]["ttl"] == 69  # 64 + 5
    assert modified[0]["dsize"] == 150  # 100 + 50
    assert modified[0]["fragmented"] is True
    assert modified[1]["ttl"] == 61  # 64 - 3
    assert modified[1]["dsize"] == 210  # 200 + 10
    assert modified[1]["overlap_offset"] == 20
    print("[PASS] test_apply_actions_basic")


def test_to_flow_features():
    """Test conversion back to flow features."""
    modifier = PacketModifier()
    
    modified_packets = [
        {"direction": "src", "dsize": 150, "time": 0.0, "ttl": 64, "fragmented": False, "overlap_offset": 0},
        {"direction": "dst", "dsize": 200, "time": 0.5, "ttl": 64, "fragmented": False, "overlap_offset": 0},
        {"direction": "src", "dsize": 100, "time": 1.0, "ttl": 64, "fragmented": False, "overlap_offset": 0}
    ]
    
    flow = modifier.to_flow_features(modified_packets)
    
    assert flow["tot_pkts"] == 3
    assert flow["tot_bytes"] == 450  # 150 + 200 + 100
    assert flow["src_bytes"] == 250  # 150 + 100
    assert flow["dur"] == 1.0  # 1.0 - 0.0
    print("[PASS] test_to_flow_features")


if __name__ == "__main__":
    test_apply_actions_basic()
    test_to_flow_features()
    print("\n[✓] All PacketModifier tests passed")
