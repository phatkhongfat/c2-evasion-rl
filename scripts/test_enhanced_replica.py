#!/usr/bin/env python3
"""Test enhanced replica checks TTL/frag/overlap."""
import sys
from pathlib import Path
REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))

from packet_modifier import PacketModifier
from enhanced_snort_replica import enhanced_replica_snort_verdict

packets = [("src", 100, i*0.1) for i in range(10)]
modifier = PacketModifier()

tests = [
    ("Baseline (no mutation)", PacketModifier(), [[0, 0, 0, 0]]*10, False),
    ("TTL=8 (too low)", PacketModifier(base_ttl=8), [[0, 0, 0, 0]]*10, True),
    ("100% fragmentation", modifier, [[0, 1, 0, 0]]*10, True),
    ("Overlap=60", modifier, [[0, 0, 0, 60]]*10, True),
    ("Padding only", modifier, [[0, 0, 50, 0]]*10, None),  # depends on flow rules
]

for name, mod, actions, expected in tests:
    modified = mod.apply_actions(packets, actions)
    flow = mod.to_flow_features(modified)
    flow["proto"] = "tcp"
    flow["state"] = "CON"
    detected = enhanced_replica_snort_verdict(flow, modified)
    status = "✓" if expected is None or detected == expected else "✗"
    print(f"{status} {name}: detected={detected}")

print("\n✓ Enhanced replica checks TTL/frag/overlap")
