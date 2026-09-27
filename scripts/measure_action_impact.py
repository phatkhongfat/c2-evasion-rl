#!/usr/bin/env python3
"""Impact measurement: which action dims actually move the reward?

Phase 2, Task 2.2/2.3.  For a fixed pool of flows, sweep ONE action dimension
at a time across its full [-1, 1] range (holding the others at 0) and measure
how much the episode reward changes.  A dimension with zero reward spread is
"dead" -- the agent cannot learn anything from it.

Run against both PacketLevelEnv (flow-level replica) and EnhancedPacketLevelEnv
(enhanced replica that receives the packet list).
"""
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))

import numpy as np

from packet_level_env import PacketLevelEnv
from enhanced_packet_level_env import EnhancedPacketLevelEnv
from pool_loader import load_malicious_pool

DIM_NAMES = ["ttl_delta", "frag_flag", "padding_bytes", "overlap_offset"]
# Values in normalized [-1, 1] space; 0 is the "do nothing" reference.
SWEEP = [-1.0, -0.5, 0.0, 0.5, 1.0]


def sweep_dim(env_cls, pool, dim, n_flows=12):
    """Return list of episode rewards for each sweep value of `dim`."""
    out = {}
    for val in SWEEP:
        rewards = []
        for i in range(n_flows):
            env = env_cls(pool, max_packets_per_flow=50)
            env.reset(seed=1000 + i)
            action = np.zeros(4, dtype=np.float32)
            action[dim] = val
            total = 0.0
            done = False
            while not done:
                _obs, r, term, trunc, _info = env.step(action)
                total += r
                done = term or trunc
            rewards.append(total)
        out[val] = float(np.mean(rewards))
    return out


def main():
    print("[*] loading pool ...", flush=True)
    pool = load_malicious_pool(verbose=False)
    print(f"[+] pool size: {len(pool)}")

    for label, cls in [("PacketLevelEnv (flow-level replica)",
                        PacketLevelEnv),
                       ("EnhancedPacketLevelEnv (enhanced replica)",
                        EnhancedPacketLevelEnv)]:
        print("\n" + "=" * 78)
        print(f"REWARD SENSITIVITY -- {label}")
        print("=" * 78)
        print(f"{'dim':<16}" + "".join(f"{v:>10}" for v in SWEEP) + f"{'spread':>10}")
        for dim, name in enumerate(DIM_NAMES):
            res = sweep_dim(cls, pool, dim)
            spread = max(res.values()) - min(res.values())
            row = f"{name:<16}" + "".join(f"{res[v]:>10.2f}" for v in SWEEP)
            print(row + f"{spread:>10.2f}")
        print(f"\n  spread = max(mean reward) - min(mean reward) over the sweep.")
        print(f"  A dead dimension has spread 0.00.")


if __name__ == "__main__":
    main()
