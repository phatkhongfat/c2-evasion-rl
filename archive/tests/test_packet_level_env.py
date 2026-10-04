#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'ai_agent'))

import numpy as np
from packet_level_env import PacketLevelEnv


def test_env_reset():
    """Test environment reset."""
    # Create dummy pool
    pool = [
        {"tot_pkts": 10, "tot_bytes": 5000, "src_bytes": 3000, "dur": 2.0, "proto": "tcp", "state": "CON"}
    ]
    
    env = PacketLevelEnv(pool, max_packets_per_flow=20, seed=42)
    obs, info = env.reset(seed=42)
    
    assert obs.shape == (7,)
    assert "flow_id" in info
    assert "n_packets" in info
    print(f"[PASS] test_env_reset: obs={obs}, info={info}")


def test_env_step():
    """Test environment step."""
    pool = [
        {"tot_pkts": 5, "tot_bytes": 2000, "src_bytes": 1000, "dur": 1.0, "proto": "tcp", "state": "CON"}
    ]
    
    env = PacketLevelEnv(pool, max_packets_per_flow=10, seed=42)
    obs, info = env.reset(seed=42)
    
    # Take one step with neutral action
    action = np.array([0.0, 0.0, 0.0, 0.0], dtype=np.float32)
    obs, reward, terminated, truncated, info = env.step(action)
    
    assert obs.shape == (7,)
    assert isinstance(reward, float)
    assert isinstance(terminated, bool)
    assert "detected" in info
    print(f"[PASS] test_env_step: reward={reward}, terminated={terminated}, detected={info['detected']}")


def test_env_episode():
    """Test full episode."""
    pool = [
        {"tot_pkts": 3, "tot_bytes": 1000, "src_bytes": 500, "dur": 0.5, "proto": "tcp", "state": "CON"}
    ]
    
    env = PacketLevelEnv(pool, max_packets_per_flow=10, seed=42)
    obs, info = env.reset(seed=42)
    
    total_reward = 0.0
    step_count = 0
    terminated = False
    
    while not terminated and step_count < 20:
        action = env.action_space.sample()
        obs, reward, terminated, truncated, info = env.step(action)
        total_reward += reward
        step_count += 1
    
    print(f"[PASS] test_env_episode: steps={step_count}, total_reward={total_reward:.2f}, detected={info['detected']}")


if __name__ == "__main__":
    test_env_reset()
    test_env_step()
    test_env_episode()
    print("\n[✓] All PacketLevelEnv tests passed")
