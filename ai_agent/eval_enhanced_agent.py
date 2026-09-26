#!/usr/bin/env python3
"""
Evaluate enhanced packet-level agent on malicious validation set.
Compares baseline (random) vs trained agent.
"""
import sys
from pathlib import Path
import numpy as np
import json

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))

from enhanced_packet_level_env import EnhancedPacketLevelEnv
from pool_loader import load_malicious_pool
from stable_baselines3 import PPO

print("[*] Loading malicious pool...")
pool = load_malicious_pool()
print(f"    {len(pool)} flows\n")

# Sample validation set
np.random.seed(123)
val_size = min(100, len(pool))
val_pool = [pool[i] for i in np.random.choice(len(pool), val_size, replace=False)]
print(f"[*] Validation set: {val_size} flows\n")

# Load trained agent
model_path = REPO / "models" / "ppo_enhanced.zip"
print(f"[*] Loading trained agent: {model_path.name}")
model = PPO.load(str(model_path))
print("    ✓ Loaded\n")

# Eval function
def eval_policy(env, policy=None, n_episodes=None):
    """Run episodes, return evasion rate and corrupted packets per flow."""
    if n_episodes is None:
        n_episodes = len(env.malicious_pool)
    
    evaded = 0
    total_corrupted = 0
    results = []
    
    for ep in range(n_episodes):
        obs, info = env.reset()
        done = False
        ep_corrupted = 0
        
        while not done:
            if policy is None:
                # Random baseline
                action = env.action_space.sample()
            else:
                action, _ = policy.predict(obs, deterministic=True)
            
            obs, reward, terminated, truncated, info = env.step(action)
            done = terminated or truncated
            
            # Count non-zero actions as corruptions
            if np.any(np.abs(action) > 0.1):
                ep_corrupted += 1
        
        detected = info.get("detected", False)
        if not detected:
            evaded += 1
        
        total_corrupted += ep_corrupted
        results.append({"detected": detected, "corrupted": ep_corrupted})
    
    evasion_rate = evaded / n_episodes
    avg_corrupted = total_corrupted / n_episodes
    
    return evasion_rate, avg_corrupted, results

# Baseline
print("[*] Evaluating random baseline...")
env_baseline = EnhancedPacketLevelEnv(val_pool, max_packets_per_flow=50, seed=123)
ev_base, corr_base, res_base = eval_policy(env_baseline, policy=None, n_episodes=val_size)
print(f"    Evasion: {ev_base*100:.1f}%")
print(f"    Avg corrupted: {corr_base:.2f} packets/flow\n")

# Trained agent
print("[*] Evaluating trained agent...")
env_agent = EnhancedPacketLevelEnv(val_pool, max_packets_per_flow=50, seed=123)
ev_agent, corr_agent, res_agent = eval_policy(env_agent, policy=model, n_episodes=val_size)
print(f"    Evasion: {ev_agent*100:.1f}%")
print(f"    Avg corrupted: {corr_agent:.2f} packets/flow\n")

# Delta
delta_ev = (ev_agent - ev_base) * 100
delta_corr = corr_agent - corr_base
print(f"[+] Agent improvement: {delta_ev:+.1f}pp evasion, {delta_corr:+.2f} corrupted/flow")

# Save
report = {
    "validation_size": val_size,
    "baseline": {"evasion_rate": ev_base, "avg_corrupted": corr_base},
    "agent": {"evasion_rate": ev_agent, "avg_corrupted": corr_agent},
    "delta": {"evasion_pp": delta_ev, "corrupted": delta_corr},
    "model": "ppo_enhanced.zip",
    "env": "EnhancedPacketLevelEnv"
}

report_path = REPO / "snort_validation" / "reports" / "enhanced_agent_eval.json"
report_path.parent.mkdir(exist_ok=True)
with open(report_path, "w") as f:
    json.dump(report, f, indent=2)

print(f"\n✓ Report: {report_path}")
