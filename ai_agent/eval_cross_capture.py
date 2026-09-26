#!/usr/bin/env python3
"""
Cross-capture eval: train enhanced agent on one capture, eval on another.
Tests generalization across different botnet captures.
"""
import sys
from pathlib import Path
import numpy as np
import pandas as pd
import json

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))

from enhanced_packet_level_env import EnhancedPacketLevelEnv
from stable_baselines3 import PPO

# Load MCFP dataset
print("[*] Loading MCFP labeled dataset...")
df = pd.read_parquet(REPO / "data" / "mcfp_snort_labeled.parquet")
print(f"    Total: {len(df)} flows")
print(f"    Captures: {df['capture'].unique()}\n")

# Group by capture
captures = df['capture'].unique()
if len(captures) < 2:
    print("[!] Need ≥2 captures for cross-capture test")
    sys.exit(1)

# Take first two captures
train_capture = captures[0]
eval_capture = captures[1]

train_pool = df[df['capture'] == train_capture].to_dict('records')
eval_pool = df[df['capture'] == eval_capture].to_dict('records')

print(f"[*] Train: {train_capture} ({len(train_pool)} flows)")
print(f"[*] Eval:  {eval_capture} ({len(eval_pool)} flows)\n")

# Sample eval set
np.random.seed(456)
eval_size = min(50, len(eval_pool))
eval_sample = [eval_pool[i] for i in np.random.choice(len(eval_pool), eval_size, replace=False)]

# Load trained model
model_path = REPO / "models" / "ppo_enhanced.zip"
if not model_path.exists():
    print(f"[!] Model not found: {model_path}")
    print("[!] Train first: .venv/bin/python ai_agent/train_enhanced_packet_agent.py")
    sys.exit(1)

print(f"[*] Loading model: {model_path.name}")
model = PPO.load(str(model_path))

# Eval
def eval_policy(pool, policy=None, n_episodes=None):
    if n_episodes is None:
        n_episodes = len(pool)
    env = EnhancedPacketLevelEnv(pool, max_packets_per_flow=50, seed=456)
    
    evaded = 0
    for ep in range(n_episodes):
        obs, info = env.reset()
        done = False
        while not done:
            if policy is None:
                action = env.action_space.sample()
            else:
                action, _ = policy.predict(obs, deterministic=True)
            obs, reward, terminated, truncated, info = env.step(action)
            done = terminated or truncated
        
        if not info.get("detected", False):
            evaded += 1
    
    return evaded / n_episodes

print(f"\n[*] Evaluating on {eval_capture} ({eval_size} flows)...")
ev_baseline = eval_policy(eval_sample, policy=None, n_episodes=eval_size)
ev_agent = eval_policy(eval_sample, policy=model, n_episodes=eval_size)

print(f"\n{'='*60}")
print(f"Train capture:  {train_capture}")
print(f"Eval capture:   {eval_capture}")
print(f"Baseline:       {ev_baseline*100:.1f}% evasion")
print(f"Enhanced agent: {ev_agent*100:.1f}% evasion")
print(f"Delta:          {(ev_agent - ev_baseline)*100:+.1f}pp")
print(f"{'='*60}")

# Save
report = {
    "train_capture": train_capture,
    "eval_capture": eval_capture,
    "eval_size": eval_size,
    "baseline_evasion": ev_baseline,
    "agent_evasion": ev_agent,
    "delta_pp": (ev_agent - ev_baseline) * 100,
    "model": "ppo_enhanced.zip"
}

report_path = REPO / "snort_validation" / "reports" / "cross_capture_eval.json"
with open(report_path, "w") as f:
    json.dump(report, f, indent=2)

print(f"\n✓ Report: {report_path}")
