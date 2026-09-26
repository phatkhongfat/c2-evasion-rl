#!/usr/bin/env python3
"""
Train PPO agent with ENHANCED packet-level environment.
TTL/frag/overlap now reach the reward via enhanced_replica_snort_verdict.
"""
import sys
import os
from pathlib import Path
import time
import argparse

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "ai_agent"))

from enhanced_packet_level_env import EnhancedPacketLevelEnv
from pool_loader import load_malicious_pool
from stable_baselines3 import PPO
from stable_baselines3.common.callbacks import CheckpointCallback
import json

parser = argparse.ArgumentParser()
parser.add_argument("--timesteps", type=int, default=10000,
                    help="total PPO timesteps (default 10K)")
parser.add_argument("--checkpoint-freq", type=int, default=2000)
parser.add_argument("--tag", default="enhanced")
args = parser.parse_args()

total_timesteps = args.timesteps
tag = args.tag

print("[*] Training PPO with EnhancedPacketLevelEnv")
print("    TTL/frag/overlap now reach reward via enhanced_replica_snort_verdict\n")

# Load pool
print("[*] Loading malicious pool...")
sys.stdout.flush()
pool = load_malicious_pool()
print(f"    Loaded {len(pool)} flows\n")

# Create ENHANCED env
print("[*] Creating EnhancedPacketLevelEnv...")
env = EnhancedPacketLevelEnv(pool, max_packets_per_flow=50, seed=42)
print(f"    Action: {env.action_space}")
print(f"    Obs: {env.observation_space}\n")

print(f"[*] Training {total_timesteps} steps (seed=42)\n")
sys.stdout.flush()

start_time = time.time()

model = PPO(
    "MlpPolicy",
    env,
    verbose=1,
    learning_rate=3e-4,
    n_steps=2048,
    batch_size=64,
    n_epochs=10,
    gamma=0.99,
    gae_lambda=0.95,
    clip_range=0.2,
    ent_coef=0.01,
    seed=42,
    tensorboard_log=None
)

checkpoint_callback = CheckpointCallback(
    save_freq=args.checkpoint_freq,
    save_path=str(REPO / "models" / f"checkpoints_{tag}"),
    name_prefix=f"ppo_{tag}"
)

model.learn(total_timesteps=total_timesteps, callback=checkpoint_callback)

elapsed = time.time() - start_time

# Save
model_path = REPO / "models" / f"ppo_{tag}.zip"
model.save(str(model_path))
print(f"\n[+] Model saved: {model_path}")

# Metadata
meta = {
    "env": "EnhancedPacketLevelEnv",
    "reward": "enhanced_replica_snort_verdict(flow, packets)",
    "timesteps": total_timesteps,
    "elapsed_s": round(elapsed, 2),
    "fps": round(total_timesteps / elapsed, 1),
    "pool_size": len(pool),
    "seed": 42
}
meta_path = REPO / "logs" / f"training_{tag}.json"
meta_path.parent.mkdir(exist_ok=True)
with open(meta_path, "w") as f:
    json.dump(meta, f, indent=2)
print(f"[+] Metadata: {meta_path}")
print(f"\n✓ Training complete: {elapsed:.1f}s ({meta['fps']} fps)")
