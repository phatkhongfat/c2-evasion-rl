#!/usr/bin/env python3
"""
Train PPO agent with packet-level environment.
Queries real Snort replica directly (no surrogate mismatch).
"""
import sys
import os
from pathlib import Path
import time
import argparse

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "ai_agent"))

from packet_level_env import PacketLevelEnv
from pool_loader import load_malicious_pool
from stable_baselines3 import PPO
from stable_baselines3.common.callbacks import CheckpointCallback
import json

parser = argparse.ArgumentParser()
parser.add_argument("--timesteps", type=int, default=10000,
                    help="total PPO timesteps (plan default: 10000)")
parser.add_argument("--checkpoint-freq", type=int, default=1000,
                    help="checkpoint every N timesteps")
parser.add_argument("--tag", default="",
                    help="suffix for the output model / metadata filenames")
args = parser.parse_args()

total_timesteps = args.timesteps
tag = args.tag

print("[*] Training packet-level PPO agent with real Snort replica")
print(f"    Environment: PacketLevelEnv")
print(f"    Reward: replica_snort_verdict() (no surrogate)\n")

# Load pool
print("[*] Loading malicious data pool...")
sys.stdout.flush()
pool = load_malicious_pool()
print(f"    Loaded {len(pool)} flows\n")
sys.stdout.flush()

# Create env
print("[*] Creating packet-level environment...")
sys.stdout.flush()
env = PacketLevelEnv(pool, max_packets_per_flow=50, seed=42)
print(f"    Action space: {env.action_space}")
print(f"    Observation space: {env.observation_space}")
print(f"    Max packets per flow: 50\n")
sys.stdout.flush()

# Training config
print(f"[*] Training from scratch ({total_timesteps} steps, seed=42)\n")
sys.stdout.flush()

start_time = time.time()

model = PPO(
    "MlpPolicy",
    env,
    learning_rate=3e-4,
    n_steps=256,  # Smaller batch (faster feedback from Snort)
    batch_size=64,
    n_epochs=10,
    gamma=0.99,
    gae_lambda=0.95,
    clip_range=0.2,
    ent_coef=0.01,
    verbose=1,  # Show progress
    seed=42,
    device="auto"
)

# Checkpoint callback
checkpoint_callback = CheckpointCallback(
    save_freq=args.checkpoint_freq,
    save_path=str(REPO / "models" / "checkpoints_packet_level"),
    name_prefix="ppo_packet_level"
)

print("[*] Starting training...\n")
sys.stdout.flush()

model.learn(total_timesteps=total_timesteps, callback=checkpoint_callback, log_interval=10)

# Save trained model
output_path = REPO / "models" / f"ppo_packet_level_agent{tag}.zip"
model.save(output_path)
elapsed = time.time() - start_time

print(f"\n[+] Training complete in {elapsed:.1f}s ({elapsed/3600:.2f}h)")
print(f"[+] Model saved: {output_path.name}")

# Save training metadata
metadata = {
    "model": output_path.name,
    "environment": "PacketLevelEnv",
    "reward_source": "replica_snort_verdict",
    "total_timesteps": total_timesteps,
    "training_time_s": elapsed,
    "seed": 42,
    "max_packets_per_flow": 50
}

metadata_path = REPO / "logs" / f"training_packet_level{tag}.json"
metadata_path.parent.mkdir(exist_ok=True)
with open(metadata_path, "w") as f:
    json.dump(metadata, f, indent=2)

print(f"[✓] Metadata saved: {metadata_path}")
print(f"\n[✓] Training complete. Next: run evaluation against real Snort validation set.")
