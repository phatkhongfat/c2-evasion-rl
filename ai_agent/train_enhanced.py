#!/usr/bin/env python3
"""
Train PPO on EnhancedPacketLevelEnv where TTL/frag/overlap actually matter.
"""
import sys
import os
from pathlib import Path
import time
import argparse

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))

from enhanced_packet_level_env import EnhancedPacketLevelEnv
from pool_loader import load_malicious_pool
from stable_baselines3 import PPO
from stable_baselines3.common.callbacks import CheckpointCallback
from snort_query_service import packet_plan
import json

parser = argparse.ArgumentParser()
parser.add_argument("--timesteps", type=int, default=50000,
                    help="total PPO timesteps")
parser.add_argument("--checkpoint-freq", type=int, default=5000,
                    help="checkpoint every N timesteps")
parser.add_argument("--subset", default="tcp10", choices=["tcp10", "full"],
                    help="training subset: tcp10 (tcp flows >=10 pkts) or full")
args = parser.parse_args()

print("[*] Training PPO on EnhancedPacketLevelEnv (TTL/frag/overlap matter!)")
print(f"    Subset: {args.subset}")
print(f"    Reward: enhanced_replica_snort_verdict (packet-level heuristics)\n")

# Load pool
print("[*] Loading malicious data pool...")
pool = load_malicious_pool()
print(f"[+] Loaded {len(pool)} flows")

if args.subset == "tcp10":
    filtered = [f for f in pool if f.get("proto", "") == "tcp" and len(packet_plan(f)) >= 10]
    print(f"[*] Filtered to tcp_pkt>=10: {len(filtered)} flows ({100*len(filtered)/len(pool):.1f}%)\n")
else:
    filtered = pool
    print(f"[*] Using full pool\n")

# Create enhanced env
print("[*] Creating enhanced packet-level environment...")
env = EnhancedPacketLevelEnv(filtered, max_packets_per_flow=50, seed=42)
print(f"    Action space: {env.action_space}")
print(f"    Observation space: {env.observation_space}")
print(f"    Reward includes: TTL variance, fragmentation %, TCP overlap\n")

print(f"[*] Training from scratch ({args.timesteps} steps, seed=42)\n")

start_time = time.time()

model = PPO(
    "MlpPolicy",
    env,
    learning_rate=3e-4,
    n_steps=256,
    batch_size=64,
    n_epochs=10,
    gamma=0.99,
    gae_lambda=0.95,
    clip_range=0.2,
    ent_coef=0.01,
    verbose=1,
    seed=42,
    device="auto"
)

checkpoint_callback = CheckpointCallback(
    save_freq=args.checkpoint_freq,
    save_path=str(REPO / "models" / "checkpoints_enhanced"),
    name_prefix="ppo_enhanced"
)

print("[*] Starting training...\n")
model.learn(total_timesteps=args.timesteps, callback=checkpoint_callback, log_interval=10)

# Save
output_path = REPO / "models" / f"ppo_enhanced_{args.subset}.zip"
model.save(output_path)
elapsed = time.time() - start_time

print(f"\n[+] Training complete in {elapsed:.1f}s ({elapsed/3600:.2f}h)")
print(f"[+] Model saved: {output_path.name}")

# Metadata
metadata = {
    "model": output_path.name,
    "environment": "EnhancedPacketLevelEnv",
    "subset": args.subset,
    "subset_size": len(filtered),
    "reward_source": "enhanced_replica_snort_verdict",
    "packet_level_features": ["ttl_variance", "fragmentation_rate", "tcp_overlap"],
    "total_timesteps": args.timesteps,
    "training_time_s": elapsed,
    "seed": 42
}

metadata_path = REPO / "logs" / f"training_enhanced_{args.subset}.json"
metadata_path.parent.mkdir(exist_ok=True)
with open(metadata_path, "w") as f:
    json.dump(metadata, f, indent=2)

print(f"[✓] Metadata saved: {metadata_path}")
print(f"\n[✓] Training complete. TTL/frag/overlap now influence the reward!")
