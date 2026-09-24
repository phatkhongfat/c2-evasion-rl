#!/usr/bin/env python3
"""
Evaluate packet-level PPO agent against real Snort replica.
Seeded evaluation: 80 episodes, seed=42.
"""
import sys
import os
from pathlib import Path
import json
import argparse

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))

from packet_level_env import PacketLevelEnv
from pool_loader import load_malicious_pool
from stable_baselines3 import PPO
from snort_query_service import replica_snort_verdict

parser = argparse.ArgumentParser()
parser.add_argument("--model", default="ppo_packet_level_agent.zip",
                    help="model filename under models/")
parser.add_argument("--episodes", type=int, default=80)
parser.add_argument("--report", default="packet_level_agent_evaluation.json",
                    help="report filename under snort_validation/reports/")
args = parser.parse_args()

print("[*] Evaluating packet-level agent (80 seeded episodes, seed=42)")

# Load pool and model
pool = load_malicious_pool()
model_path = REPO / "models" / args.model

if not model_path.exists():
    print(f"[!] Model not found: {model_path}")
    print("[!] Run training first: python3 ai_agent/train_packet_level_agent.py")
    sys.exit(1)

print(f"[*] Loading model: {model_path.name}")
model = PPO.load(model_path)

# Create env
env = PacketLevelEnv(pool, max_packets_per_flow=50, seed=42)

# Evaluate
n_episodes = args.episodes
agent_evaded = 0
agent_detected = 0
random_evaded = 0
random_detected = 0

print(f"[*] Running {n_episodes} evaluation episodes...")

for ep in range(n_episodes):
    obs, info = env.reset(seed=42 + ep)
    
    # Agent episode
    done = False
    while not done:
        action, _ = model.predict(obs, deterministic=True)
        obs, reward, terminated, truncated, info = env.step(action)
        done = terminated or truncated
    
    if info["detected"]:
        agent_detected += 1
    else:
        agent_evaded += 1
    
    # Random baseline: unmodified flow
    initial_flow = env.current_flow.copy()
    random_verdict = replica_snort_verdict(initial_flow)
    if random_verdict:
        random_detected += 1
    else:
        random_evaded += 1
    
    if (ep + 1) % 20 == 0:
        print(f"[*] Episodes {ep+1}/{n_episodes} complete")

# Compute stats
agent_evasion_pct = (agent_evaded / n_episodes) * 100
random_evasion_pct = (random_evaded / n_episodes) * 100

print(f"\n[+] Packet-level agent evaluation:")
print(f"    Agent: {agent_detected} detected / {agent_evaded} evaded ({agent_evasion_pct:.1f}% evasion)")
print(f"    Random: {random_detected} detected / {random_evaded} evaded ({random_evasion_pct:.1f}% evasion)")

# Save report
report = {
    "seed": 42,
    "n_episodes": n_episodes,
    "model": args.model,
    "environment": "PacketLevelEnv",
    "agent": {
        "detected": agent_detected,
        "evaded": agent_evaded,
        "evasion_rate": agent_evasion_pct
    },
    "random_baseline": {
        "detected": random_detected,
        "evaded": random_evaded,
        "evasion_rate": random_evasion_pct
    }
}

report_path = REPO / "snort_validation" / "reports" / args.report
report_path.parent.mkdir(parents=True, exist_ok=True)
with open(report_path, "w") as f:
    json.dump(report, f, indent=2)

print(f"[✓] Report: {report_path}")

# Success criterion
if agent_evasion_pct > random_evasion_pct:
    print(f"\n[✓] SUCCESS: Agent beats random baseline by {agent_evasion_pct - random_evasion_pct:.1f}%")
else:
    print(f"\n[!] Agent underperforms random by {random_evasion_pct - agent_evasion_pct:.1f}%")
    print("[!] Consider: more training steps, hyperparameter tuning, or action space redesign")
