#!/usr/bin/env python3
"""
Wrapper for ai_agent/evaluate.py that captures episode data for Snort validation.

This script:
1. Runs evaluation with the trained PPO agent (80 episodes)
2. Captures original and mutated flow features for each episode
3. Saves the data in a format that validate_with_snort.py can consume
"""
import os
import sys
import glob
import json
import argparse
import pandas as pd
import numpy as np
from pathlib import Path

# Add ai_agent to path
sys.path.insert(0, str(Path(__file__).parent.parent / "ai_agent"))

from stable_baselines3 import PPO
from c2_evasion_env import C2EvasionEnv
from pool_loader import load_malicious_pool


def load_test_pool():
    """Load malicious botnet flows from CTU-13 dataset.

    Uses the shared lean loader so evaluation and training see exactly the same
    pool (and so eval does not balloon to ~2.7 GB).
    """
    return load_malicious_pool(verbose=True)


def extract_flow_features(env):
    """
    Extract current flow features from environment.
    
    Returns dict with the 6 flow features (after any mutations).
    """
    # Access current_sample which holds mutated flow features
    sample = getattr(env, 'current_sample', None)
    if sample is None:
        # Fallback to initial_sample if current_sample not available
        sample = getattr(env, 'initial_sample', {})
    
    return {
        'dur': float(sample.get('dur', 0)),
        'tot_pkts': int(sample.get('tot_pkts', 0)),
        'tot_bytes': int(sample.get('tot_bytes', 0)),
        'src_bytes': int(sample.get('src_bytes', 0)),
        'proto': str(getattr(env, 'current_proto', sample.get('proto', 'udp'))),
        'state': str(getattr(env, 'current_state', sample.get('state', 'CON')))
    }


def run_evaluation_with_capture(num_episodes=80, policy_type='agent', agent_model="models/ppo_c2_evasion_agent.zip", seed=42):
    """
    Run evaluation and capture episode data.
    
    Args:
        num_episodes: number of episodes to run
        policy_type: 'agent' (PPO), 'random', or 'baseline' (no mutation)
        agent_model: path (relative to repo root) to the PPO model zip
        seed: base seed; episode i is reset with seed+i, so all policies and
              all runs are evaluated on the SAME episode sequence
    
    Returns:
        dict with episodes data and summary stats
    """
    print(f"[*] Loading test data...")
    test_pool = load_test_pool()
    
    print(f"[*] Initializing environment...")
    script_dir = Path(__file__).parent.parent
    env = C2EvasionEnv(
        malicious_data_pool=test_pool,
        model_path=str(script_dir / "data/surrogate_ids_ctu13.pkl"),
        proto_encoder_path=str(script_dir / "data/label_encoder_proto.pkl"),
        state_encoder_path=str(script_dir / "data/label_encoder_state.pkl"),
        max_steps=10
    )
    
    model = None
    if policy_type == 'agent':
        model_path = script_dir / agent_model
        print(f"[*] Loading PPO model from: {model_path}")
        try:
            model = PPO.load(str(model_path), env=env, device="cpu")
        except Exception as e:
            print(f"[-] Error loading model: {e}")
            return None
    
    print(f"\n{'='*60}")
    print(f" EVALUATION: {policy_type.upper()} POLICY ON {num_episodes} EPISODES")
    print(f"{'='*60}\n")
    
    episodes_data = []
    success_count = 0
    
    for i in range(num_episodes):
        # Deterministic episode sampling: identical across policies and runs.
        obs, info = env.reset(seed=seed + i)

        # The random policy must also be reproducible. action_space.sample()
        # draws from a separate RNG that env.reset(seed=...) does not touch, so
        # it produced a different mutation sequence on every run (57/80 one
        # run, 55/80 the next) and made the random row un-comparable.
        rng = np.random.default_rng(seed + i)
        
        # Capture original flow features
        original_features = extract_flow_features(env)
        
        done = False
        truncated = False
        step_count = 0
        episode_actions = []
        
        # Run episode
        while not done and not truncated:
            if policy_type == 'agent' and model is not None:
                action, _ = model.predict(obs, deterministic=True)
            elif policy_type == 'random':
                action = rng.uniform(-1.0, 1.0, size=4).astype(np.float32)
            else:  # baseline: no action
                action = np.zeros(4, dtype=np.float32)  # [0, 0, 0, 0] = no mutation
            
            if hasattr(action, 'tolist'):
                episode_actions.append(action.tolist())
            elif isinstance(action, (list, tuple)):
                episode_actions.append(list(action))
            else:
                episode_actions.append([float(action)])
            obs, reward, done, truncated, info = env.step(action)
            step_count += 1
        
        # Capture mutated flow features
        mutated_features = extract_flow_features(env)
        
        evaded = info.get("evasion_success", 0) == 1
        
        # Build episode record
        episode_record = {
            'episode_id': i,
            'policy': policy_type,
            'original_features': original_features,
            'mutated_features': mutated_features,
            'actions': episode_actions,
            'steps': step_count,
            'evaded_xgboost': evaded,
            'jitter': float(info.get("total_jitter", 0.0)),
            'padding': float(info.get("total_padding", 0.0)),
            'proto_hop': bool(info.get("proto_hop", False)),
            'state_hop': bool(info.get("state_hop", False))
        }
        
        episodes_data.append(episode_record)
        
        if evaded:
            success_count += 1
        
        # Progress indicator
        if (i + 1) % 20 == 0:
            print(f"Processed {i+1}/{num_episodes} episodes...")
    
    xgb_evasion_rate = success_count / num_episodes
    
    print(f"\n{'='*60}")
    print(f"XGBoost Evasion Rate: {success_count}/{num_episodes} ({xgb_evasion_rate*100:.1f}%)")
    print(f"{'='*60}\n")
    
    return {
        'policy': policy_type,
        'num_episodes': num_episodes,
        'xgb_evasion_rate': xgb_evasion_rate,
        'xgb_success_count': success_count,
        'episodes': episodes_data
    }


def parse_args():
    ap = argparse.ArgumentParser()
    ap.add_argument("--agent-model", default="models/ppo_c2_evasion_agent.zip",
                    help="path to PPO model zip for the agent policy")
    ap.add_argument("--suffix", default="",
                    help="run-tag suffix for output files, e.g. _enhanced_10. "
                         "REQUIRED to keep a new sweep from overwriting the "
                         "blind baseline reports.")
    ap.add_argument("--num-episodes", type=int, default=80)
    ap.add_argument("--seed", type=int, default=42,
                    help="base seed; episode i uses seed+i so every policy "
                         "and every run sees the SAME 80 episodes. Without "
                         "this, cross-run deltas mix policy effect with "
                         "episode-sampling variance (the no-mutation baseline "
                         "alone moved 5%%->15%% between unseeded runs).")
    return ap.parse_args()

def main():
    """
    Main workflow: run evaluation for agent, random, and baseline policies.
    """
    args = parse_args()
    sfx = args.suffix
    output_dir = Path(__file__).parent.parent / "snort_validation/reports"
    output_dir.mkdir(parents=True, exist_ok=True)

    # 1. Agent policy (PPO)
    print("=" * 70)
    print("PHASE 1: AGENT POLICY (PPO)")
    print("=" * 70)
    agent_results = run_evaluation_with_capture(num_episodes=args.num_episodes, policy_type='agent', agent_model=args.agent_model, seed=args.seed)
    
    if agent_results is None:
        print("ERROR: Failed to run agent evaluation")
        return
    
    agent_output = output_dir / f"agent_evaluation{sfx}.json"
    with open(agent_output, 'w') as f:
        json.dump(agent_results, f, indent=2)
    print(f"✓ Agent results saved to: {agent_output}\n")
    
    # 2. Random policy
    print("=" * 70)
    print("PHASE 2: RANDOM POLICY (BASELINE)")
    print("=" * 70)
    random_results = run_evaluation_with_capture(num_episodes=args.num_episodes, policy_type="random", seed=args.seed)
    
    random_output = output_dir / f"random_evaluation{sfx}.json"
    with open(random_output, 'w') as f:
        json.dump(random_results, f, indent=2)
    print(f"✓ Random results saved to: {random_output}\n")
    
    # 3. No mutation baseline (use original features as-is)
    print("=" * 70)
    print("PHASE 3: NO MUTATION BASELINE")
    print("=" * 70)
    baseline_results = run_evaluation_with_capture(num_episodes=args.num_episodes, policy_type="baseline", seed=args.seed)
    
    baseline_output = output_dir / f"baseline_evaluation{sfx}.json"
    with open(baseline_output, 'w') as f:
        json.dump(baseline_results, f, indent=2)
    print(f"✓ Baseline results saved to: {baseline_output}\n")
    
    # Summary
    print("\n" + "=" * 70)
    print("EVALUATION COMPLETE — XGBoost Evasion Rates:")
    print("=" * 70)
    print(f"Agent:    {agent_results['xgb_evasion_rate']*100:.1f}%")
    print(f"Random:   {random_results['xgb_evasion_rate']*100:.1f}%")
    print(f"Baseline: {baseline_results['xgb_evasion_rate']*100:.1f}%")
    print("=" * 70)
    print("\nNext: Run validate_with_snort.py to measure Snort detection rates")


if __name__ == "__main__":
    main()
