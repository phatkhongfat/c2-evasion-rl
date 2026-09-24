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


def load_test_pool():
    """Load malicious botnet flows from CTU-13 dataset."""
    script_dir = Path(__file__).parent.parent
    dataset_path = script_dir / 'data' / 'archive' / '*.parquet'
    file_paths = glob.glob(str(dataset_path))
    
    df_list = [pd.read_parquet(file) for file in file_paths]
    df = pd.concat(df_list, ignore_index=True)
    
    label_col = 'Label' if 'Label' in df.columns else 'label'
    malicious_df = df[df[label_col].astype(str).str.lower().str.contains('botnet')].copy()
    
    feature_mapping = {
        'Dur': 'dur', 'TotPkts': 'tot_pkts', 'TotBytes': 'tot_bytes',
        'SrcBytes': 'src_bytes', 'Proto': 'proto', 'State': 'state'
    }
    malicious_df = malicious_df.rename(columns=feature_mapping)
    return malicious_df.to_dict(orient='records')


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


def run_evaluation_with_capture(num_episodes=80, policy_type='agent', agent_model="models/ppo_c2_evasion_agent.zip"):
    """
    Run evaluation and capture episode data.
    
    Args:
        num_episodes: number of episodes to run
        policy_type: 'agent' (PPO), 'random', or 'baseline' (no mutation)
        agent_model: path (relative to repo root) to the PPO model zip
    
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
        obs, info = env.reset()
        
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
                action = env.action_space.sample()
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
    return ap.parse_args()

def main():
    """
    Main workflow: run evaluation for agent, random, and baseline policies.
    """
    args = parse_args()
    output_dir = Path(__file__).parent.parent / "snort_validation/reports"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # 1. Agent policy (PPO)
    print("=" * 70)
    print("PHASE 1: AGENT POLICY (PPO)")
    print("=" * 70)
    agent_results = run_evaluation_with_capture(num_episodes=80, policy_type='agent', agent_model=args.agent_model)
    
    if agent_results is None:
        print("ERROR: Failed to run agent evaluation")
        return
    
    agent_output = output_dir / "agent_evaluation.json"
    with open(agent_output, 'w') as f:
        json.dump(agent_results, f, indent=2)
    print(f"✓ Agent results saved to: {agent_output}\n")
    
    # 2. Random policy
    print("=" * 70)
    print("PHASE 2: RANDOM POLICY (BASELINE)")
    print("=" * 70)
    random_results = run_evaluation_with_capture(num_episodes=80, policy_type='random')
    
    random_output = output_dir / "random_evaluation.json"
    with open(random_output, 'w') as f:
        json.dump(random_results, f, indent=2)
    print(f"✓ Random results saved to: {random_output}\n")
    
    # 3. No mutation baseline (use original features as-is)
    print("=" * 70)
    print("PHASE 3: NO MUTATION BASELINE")
    print("=" * 70)
    baseline_results = run_evaluation_with_capture(num_episodes=80, policy_type='baseline')
    
    baseline_output = output_dir / "baseline_evaluation.json"
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
