"""
Fix: evaluate.py path resolution

Original issue:
  Line 10 uses hardcoded ~/Projects/... path which fails on other machines.

Solution:
  Use os.path.join() with relative paths from script directory.
"""

import os
import glob
import pandas as pd
import numpy as np
from stable_baselines3 import PPO
from c2_evasion_env import C2EvasionEnv

# Get script directory (relative paths from here)
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(SCRIPT_DIR)  # project root

def load_test_pool():
    """Load test data using relative paths."""
    archive_path = os.path.join(BASE_DIR, 'data', 'archive', '*.parquet')
    file_paths = glob.glob(archive_path)
    
    if len(file_paths) == 0:
        raise FileNotFoundError(f"No parquet files found in {archive_path}")
    
    df_list = [pd.read_parquet(file) for file in file_paths]
    df = pd.concat(df_list, ignore_index=True)
    
    label_col = 'Label' if 'Label' in df.columns else 'label'
    malicious_df = df[df[label_col].astype(str).str.lower().str.contains('botnet')].copy()
    
    feature_mapping = {
        'Dur': 'dur', 'TotPkts': 'tot_pkts', 'TotBytes': 'tot_bytes',
        'SrcBytes': 'src_bytes', 'Proto': 'proto', 'State': 'state'
    }
    malicious_df = malicious_df.rename(columns=feature_mapping)
    malicious_df = malicious_df.dropna(subset=['dur', 'tot_pkts', 'tot_bytes', 'src_bytes', 'proto', 'state'])
    
    return malicious_df.to_dict(orient='records')

if __name__ == "__main__":
    print("[*] Loading test data...")
    test_pool = load_test_pool()
    
    print("[*] Initializing environment...")
    surrogate_path = os.path.join(BASE_DIR, 'data', 'surrogate_ids_ctu13.pkl')
    proto_encoder_path = os.path.join(BASE_DIR, 'data', 'label_encoder_proto.pkl')
    state_encoder_path = os.path.join(BASE_DIR, 'data', 'label_encoder_state.pkl')
    
    env = C2EvasionEnv(
        malicious_data_pool=test_pool,
        model_path=surrogate_path,
        proto_encoder_path=proto_encoder_path,
        state_encoder_path=state_encoder_path,
        max_steps=10
    )
    
    model_path = os.path.join(BASE_DIR, 'models', 'ppo_c2_evasion_agent.zip')
    print(f"[*] Loading model from: {model_path}")
    
    try:
        model = PPO.load(model_path, env=env, device="cpu")
    except FileNotFoundError:
        print(f"[-] Model not found: {model_path}")
        print("[*] Run: python3 ai_agent/train_agent.py")
        exit(1)

    print("\n" + "="*60)
    print(" EVALUATING PPO AGENT ON 80 RANDOM SAMPLES")
    print("="*60)

    num_episodes = 80
    success_count = 0

    for i in range(num_episodes):
        obs, info = env.reset()
        done = False
        truncated = False
        step_count = 0
        
        while not done and not truncated:
            action, _states = model.predict(obs, deterministic=True)
            obs, reward, done, truncated, info = env.step(action)
            step_count += 1
        
        evaded = info.get("evasion_success", 0) == 1
        jitter = info.get("total_jitter", 0.0)
        padding = info.get("total_padding", 0.0)
        proto_hop = info.get("proto_hop", False)
        state_hop = info.get("state_hop", False)
        
        status = "✅ EVADED" if evaded else "❌ DETECTED"
        print(f"\n[Sample {i+1:02d}] {status}")
        print(f" ├─ Steps: {step_count}/{env.max_steps}")
        print(f" ├─ Jitter: {jitter:+.2f}s")
        print(f" ├─ Padding: {padding:+.0f}B")
        print(f" ├─ Proto hop: {'Yes' if proto_hop else 'No'}")
        print(f" ├─ State hop: {'Yes' if state_hop else 'No'}")
        
        if evaded:
            success_count += 1

    print("\n" + "="*60)
    success_rate = (success_count / num_episodes) * 100
    print(f"RESULT: {success_count}/{num_episodes} evasions ({success_rate:.1f}%)")
    print("="*60)
