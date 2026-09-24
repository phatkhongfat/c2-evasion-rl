import os
import glob
import pandas as pd
import random
import argparse
import numpy as np
import torch
from stable_baselines3 import PPO
from stable_baselines3.common.env_checker import check_env
from c2_evasion_env import C2EvasionEnv
from evasion_metrics_callback import EvasionMetricsCallback
from config import (
    DATA_DIR, ARCHIVE_DIR, MODEL_DIR, SNORT_SURROGATE_PATH,
    PPO_LEARNING_RATE, PPO_N_STEPS, PPO_BATCH_SIZE,
    PPO_GAMMA, PPO_ENT_COEF, PPO_CLIP_RANGE,
    TOTAL_TIMESTEPS
)

# Set seed for reproducibility
SEED = 42
random.seed(SEED)
np.random.seed(SEED)
torch.manual_seed(SEED)

# Ghi chú về feature_mapping: Cột gốc trong CTU-13 là lowercase
# ('dur', 'tot_pkts', 'tot_bytes', 'src_bytes', 'proto', 'state'),
# nên mapping sau là no-op an toàn, giữ lại cho tương thích ngược.

def load_malicious_pool():
    print("[*] Loading malicious samples from data/archive...")
    dataset_path = os.path.join(ARCHIVE_DIR, "*.parquet")
    file_paths = glob.glob(dataset_path)

    if len(file_paths) == 0:
        raise FileNotFoundError(f"No .parquet files found in {ARCHIVE_DIR}")

    df_list = [pd.read_parquet(file) for file in file_paths]
    df = pd.concat(df_list, ignore_index=True)

    label_col = 'Label' if 'Label' in df.columns else 'label'
    if label_col not in df.columns:
        raise KeyError("Column 'Label' or 'label' not found in data.")

    malicious_df = df[df[label_col].astype(str).str.lower().str.contains('botnet')].copy()

    feature_mapping = {
        'Dur': 'dur', 'TotPkts': 'tot_pkts', 'TotBytes': 'tot_bytes',
        'SrcBytes': 'src_bytes', 'Proto': 'proto', 'State': 'state'
    }
    malicious_df = malicious_df.rename(columns=feature_mapping)

    # Drop rows with missing values in these columns
    required_cols = ['dur', 'tot_pkts', 'tot_bytes', 'src_bytes', 'proto', 'state']
    malicious_df = malicious_df.dropna(subset=required_cols)

    pool = malicious_df.to_dict(orient='records')
    print(f"[+] Loaded {len(pool)} malicious samples.")
    return pool

def parse_args():
    ap = argparse.ArgumentParser()
    ap.add_argument("--snort", action="store_true",
                    help="enable Snort-surrogate defense-aware reward")
    return ap.parse_args()

if __name__ == "__main__":
    args = parse_args()
    malicious_pool = load_malicious_pool()

    env = C2EvasionEnv(
        malicious_data_pool=malicious_pool,
        max_steps=10,
        snort_surrogate_path=SNORT_SURROGATE_PATH if args.snort else None
    )

    print("[*] Checking environment compatibility...")
    check_env(env, warn=True)
    print("[+] Environment is valid.")

    print("[*] Initializing PPO agent with tuned hyperparameters...")
    model = PPO(
        "MlpPolicy",
        env,
        learning_rate=PPO_LEARNING_RATE,
        n_steps=PPO_N_STEPS,
        batch_size=PPO_BATCH_SIZE,
        gamma=PPO_GAMMA,
        ent_coef=PPO_ENT_COEF,
        clip_range=PPO_CLIP_RANGE,
        verbose=1,
        tensorboard_log="./c2_ppo_tensorboard/",
        device="cpu",
        seed=SEED
    )

    callback = EvasionMetricsCallback(log_interval=2048)

    print("[*] Starting training...")
    model.learn(total_timesteps=TOTAL_TIMESTEPS, callback=callback)

    os.makedirs(MODEL_DIR, exist_ok=True)
    tag = "_snortaware" if args.snort else ""
    model_save_path = os.path.join(MODEL_DIR, f"ppo_c2_evasion_agent{tag}")
    model.save(model_save_path)
    print(f"[+] Training complete. Model saved to {model_save_path}.zip")