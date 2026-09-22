"""
PROOF: evasion_metrics_callback.py reports STEP-fraction, not episode evasion rate.

The callback appends info["evasion_success"] for EVERY step:
  - Successful episode → 1 step with flag=1
  - Failed episode → up to max_steps steps with flag=0

Therefore:  callback_metric ≈ (episodes_evaded) / (total_steps) = p / L

where p = true episode evasion rate, L = mean episode length.

This test proves it on 300 deterministic rollouts from a trained model.
"""
import sys, os, glob, warnings
warnings.filterwarnings("ignore")
import numpy as np, pandas as pd

sys.path.insert(0, os.path.dirname(__file__))
from c2_evasion_env import C2EvasionEnv
from stable_baselines3 import PPO

def main():
    # Load data
    files = sorted(glob.glob("../data/archive/*.parquet"))
    df = pd.concat([pd.read_parquet(f) for f in files], ignore_index=True)
    df = df[df["label"].astype(str).str.lower().str.contains("botnet")].copy()
    df = df.rename(columns={"Dur": "dur", "TotPkts": "tot_pkts", "TotBytes": "tot_bytes",
                            "SrcBytes": "src_bytes", "Proto": "proto", "State": "state"})
    df = df.dropna(subset=["dur", "tot_pkts", "tot_bytes", "src_bytes", "proto", "state"])
    pool = df.to_dict(orient="records")
    print(f"[*] pool: {len(pool):,} botnet flows")

    env = C2EvasionEnv(malicious_data_pool=pool, max_steps=10)
    
    # Load a trained model (or create a dummy one for testing)
    try:
        model = PPO.load("./ppo_c2_evasion_agent", device="cpu")
        print("[*] loaded trained model")
    except:
        print("[!] no trained model; create one or load from checkpoint")
        return

    # Roll out 300 episodes deterministically
    N = 300
    ep_success, ep_len = [], []
    step_flags = []  # faithful replay of callback's success_buffer

    for i in range(N):
        obs, _ = env.reset(seed=5000 + i)
        done = trunc = False
        info = {}
        flags_this_ep = []
        k = 0
        while not done and not trunc:
            a, _ = model.predict(obs, deterministic=True)
            obs, r, done, trunc, info = env.step(a)
            k += 1
            flags_this_ep.append(info.get("evasion_success", 0))
        step_flags.extend(flags_this_ep)
        ep_success.append(info.get("evasion_success", 0) == 1)
        ep_len.append(k)

    # Calculate metrics
    p = float(np.mean(ep_success))
    L = float(np.mean(ep_len))
    cb_metric = float(np.mean(step_flags))

    print()
    print("=" * 74)
    print(" PROOF: callback metric = p / L")
    print("=" * 74)
    print(f"  Episodes evaluated              : {N}")
    print(f"  (1) TRUE episode evasion rate p : {p*100:.1f}%")
    print(f"  (2) mean episode length L       : {L:.2f}")
    print()
    print(f"  (3) callback metric (steps)     : {cb_metric*100:.1f}%")
    print(f"      predicted by p/L            : {p/L*100:.1f}%")
    print(f"      difference                  : {abs(cb_metric - p/L)*100:.2f} pp")
    print()
    print(f"  Deflation factor                : {p/cb_metric:.2f}x")
    print("=" * 74)
    print()
    print("  FIX: evasion_metrics_callback.py should aggregate per-episode,")
    print("  not per-step. See callback_fix.patch for the correction.")

if __name__ == "__main__":
    main()
