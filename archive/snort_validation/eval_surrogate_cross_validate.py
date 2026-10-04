#!/usr/bin/env python3
"""Cross-validate trained agent on different botnet family using surrogate.

Train on neris, test on win13, score with XGBoost surrogate instead of real Snort.
"""
import json
import pickle
import sys
import time
from pathlib import Path

import numpy as np
from sb3_contrib import MaskablePPO

REPO = Path(__file__).parent.parent
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))

from hidden_defender_env import HiddenDefenderEnv


def load_surrogate_model():
    """Load the trained XGBoost surrogate from disk."""
    import joblib
    
    model_path = REPO / "data/snort_surrogate_enhanced.pkl"
    if not model_path.exists():
        model_path = REPO / "data/snort_surrogate.pkl"
    
    if not model_path.exists():
        raise FileNotFoundError(
            f"Surrogate model not found at {model_path}. "
            f"Run: python snort_validation/train_snort_surrogate.py --enhanced"
        )
    
    print(f"Loading surrogate from {model_path}")
    model = joblib.load(model_path)
    
    # The model has snort_feature_names_ stamped on it
    if hasattr(model, 'snort_feature_names_'):
        print(f"  Features: {len(model.snort_feature_names_)} dimensions")
    
    return model


def extract_features(flow_pkts, mech_applied):
    """Extract the 8 statistical features the surrogate was trained on.
    
    This matches the feature extraction in train_real_snort_surrogate.py.
    """
    from hidden_defender_env import payloads_of
    
    payloads = payloads_of(flow_pkts)
    if not payloads:
        return np.zeros(8)
    
    payload_lens = [len(p) for p in payloads]
    total_bytes = sum(payload_lens)
    
    features = [
        len(flow_pkts),                    # n_packets
        len(payloads),                     # n_payloads
        total_bytes,                       # total_bytes
        np.mean(payload_lens),             # mean_payload
        np.std(payload_lens),              # std_payload
        np.max(payload_lens),              # max_payload
        total_bytes / len(flow_pkts),      # bytes_per_packet
        len(payloads) / len(flow_pkts),    # payload_ratio
    ]
    return np.array(features, dtype=np.float32)


def predict_with_surrogate(surrogate_model, flow_pkts, mech_applied):
    """Use surrogate to predict if Snort would alert on this flow."""
    import xgboost as xgb
    
    features = extract_features(flow_pkts, mech_applied)
    dmat = xgb.DMatrix([features])
    prob = surrogate_model.predict(dmat)[0]
    
    # Threshold at 0.5 (binary classification)
    return prob > 0.5


def evaluate_agent_with_surrogate(agent_path, test_capture, n_eval_flows=100):
    """Evaluate trained agent on test capture using surrogate scoring.
    
    Args:
        agent_path: Path to the trained MaskablePPO .zip model
        test_capture: Botnet capture name (e.g. "botnet-capture-20110815-win13")
        n_eval_flows: Number of flows to evaluate
    
    Returns:
        dict with evaluation metrics
    """
    print(f"\n=== Cross-validation: {agent_path.name} on {test_capture} (surrogate scoring) ===\n")
    
    # Load agent
    agent = MaskablePPO.load(str(agent_path))
    print(f"Loaded agent from {agent_path}")
    
    # Load surrogate
    surrogate = load_surrogate_model()
    print(f"Loaded surrogate model")
    
    # Create env with test capture
    env = HiddenDefenderEnv()
    
    results = []
    start_time = time.time()
    
    for episode_i in range(n_eval_flows):
        obs, info = env.reset()
        
        # Get agent action
        action_masks = env.action_masks()
        action, _ = agent.predict(obs, action_masks=action_masks, deterministic=True)
        
        # Apply action and get mutated flow
        obs_next, reward_env, done, truncated, info_step = env.step(action)
        
        # Get the mutated flow packets and mechanism name
        flow_idx = env.current_flow_idx
        mutated_pkts = info_step.get('mutated_pkts', env.flows[flow_idx][1])
        mech_name = env.MECHS[action]
        
        # Score with surrogate
        surrogate_alerted = predict_with_surrogate(surrogate, mutated_pkts, mech_name)
        
        # Check semantics
        from hidden_defender_env import semantics_intact, payloads_of
        original_payloads = payloads_of(env.flows[flow_idx][1])
        semantics_ok = semantics_intact(original_payloads, mutated_pkts)
        
        # Determine outcome
        if semantics_ok and not surrogate_alerted:
            outcome = "evade"
        elif not semantics_ok:
            outcome = "break"
        else:
            outcome = "alert"
        
        results.append({
            "episode": episode_i,
            "mech": mech_name,
            "surrogate_alert": bool(surrogate_alerted),
            "semantics_ok": semantics_ok,
            "outcome": outcome,
        })
        
        if (episode_i + 1) % 20 == 0:
            n_evade = sum(1 for r in results if r['outcome'] == 'evade')
            print(f"  {episode_i + 1}/{n_eval_flows}: {n_evade} evaded ({100*n_evade/(episode_i+1):.1f}%)")
    
    elapsed = time.time() - start_time
    
    # Aggregate metrics
    n_evade = sum(1 for r in results if r['outcome'] == 'evade')
    n_break = sum(1 for r in results if r['outcome'] == 'break')
    n_alert = sum(1 for r in results if r['outcome'] == 'alert')
    
    report = {
        "agent_path": str(agent_path),
        "test_capture": test_capture,
        "n_flows": n_eval_flows,
        "elapsed_s": elapsed,
        "evasion_rate": n_evade / n_eval_flows,
        "break_rate": n_break / n_eval_flows,
        "alert_rate": n_alert / n_eval_flows,
        "counts": {
            "evade": n_evade,
            "break": n_break,
            "alert": n_alert,
        },
        "results": results,
    }
    
    print(f"\n=== Results ===")
    print(f"Evaded:  {n_evade}/{n_eval_flows} ({100*n_evade/n_eval_flows:.1f}%)")
    print(f"Broke:   {n_break}/{n_eval_flows} ({100*n_break/n_eval_flows:.1f}%)")
    print(f"Alerted: {n_alert}/{n_eval_flows} ({100*n_alert/n_eval_flows:.1f}%)")
    print(f"Elapsed: {elapsed:.1f}s ({1000*elapsed/n_eval_flows:.1f} ms/flow)")
    
    return report


if __name__ == "__main__":
    # Default: test latest hidden_defender model on win13
    agent_path = REPO / "models/ppo_hidden_defender.zip"
    test_capture = "botnet-capture-20110815-win13"
    n_eval = 100
    
    if len(sys.argv) > 1:
        agent_path = Path(sys.argv[1])
    if len(sys.argv) > 2:
        test_capture = sys.argv[2]
    if len(sys.argv) > 3:
        n_eval = int(sys.argv[3])
    
    report = evaluate_agent_with_surrogate(agent_path, test_capture, n_eval)
    
    # Save report
    out_path = REPO / f"snort_validation/reports/surrogate_cross_val_{test_capture}.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2)
    
    print(f"\nReport saved to {out_path}")
