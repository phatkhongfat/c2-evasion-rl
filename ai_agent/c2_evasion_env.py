import gymnasium as gym
from gymnasium import spaces
import numpy as np
import joblib
import warnings

# Tắt cảnh báo thiếu tên cột của scikit-learn
warnings.filterwarnings("ignore", message="X does not have valid feature names")

class C2EvasionEnv(gym.Env):
    metadata = {'render.modes': ['human']}

    def __init__(
        self, 
        malicious_data_pool, 
        model_path="../data/surrogate_ids_ctu13.pkl",
        proto_encoder_path="../data/label_encoder_proto.pkl",
        state_encoder_path="../data/label_encoder_state.pkl",
        max_steps=10
    ):
        super(C2EvasionEnv, self).__init__()
        
        self.judge = joblib.load(model_path)
        self.protocol_encoder = joblib.load(proto_encoder_path)
        self.state_encoder = joblib.load(state_encoder_path)
        
        self.malicious_pool = malicious_data_pool
        self.max_steps = max_steps
        self.current_step = 0
        
        # MỞ RỘNG ACTION SPACE: [jitter, padding, proto_hop, state_hop]
        # shape=(4,) cho phép agent kiểm soát cả 4 yếu tố
        self.action_space = spaces.Box(
            low=-1.0, high=1.0, shape=(4,), dtype=np.float32
        )
        
        self.observation_space = spaces.Box(
            low=-np.inf, high=np.inf, shape=(6,), dtype=np.float32
        )
        
    def reset(self, seed=None, options=None):
        super().reset(seed=seed)
        self.current_step = 0
        
        self.current_idx = int(self.np_random.integers(0, len(self.malicious_pool)))
        self.initial_sample = self.malicious_pool[self.current_idx].copy()
        self.current_sample = self.initial_sample.copy()
        
        initial_obs = self._extract_features(self.current_sample)
        self.initial_pred = int(self.judge.predict(initial_obs.reshape(1, -1))[0])
        
        return initial_obs, {}

    def step(self, action):
        self.current_step += 1

        # Clip action space to valid continuous bounds [-1, 1]
        action = np.clip(np.asarray(action, dtype=np.float32), -1.0, 1.0)

        jitter = float(action[0] * 5.0)
        byte_delta = float(action[1] * 500.0)
        proto_hop = bool(action[2] > 0.0)
        state_hop = bool(action[3] > 0.0)

        # 1. Cumulative mutation for continuous features (dur, bytes)
        self.current_sample["dur"] += jitter
        self.current_sample["tot_bytes"] += byte_delta
        self.current_sample["src_bytes"] += byte_delta

        # 2. Packet transform logic (Padding vs Fragmentation)
        if byte_delta >= 0:
            added_packets = np.ceil(byte_delta / 1460.0)
            self.current_sample["tot_pkts"] += added_packets
        else:
            fragment_ratio = 1.0 + abs(action[1]) * 4.0
            current_pkts = self.current_sample["tot_pkts"]
            new_pkts = np.ceil(current_pkts * fragment_ratio)
            
            # Header overhead logic for fragmentation (TCP/IP = ~54 bytes)
            added_packets = new_pkts - current_pkts
            added_headers = added_packets * 54.0
            
            self.current_sample["tot_pkts"] += added_packets
            self.current_sample["tot_bytes"] += added_headers
            self.current_sample["src_bytes"] += added_headers

        # 3. Categorical Reset & Hop (Non-cumulative per step)
        self.current_sample["proto"] = self.initial_sample.get("proto", "tcp")
        self.current_sample["state"] = self.initial_sample.get("state", "CON")

        if proto_hop:
            self.current_sample["proto"] = "tcp"
        if state_hop:
            self.current_sample["state"] = "CON"

        # 4. Fallback Bounds
        self.current_sample["dur"] = max(0.0, float(self.current_sample["dur"]))
        self.current_sample["tot_bytes"] = max(0.0, float(self.current_sample["tot_bytes"]))
        self.current_sample["src_bytes"] = max(0.0, float(self.current_sample["src_bytes"]))
        self.current_sample["tot_pkts"] = max(1.0, float(self.current_sample["tot_pkts"]))

        obs = self._extract_features(self.current_sample)
        prediction = int(self.judge.predict(obs.reshape(1, -1))[0])

        # 5. Meaningful Penalty for Operations Security (OPSEC)
        # Tăng trọng số phạt (0.01 cho byte, 0.1 cho giây) để PPO tiết kiệm hành động
        mutation_cost = (abs(byte_delta) * 0.01) + (abs(jitter) * 0.1)

        if prediction == 0:
            reward = 50.0 - mutation_cost
            evaded = True
            terminated = True
        else:
            reward = -2.0 - mutation_cost
            evaded = False
            terminated = False

        # Gym API compliance
        truncated = self.current_step >= self.max_steps

        info = {
            "initial_prediction": self.initial_pred,
            "final_prediction": prediction,
            "evasion_success": int(evaded),
            "total_padding": byte_delta,
            "total_jitter": jitter,
            "proto_hop": proto_hop,
            "state_hop": state_hop,
            "episode_length": self.current_step,
        }

        return obs, float(reward), terminated, truncated, info

    def _extract_features(self, sample):
        dur = self._safe_float(sample.get('dur', 0.0))
        tot_pkts = self._safe_float(sample.get('tot_pkts', 1.0))
        tot_bytes = self._safe_float(sample.get('tot_bytes', 40.0))
        src_bytes = self._safe_float(sample.get('src_bytes', 40.0))
        
        proto_val = sample.get('proto', 'tcp')
        state_val = sample.get('state', 'CON')
        
        p_encoded = self._encode_value(self.protocol_encoder, proto_val)
        s_encoded = self._encode_value(self.state_encoder, state_val)
            
        features = np.array([
            dur, tot_pkts, tot_bytes, src_bytes, p_encoded, s_encoded
        ], dtype=np.float32)
        
        return np.nan_to_num(features, nan=0.0, posinf=1e6, neginf=-1e6)

    @staticmethod
    def _safe_float(value, default=0.0):
        try:
            val = float(value)
            return val if np.isfinite(val) else float(default)
        except (TypeError, ValueError):
            return float(default)

    @staticmethod
    def _encode_value(encoder, value, default=0.0):
        try:
            return float(encoder.transform([str(value)])[0])
        except Exception:
            return float(default)