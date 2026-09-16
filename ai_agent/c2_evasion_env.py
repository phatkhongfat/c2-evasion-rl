import gymnasium as gym
from gymnasium import spaces
import numpy as np
import joblib
import warnings
from config import (
    SURROGATE_PATH, PROTO_ENCODER_PATH, STATE_ENCODER_PATH,
    MAX_STEPS, FEATURE_BOUNDS,
    REWARD_EVASION, REWARD_DETECTION, STEP_PENALTY,
    CONFIDENCE_BONUS_SCALE, COST_BYTE, COST_JITTER,
    OBSERVATION_FEATURES
)

warnings.filterwarnings("ignore", message="X does not have valid feature names")

class C2EvasionEnv(gym.Env):
    metadata = {'render.modes': ['human']}

    def __init__(
        self,
        malicious_data_pool,
        model_path=SURROGATE_PATH,
        proto_encoder_path=PROTO_ENCODER_PATH,
        state_encoder_path=STATE_ENCODER_PATH,
        max_steps=MAX_STEPS
    ):
        super(C2EvasionEnv, self).__init__()

        self.judge = joblib.load(model_path)
        self.protocol_encoder = joblib.load(proto_encoder_path)
        self.state_encoder = joblib.load(state_encoder_path)

        self.malicious_pool = malicious_data_pool
        self.max_steps = max_steps
        self.current_step = 0

        # Action: [jitter, padding, proto_hop, state_hop]
        self.action_space = spaces.Box(
            low=-1.0, high=1.0, shape=(4,), dtype=np.float32
        )

        # Observation: 6 features (will be normalized)
        self.observation_space = spaces.Box(
            low=-np.inf, high=np.inf, shape=(6,), dtype=np.float32
        )

        # Running state for proto and state (cumulative)
        self.current_proto = None
        self.current_state = None

    def reset(self, seed=None, options=None):
        super().reset(seed=seed)
        self.current_step = 0

        self.current_idx = int(self.np_random.integers(0, len(self.malicious_pool)))
        self.initial_sample = self.malicious_pool[self.current_idx].copy()
        self.current_sample = self.initial_sample.copy()

        # Initialize proto and state from the sample
        self.current_proto = self.current_sample.get('proto', 'tcp')
        self.current_state = self.current_sample.get('state', 'CON')

        # Raw features for the judge (trained on raw magnitudes), normalized for the agent
        raw = self._extract_features(self.current_sample)
        self.initial_pred = int(self.judge.predict(raw.reshape(1, -1))[0])
        # Get initial probability of being malicious (for confidence shaping)
        self.initial_proba = self.judge.predict_proba(raw.reshape(1, -1))[0][1]

        return self._normalize(raw), {}

    def step(self, action):
        self.current_step += 1
        action = np.clip(np.asarray(action, dtype=np.float32), -1.0, 1.0)

        jitter = float(action[0] * 5.0)           # ±5 seconds
        byte_delta = float(action[1] * 500.0)     # ±500 bytes
        proto_hop = bool(action[2] > 0.0)
        state_hop = bool(action[3] > 0.0)

        # 1. Continuous mutations
        self.current_sample["dur"] += jitter
        self.current_sample["tot_bytes"] += byte_delta
        self.current_sample["src_bytes"] += byte_delta

        # 2. Packet transform (padding/fragmentation)
        if byte_delta >= 0:
            added_packets = np.ceil(byte_delta / 1460.0)
            self.current_sample["tot_pkts"] += added_packets
        else:
            fragment_ratio = 1.0 + abs(action[1]) * 4.0
            current_pkts = self.current_sample["tot_pkts"]
            new_pkts = np.ceil(current_pkts * fragment_ratio)
            added_packets = new_pkts - current_pkts
            added_headers = added_packets * 54.0
            self.current_sample["tot_pkts"] += added_packets
            self.current_sample["tot_bytes"] += added_headers
            self.current_sample["src_bytes"] += added_headers

        # 3. Categorical hops (cumulative)
        if proto_hop:
            # Toggle protocol between 'tcp' and 'udp' (or stay if unknown)
            if self.current_proto == 'tcp':
                self.current_proto = 'udp'
            elif self.current_proto == 'udp':
                self.current_proto = 'tcp'
            # else keep as is
        if state_hop:
            # Toggle state between 'CON' and 'INT' (or stay)
            if self.current_state == 'CON':
                self.current_state = 'INT'
            elif self.current_state == 'INT':
                self.current_state = 'CON'
        self.current_sample["proto"] = self.current_proto
        self.current_sample["state"] = self.current_state

        # 4. Bounds
        self.current_sample["dur"] = max(0.0, float(self.current_sample["dur"]))
        self.current_sample["tot_bytes"] = max(0.0, float(self.current_sample["tot_bytes"]))
        self.current_sample["src_bytes"] = max(0.0, float(self.current_sample["src_bytes"]))
        self.current_sample["tot_pkts"] = max(1.0, float(self.current_sample["tot_pkts"]))

        raw = self._extract_features(self.current_sample)
        prediction = int(self.judge.predict(raw.reshape(1, -1))[0])
        proba = self.judge.predict_proba(raw.reshape(1, -1))[0][1]

        # 5. Reward shaping
        mutation_cost = (abs(byte_delta) * COST_BYTE) + (abs(jitter) * COST_JITTER)

        if prediction == 0:  # Evaded
            reward = REWARD_EVASION - mutation_cost
            evaded = True
            terminated = True
        else:  # Detected
            reward = REWARD_DETECTION - mutation_cost
            evaded = False
            terminated = False

        # Step penalty (encourage quick evasion)
        reward += STEP_PENALTY

        # Confidence bonus: reward for decreasing the judge's confidence in "malicious"
        confidence_reduction = self.initial_proba - proba
        reward += max(0, confidence_reduction) * CONFIDENCE_BONUS_SCALE

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
            "reward": reward,
            "confidence_reduction": confidence_reduction,
        }

        return self._normalize(raw), float(reward), terminated, truncated, info

    def _extract_features(self, sample):
        # Raw feature vector — exactly what the surrogate judge was trained on.
        dur = self._safe_float(sample.get('dur', 0.0))
        tot_pkts = self._safe_float(sample.get('tot_pkts', 1.0))
        tot_bytes = self._safe_float(sample.get('tot_bytes', 40.0))
        src_bytes = self._safe_float(sample.get('src_bytes', 40.0))
        proto_val = sample.get('proto', 'tcp')
        state_val = sample.get('state', 'CON')

        p_encoded = self._encode_value(self.protocol_encoder, proto_val)
        s_encoded = self._encode_value(self.state_encoder, state_val)

        return np.array(
            [dur, tot_pkts, tot_bytes, src_bytes, p_encoded, s_encoded],
            dtype=np.float32,
        )

    @staticmethod
    def _normalize(raw):
        # Scale raw features to [-1, 1] for the agent's observation only.
        normalized = []
        for i, key in enumerate(OBSERVATION_FEATURES):
            low, high = FEATURE_BOUNDS[key]
            if high - low > 1e-12:
                scaled = 2.0 * (raw[i] - low) / (high - low) - 1.0
            else:
                scaled = 0.0
            normalized.append(np.clip(scaled, -1.0, 1.0))
        return np.array(normalized, dtype=np.float32)

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