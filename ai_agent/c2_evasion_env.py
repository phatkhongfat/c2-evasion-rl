import gymnasium as gym
from gymnasium import spaces
import numpy as np
import joblib
import os
import sys
import warnings
from config import (
    SURROGATE_PATH, PROTO_ENCODER_PATH, STATE_ENCODER_PATH,
    MAX_STEPS, FEATURE_BOUNDS,
    REWARD_EVASION, REWARD_DETECTION, STEP_PENALTY,
    CONFIDENCE_BONUS_SCALE, COST_BYTE, COST_JITTER,
    SNORT_PENALTY_SCALE,
    OBSERVATION_FEATURES
)

# Derived (packet-size / IAT / rate / flag) features for the enhanced Snort
# surrogate.  flow_features.py is the single definition of these features and
# is also used by the extraction, validation and data-prep scripts, so the
# reward path and the training path cannot drift apart.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from flow_features import CANDIDATE_FEATURES, derive_flow_features

# Import the verified Snort replica for snort-direct reward training
snort_val_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'snort_validation')
sys.path.insert(0, snort_val_path)
from snort_query_service import replica_snort_verdict

warnings.filterwarnings("ignore", message="X does not have valid feature names")

class C2EvasionEnv(gym.Env):
    metadata = {'render.modes': ['human']}

    def __init__(
        self,
        malicious_data_pool,
        model_path=SURROGATE_PATH,
        proto_encoder_path=PROTO_ENCODER_PATH,
        state_encoder_path=STATE_ENCODER_PATH,
        max_steps=MAX_STEPS,
        snort_surrogate_path=None,
        snort_penalty_scale=SNORT_PENALTY_SCALE,
        snort_feature_names=None,
        snort_direct=False,
        snort_direct_mode="replica"
    ):
        super(C2EvasionEnv, self).__init__()

        self.judge = joblib.load(model_path)
        self.snort_surrogate = None
        self.snort_feature_names = None
        if snort_surrogate_path and os.path.exists(snort_surrogate_path):
            self.snort_surrogate = joblib.load(snort_surrogate_path)
            self.snort_feature_names = self._resolve_snort_features(
                self.snort_surrogate, snort_feature_names)
        self.snort_penalty_scale = snort_penalty_scale
        self.snort_direct = snort_direct
        self.snort_direct_mode = snort_direct_mode
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
        # Clamp to the environment's declared FEATURE_BOUNDS.  The observation
        # normalizer already clips to [-1, 1] against these same bounds, so a
        # value beyond them is indistinguishable from the bound itself to the
        # policy: clamping removes no learnable signal.
        #
        # The upper clamps are also a correctness/safety requirement.  The
        # negative byte_delta branch below multiplies tot_pkts by up to 5x per
        # step, and in snort-direct mode a DETECTED step does not terminate the
        # episode, so ten detected steps drove tot_pkts to 1.9e7.  Materializing
        # that flow in the Snort replica cost 2.4 GB and OOM-killed training
        # (container limit 7 GB, observed anon-rss 4.05 GB).  Bounding the
        # feature is the fix; it also keeps the flow physically plausible.
        self.current_sample["dur"] = float(np.clip(
            self.current_sample["dur"], 0.0, FEATURE_BOUNDS["dur"][1]))
        self.current_sample["tot_bytes"] = float(np.clip(
            self.current_sample["tot_bytes"], 0.0, FEATURE_BOUNDS["tot_bytes"][1]))
        self.current_sample["src_bytes"] = float(np.clip(
            self.current_sample["src_bytes"], 0.0, FEATURE_BOUNDS["src_bytes"][1]))
        self.current_sample["tot_pkts"] = float(np.clip(
            self.current_sample["tot_pkts"], 1.0, FEATURE_BOUNDS["tot_pkts"][1]))

        raw = self._extract_features(self.current_sample)
        prediction = int(self.judge.predict(raw.reshape(1, -1))[0])
        proba = self.judge.predict_proba(raw.reshape(1, -1))[0][1]

        # 5. Reward shaping
        mutation_cost = (abs(byte_delta) * COST_BYTE) + (abs(jitter) * COST_JITTER)

        # Snort-direct reward: use the verified replica instead of XGBoost
        snort_detected = None
        if self.snort_direct:
            snort_detected = replica_snort_verdict(self.current_sample)
            if snort_detected:  # Detected by Snort replica
                reward = REWARD_DETECTION - mutation_cost
                evaded = False
                terminated = False
            else:  # Evaded Snort
                reward = REWARD_EVASION - mutation_cost
                evaded = True
                terminated = True
            confidence_reduction = 0.0  # N/A for snort-direct
        else:
            # Original XGBoost-based reward
            if prediction == 0:  # Evaded
                reward = REWARD_EVASION - mutation_cost
                evaded = True
                terminated = True
            else:  # Detected
                reward = REWARD_DETECTION - mutation_cost
                evaded = False
                terminated = False

            # Confidence bonus: reward for decreasing the judge's confidence in "malicious"
            confidence_reduction = self.initial_proba - proba
            reward += max(0, confidence_reduction) * CONFIDENCE_BONUS_SCALE

        # Step penalty (encourage quick evasion)
        reward += STEP_PENALTY

        truncated = self.current_step >= self.max_steps

        # Defense-aware: penalize flows the Snort surrogate expects to be flagged
        # (only used when NOT in snort-direct mode)
        snort_proba = None
        if not self.snort_direct and self.snort_surrogate is not None:
            snort_vec = self._snort_features(self.current_sample).reshape(1, -1)
            snort_proba = float(self.snort_surrogate.predict_proba(snort_vec)[0][1])
            reward -= self.snort_penalty_scale * snort_proba

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
            "confidence_reduction": (confidence_reduction if not self.snort_direct else None),
            "snort_proba": snort_proba,
            "snort_detected": snort_detected,
            "snort_penalty_scale": (self.snort_penalty_scale
                                    if self.snort_surrogate is not None else None),
            "snort_feature_width": (len(self.snort_feature_names)
                                    if self.snort_feature_names else None),
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

    def _snort_features(self, sample):
        """Feature vector for the Snort surrogate, in its training order.

        The blind (v1) surrogate was trained on the 6 raw flow features; the
        enhanced (v2) surrogate on those 6 plus the selected derived features.
        Which one to build is decided by the loaded model's own
        ``n_features_in_``, so a stale or mismatched model can never be fed a
        silently wrong vector width.
        """
        names = self.snort_feature_names
        if not names:
            return self._extract_features(sample)

        base = self._extract_features(sample)
        base_by_name = {
            'dur': base[0], 'tot_pkts': base[1], 'tot_bytes': base[2],
            'src_bytes': base[3], 'proto_encoded': base[4],
            'state_encoded': base[5],
        }
        derived = derive_flow_features(sample)
        base_by_name.update({k: float(v) for k, v in derived.items()})
        return np.array([base_by_name.get(n, 0.0) for n in names],
                        dtype=np.float32)

    @staticmethod
    def _resolve_snort_features(model, explicit_names):
        """Decide the Snort surrogate's feature order.

        Order of authority:
          1. ``snort_feature_names`` passed by the caller;
          2. the ``snort_feature_names_`` attribute the trainer stamps onto the
             model before saving (authoritative — this is the real order);
          3. the model's own width, but only when that width is the 6-feature
             baseline.
        If the model is wider than the baseline and carries no stamped names we
        RAISE rather than guess: feeding a 16-feature model the wrong 10
        derived features would produce plausible-but-wrong reward shaping, and
        a loud failure is strictly better than a silent one.
        """
        baseline = ['dur', 'tot_pkts', 'tot_bytes', 'src_bytes',
                    'proto_encoded', 'state_encoded']
        width = int(getattr(model, 'n_features_in_', 0) or 0)

        if explicit_names is not None:
            explicit_names = list(explicit_names)
            if width and len(explicit_names) != width:
                raise ValueError(
                    f"snort_feature_names has {len(explicit_names)} entries but "
                    f"the model expects {width}")
            return explicit_names

        stamped = getattr(model, 'snort_feature_names_', None)
        if stamped is not None:
            stamped = list(stamped)
            if width and len(stamped) != width:
                raise ValueError(
                    f"model carries snort_feature_names_ with {len(stamped)} "
                    f"entries but expects {width}")
            return stamped

        if width in (0, len(baseline)):
            return baseline

        raise ValueError(
            f"Snort surrogate expects {width} features but carries no "
            f"snort_feature_names_ attribute; pass snort_feature_names "
            f"explicitly so the feature order is not guessed")

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