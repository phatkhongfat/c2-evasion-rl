import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "..", "data")
MODEL_DIR = os.path.join(BASE_DIR, "..", "models")
ARCHIVE_DIR = os.path.join(DATA_DIR, "archive")

SURROGATE_PATH = os.path.join(DATA_DIR, "surrogate_ids_ctu13.pkl")
PROTO_ENCODER_PATH = os.path.join(DATA_DIR, "label_encoder_proto.pkl")
STATE_ENCODER_PATH = os.path.join(DATA_DIR, "label_encoder_state.pkl")

MAX_STEPS = 10
OBSERVATION_FEATURES = ['dur', 'tot_pkts', 'tot_bytes', 'src_bytes', 'proto', 'state']

# Approximate min/max for normalization (derived from data exploration)
FEATURE_BOUNDS = {
    'dur': (0, 1000),
    'tot_pkts': (1, 10000),
    'tot_bytes': (40, 1_000_000),
    'src_bytes': (40, 1_000_000),
    'proto': (0, 1),
    'state': (0, 1),
}

# Reward shaping
REWARD_EVASION = 50.0
REWARD_DETECTION = -2.0
STEP_PENALTY = -0.1
CONFIDENCE_BONUS_SCALE = 0.1

# Mutation costs
COST_BYTE = 0.01
COST_JITTER = 0.1
COST_PADDING_AFTER_EVASION = 0.5  # Penalize padding once Snort is evaded (snort-direct mode)

# Defense-aware reward shaping (Snort surrogate)
SNORT_SURROGATE_PATH = os.path.join(DATA_DIR, "snort_surrogate.pkl")
SNORT_SURROGATE_ENHANCED_PATH = os.path.join(DATA_DIR, "snort_surrogate_enhanced.pkl")
SNORT_PENALTY_SCALE = 20.0   # < REWARD_EVASION (50); keep evasion net-positive

# PPO Hyperparameters (tuned)
PPO_LEARNING_RATE = 1e-4
PPO_N_STEPS = 256
PPO_BATCH_SIZE = 16
PPO_GAMMA = 0.99
PPO_ENT_COEF = 0.01
PPO_CLIP_RANGE = 0.2
TOTAL_TIMESTEPS = 50_000