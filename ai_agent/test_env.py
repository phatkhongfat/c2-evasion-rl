import numpy as np

# sửa import theo project của bạn
from c2_evasion_env import C2EvasionEnv


# malicious_pool phải được tạo giống lúc train
env = C2EvasionEnv(
    malicious_data_pool=malicious_pool,
    max_steps=10,
    debug=True,
)

print("=== TEST ENVIRONMENT ===")

obs, info = env.reset(seed=42)

print("Initial observation:")
print(obs)

print("\nObservation shape:", obs.shape)
print("Observation dtype:", obs.dtype)

print("\nAction space:")
print("low :", env.action_space.low)
print("high:", env.action_space.high)

print("\nObservation space:")
print("shape:", env.observation_space.shape)
