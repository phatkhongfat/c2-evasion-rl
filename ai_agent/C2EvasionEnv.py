import warnings
warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")

import gymnasium as gym
from gymnasium import spaces
import numpy as np
import joblib
import os

class C2EvasionEnv(gym.Env):
    def __init__(self):
        super(C2EvasionEnv, self).__init__()
        
        self.action_space = spaces.Discrete(4)
        self.observation_space = spaces.Box(low=0, high=np.inf, shape=(11,), dtype=np.float32)
        
        # Nạp mô hình IDS
        model_path = '../data/ids_model.pkl'
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Không tìm thấy IDS model tại {model_path}.")
        print("[*] Nạp IDS Model (Random Forest) vào Môi trường RL...")
        self.ids_model = joblib.load(model_path)
        
        # Nạp kho mẫu mã độc thực tế từ dataset
        pool_path = '../data/real_malicious_pool.pkl'
        if not os.path.exists(pool_path):
            raise FileNotFoundError(f"Chưa tìm thấy file kho mẫu real_malicious_pool.pkl! Hãy chạy script trích xuất trước.")
        self.malicious_pool = joblib.load(pool_path)
        print(f"[*] Đã nạp {len(self.malicious_pool)} mẫu mã độc thực tế vào Môi trường RL.")
        
        self.current_state = None
        
    def reset(self, seed=None):
        super().reset(seed=seed)
        
        # Bốc ngẫu nhiên một mẫu mã độc chuẩn từ tập dữ liệu thật 
        # và đảm bảo qua IDS chắc chắn bị tóm ở Action 0
        while True:
            idx = np.random.choice(len(self.malicious_pool))
            self.current_state = self.malicious_pool[idx].astype(np.float32)
            
            pred = self.ids_model.predict(self.current_state.reshape(1, -1))[0]
            if pred == 1: 
                break # Đã tìm được mẫu chuẩn bị IDS phát hiện
            
        return self.current_state, {}

    def step(self, action):
        next_state = self.current_state.copy()
        penalty_cost = 0.0
        
        # Tương ứng với 11 đặc trưng đã chọn, ta cấu hình lại các hành động chèn padding/delay cho phù hợp:
        if action == 1: # Padding nhỏ (ảnh hưởng đến max/mean length)
            next_state[0] += 50.0  # Flow Duration
            next_state[3] += 50.0  # Fwd Packet Length Max
            next_state[5] += 25.0  # Fwd Packet Length Mean
            penalty_cost = -1.0
        elif action == 2: # Padding lớn
            next_state[0] += 500.0
            next_state[3] += 500.0
            next_state[5] += 250.0
            penalty_cost = -5.0
        elif action == 3: # Delay (ảnh hưởng đến các cột Flow IAT)
            next_state[7] += 2.0   # Flow IAT Mean
            next_state[9] += 2.0   # Flow IAT Max
            penalty_cost = -2.0
            
        # Kiểm tra lại với The Judge (IDS)
        features_2d = next_state.reshape(1, -1)
        ids_prediction = self.ids_model.predict(features_2d)[0]
        
        if ids_prediction == 1:
            reward = -50.0
            done = True # Vẫn bị phát hiện -> Phạt nặng
        else:
            reward = 10.0 + penalty_cost
            done = True # Lẩn tránh thành công!
            
        return next_state, float(reward), done, False, {}