# Lưu vào ai_agent/train_agent.py
import os
import warnings
from stable_baselines3 import PPO
from C2EvasionEnv import C2EvasionEnv

# Tắt các cảnh báo phụ từ sklearn để log sạch sẽ
warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")

print("[*] Khởi tạo môi trường C2 Evasion (với kho mẫu mã độc thật)...")
env = C2EvasionEnv()

# Định nghĩa thư mục lưu log cho TensorBoard
log_dir = "../data/tensorboard_logs/"
os.makedirs(log_dir, exist_ok=True)

print("[*] Nạp thuật toán PPO...")
# Sử dụng MlpPolicy, ép chạy trên CPU để đạt hiệu suất tối ưu cho mảng 11 chiều
model = PPO("MlpPolicy", env, verbose=1, tensorboard_log=log_dir, device="cpu")

print("[*] Bắt đầu quá trình huấn luyện (10.000 timesteps)...")
model.learn(total_timesteps=30000)

model_path = "../data/ppo_c2_evasion"
model.save(model_path)
print(f"[+] Huấn luyện hoàn tất! Mô hình đã lưu tại: {model_path}.zip")

# Kiểm thử nhanh mô hình vừa tạo với dữ liệu thực tế
print("\n[*] Chạy thử nghiệm chiến lược ngụy trang đã học:")
obs, info = env.reset()
for i in range(5):
    # Model tự dự đoán hành động tối ưu dựa trên State mã độc thật
    action, _states = model.predict(obs, deterministic=True)
    obs, reward, done, truncated, info = env.step(action)
    print(f"  - Bước {i+1} | Hành động chèn (Action): {action} | Reward: {reward}")
    if done:
        print("  -> Episode kết thúc.")
        break