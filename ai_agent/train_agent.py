import os
import glob
import pandas as pd
from stable_baselines3 import PPO
from stable_baselines3.common.env_checker import check_env
from c2_evasion_env import C2EvasionEnv
from evasion_metrics_callback import EvasionMetricsCallback

def load_malicious_pool():
    print("[*] Đang nạp tập dữ liệu mẫu mã độc từ thư mục data/archive...")
    dataset_path = os.path.expanduser('~/Projects/c2-evasion-rl/data/archive/*.parquet')
    file_paths = glob.glob(dataset_path)
    
    if len(file_paths) == 0:
        file_paths = glob.glob('../data/archive/*.parquet')
        
    if len(file_paths) == 0:
        raise FileNotFoundError("Không tìm thấy tệp .parquet nào trong thư mục dữ liệu.")
        
    df_list = [pd.read_parquet(file) for file in file_paths]
    df = pd.concat(df_list, ignore_index=True)
    
    # Tìm cột Label (CTU-13 gốc thường viết hoa chữ L)
    label_col = 'Label' if 'Label' in df.columns else 'label'
    
    if label_col in df.columns:
        malicious_df = df[df[label_col].astype(str).str.lower().str.contains('botnet')].copy()
    else:
        raise KeyError("Không tìm thấy cột 'Label' hoặc 'label' trong dữ liệu.")
        
    # Ánh xạ về ĐÚNG 6 tên cột để Environment trích xuất
    feature_mapping = {
        'Dur': 'dur',
        'TotPkts': 'tot_pkts',
        'TotBytes': 'tot_bytes',
        'SrcBytes': 'src_bytes',
        'Proto': 'proto',
        'State': 'state'
    }
    malicious_df = malicious_df.rename(columns=feature_mapping)
    
    malicious_pool = malicious_df.to_dict(orient='records')
    print(f"[+] Đã trích xuất thành công {len(malicious_pool)} mẫu mã độc vào bộ nhớ huấn luyện.")
    return malicious_pool

if __name__ == "__main__":
    malicious_pool = load_malicious_pool()
    
    # Khởi tạo kèm khai báo minh bạch đường dẫn model (đặt trong thư mục data)
    env = C2EvasionEnv(
        malicious_data_pool=malicious_pool,
        model_path="../data/surrogate_ids_ctu13.pkl",
        proto_encoder_path="../data/label_encoder_proto.pkl",
        state_encoder_path="../data/label_encoder_state.pkl",
        max_steps=10
    )
    
    print("[*] Đang kiểm tra tính tương thích của môi trường Gymnasium...")
    check_env(env, warn=True)
    print("[+] Môi trường hoàn toàn hợp lệ!")
    
    print("[*] Đang khởi tạo mô hình PPO Agent...")
    print("[*] Đang khởi tạo mô hình PPO Agent trên CPU...")
    model = PPO(
        "MlpPolicy",
        env,
        learning_rate=3e-4,
        n_steps=2048,
        batch_size=64,
        gamma=0.95,
        verbose=1,
        tensorboard_log="./c2_ppo_tensorboard/",
        device="cpu"  # Ép PPO chạy hoàn toàn bằng CPU
    )
    
    callback = EvasionMetricsCallback()
    
    print("[*] Bắt đầu quá trình huấn luyện PPO Agent đối đầu với The Judge...")
    # Chạy 50k steps để theo dõi đường Evasion Success Rate trên TensorBoard
    model.learn(total_timesteps=50_000, callback=callback)
    
    os.makedirs("../models", exist_ok=True)
    model_save_path = "../models/ppo_c2_evasion_agent"
    model.save(model_save_path)
    print(f"[+] Huấn luyện hoàn tất! Đã lưu trọng số PPO Agent tại: {model_save_path}.zip")