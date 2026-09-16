import os
import glob
import pandas as pd
import numpy as np
from stable_baselines3 import PPO
from c2_evasion_env import C2EvasionEnv

def load_test_pool():
    # Sử dụng logic nạp dữ liệu giống hệt lúc train
    # Use relative paths from script directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    base_dir = os.path.dirname(script_dir)
    dataset_path = os.path.join(base_dir, 'data', 'archive', '*.parquet')
    file_paths = glob.glob(dataset_path)
        
    df_list = [pd.read_parquet(file) for file in file_paths]
    df = pd.concat(df_list, ignore_index=True)
    
    label_col = 'Label' if 'Label' in df.columns else 'label'
    malicious_df = df[df[label_col].astype(str).str.lower().str.contains('botnet')].copy()
    
    feature_mapping = {
        'Dur': 'dur', 'TotPkts': 'tot_pkts', 'TotBytes': 'tot_bytes',
        'SrcBytes': 'src_bytes', 'Proto': 'proto', 'State': 'state'
    }
    malicious_df = malicious_df.rename(columns=feature_mapping)
    return malicious_df.to_dict(orient='records')

if __name__ == "__main__":
    print("[*] Đang nạp dữ liệu kiểm thử (Test Set)...")
    test_pool = load_test_pool()
    
    print("[*] Đang khởi tạo môi trường...")
    env = C2EvasionEnv(
        malicious_data_pool=test_pool,
        model_path="../data/surrogate_ids_ctu13.pkl",
        proto_encoder_path="../data/label_encoder_proto.pkl",
        state_encoder_path="../data/label_encoder_state.pkl",
        max_steps=10
    )
    
    model_path = "../models/ppo_c2_evasion_agent.zip"
    print(f"[*] Đang tải trọng số mô hình từ: {model_path}")
    try:
        model = PPO.load(model_path, env=env, device="cpu")
    except Exception as e:
        print(f"[-] Lỗi khi tải mô hình: {e}")
        exit()

    print("\n" + "="*60)
    print(" BẮT ĐẦU KIỂM CHỨNG PPO AGENT TRÊN 80 MẪU NGẪU NHIÊN")
    print("="*60)

    num_episodes = 80
    success_count = 0

    for i in range(num_episodes):
        # 1. Khởi tạo một mẫu mã độc mới
        obs, info = env.reset()
        done = False
        truncated = False
        step_count = 0
        
        # 2. Vòng lặp cho phép Agent hành động
        while not done and not truncated:
            # deterministic=True: Ép Agent dùng chiến thuật thông minh nhất, không thử ngẫu nhiên
            action, _states = model.predict(obs, deterministic=True)
            obs, reward, done, truncated, info = env.step(action)
            step_count += 1
            
        # 3. Trích xuất và in báo cáo chiến thuật
        evaded = info.get("evasion_success", 0) == 1
        jitter = info.get("total_jitter", 0.0)
        padding = info.get("total_padding", 0.0)
        proto_hop = info.get("proto_hop", False)
        state_hop = info.get("state_hop", False)
        
        print(f"\n[Mẫu {i+1:02d}] Kết quả: {'✅ BỎ LỌT (Bypass)' if evaded else '❌ BỊ TÓM (Blocked)'}")
        print(f" ├─ Số bước thực hiện : {step_count}/{env.max_steps}")
        print(f" ├─ Jitter áp dụng    : {jitter:+.2f} giây")
        print(f" ├─ Padding áp dụng   : {padding:+.2f} bytes")
        print(f" ├─ Nhảy Giao thức    : {'🔥 CÓ (Chuyển sang TCP)' if proto_hop else 'Không'}")
        print(f" ├─ Nhảy Trạng thái   : {'🔥 CÓ (Chuyển sang CON)' if state_hop else 'Không'}")
        
        if evaded:
            success_count += 1

    print("\n" + "="*60)
    print(f"TỔNG KẾT: Tỷ lệ Evasion Thành công = {success_count}/{num_episodes} ({(success_count/num_episodes)*100:.1f}%)")
    print("="*60)