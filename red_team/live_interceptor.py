from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, Raw
from stable_baselines3 import PPO
import numpy as np
import joblib
import os
import time

print("[*] Đang khởi động Live Traffic Interceptor & IDS Guard...")

# 1. Nạp mô hình IDS (The Judge)
ids_path = '/home/phatkhongfat/Projects/c2-evasion-rl/data/ids_model.pkl'
ids_model = joblib.load(ids_path)

# 2. Nạp bộ não PPO (Red Team AI Agent)
ppo_path = '/home/phatkhongfat/Projects/c2-evasion-rl/data/ppo_c2_evasion.zip'
ai_model = PPO.load(ppo_path)

# Bộ nhớ tạm để theo dõi thời gian giữa các gói tin (phục vụ tính toán IAT)
last_packet_time = time.time()

def process_live_packet(packet):
    global last_packet_time
    scapy_pkt = IP(packet.get_payload())
    
    # Chỉ xử lý các gói tin TCP có dữ liệu (Payload)
    if scapy_pkt.haslayer(TCP) and scapy_pkt.haslayer(Raw):
        current_time = time.time()
        iat = current_time - last_packet_time
        last_packet_time = current_time
        
        pkt_len = float(len(scapy_pkt))
        payload_len = float(len(scapy_pkt[Raw].load))
        
        # --- BƯỚC 1: XÂY DỰNG VECTOR 11 ĐẶC TRƯNG TỪ LIVE PACKET ---
        # Khớp chính xác 11 cột mà IDS yêu cầu
        live_features = np.array([
            float(iat * 1000000.0),      # Flow Duration (giả lập dựa trên IAT microsecond)
            1.0,                         # Total Fwd Packets
            payload_len,                 # Total Length of Fwd Packets
            pkt_len,                     # Fwd Packet Length Max
            pkt_len,                     # Fwd Packet Length Min
            pkt_len,                     # Fwd Packet Length Mean
            0.0,                         # Fwd Packet Length Std
            float(iat),                  # Flow IAT Mean
            0.0,                         # Flow IAT Std
            float(iat),                  # Flow IAT Max
            float(iat)                   # Flow IAT Min
        ], dtype=np.float32)
        
        # --- BƯỚC 2: HỎI Ý KIẾN AI AGENT (PPO) XEM CÓ CẦN NGỤY TRANG KHÔNG ---
        action, _ = ai_model.predict(live_features, deterministic=True)
        
        modified_features = live_features.copy()
        
        if action == 1:
            # AI chọn chèn Padding nhỏ
            scapy_pkt[Raw].load += b"X" * 50
            modified_features[0] += 50.0
            modified_features[2] += 50.0
            print(f"[AI Action 1] Chèn 50 bytes padding cho live packet.")
        elif action == 2:
            # AI chọn chèn Padding lớn
            scapy_pkt[Raw].load += b"X" * 500
            modified_features[0] += 500.0
            modified_features[2] += 500.0
            print(f"[AI Action 2] Chèn 500 bytes padding cho live packet.")
        else:
            print(f"[AI Action 0] Giữ nguyên gói tin live.")

        # --- BƯỚC 3: KIỂM TRA TRỰC TIẾP QUA IDS (RANDOM FOREST) ---
        features_2d = modified_features.reshape(1, -1)
        ids_prediction = ids_model.predict(features_2d)[0]
        
        if ids_prediction == 1:
            print(f"[!] IDS PHÁT HIỆN: Live traffic bị gắn nhãn ĐỘC HẠI (1)!")
        else:
            print(f"[+] IDS AN TOÀN: Live traffic đã qua mặt thành công (0)!")

        # --- BƯỚC 4: TÍNH TOÁN LẠI CHECKSUM VÀ CHO PHÉP QUA MẠNG ---
        if scapy_pkt.haslayer(IP):
            del scapy_pkt[IP].len
            del scapy_pkt[IP].chksum
        if scapy_pkt.haslayer(TCP):
            del scapy_pkt[TCP].chksum
            
        packet.set_payload(bytes(scapy_pkt))
        
    packet.accept()

# Gắn kết vào NetfilterQueue số 1
nfqueue = NetfilterQueue()
nfqueue.bind(1, process_live_packet)

try:
    print("[*] Đang bắt live traffic qua NFQUEUE số 1. Nhấn Ctrl+C để thoát.")
    nfqueue.run()
except KeyboardInterrupt:
    print("\n[*] Đang gỡ bỏ cấu hình hàng đợi...")
    nfqueue.unbind()
