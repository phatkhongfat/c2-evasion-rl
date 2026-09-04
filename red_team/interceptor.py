from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, Raw
from stable_baselines3 import PPO
import numpy as np

# 1. Nạp bộ não AI đã train xong vào bộ nhớ RAM của Interceptor
print("[*] Đang nạp mô hình PPO Evasion Agent vào Interceptor...")
ai_model = PPO.load("/home/phatkhongfat/Projects/c2-evasion-rl/data/ppo_c2_evasion")

def process_packet(packet):
    scapy_pkt = IP(packet.get_payload())
    
    if scapy_pkt.haslayer(TCP) and scapy_pkt.haslayer(Raw):
        original_len = len(scapy_pkt)
        
        # 2. Trích xuất đặc trưng gói tin thực tế (11 thông số khớp với Observation Space)
        # (Ở đây ta mô phỏng trích xuất từ packet thật, hoặc dựng vector 11 chiều tương ứng)
        current_state = np.array([
            float(len(scapy_pkt)), 1.0, float(len(scapy_pkt)), float(len(scapy_pkt)), 
            40.0, 80.0, 20.0, 0.01, 0.001, 0.02, 0.005
        ], dtype=np.float32)
        
        # 3. Hỏi ý kiến "Bộ não AI" xem nên chọn hành động nào
        action, _states = ai_model.predict(current_state, deterministic=True)
        
        # 4. Thực thi hành động do AI chỉ định lên gói tin mạng thật
        if action == 1:
            # Action 1: Padding nhỏ
            scapy_pkt[Raw].load += b"X" * 50
            print(f"[AI Decision] Action 1 (Padding nhỏ) -> Biến đổi gói tin từ {original_len} lên {len(scapy_pkt)} bytes")
        elif action == 2:
            # Action 2: Padding lớn
            scapy_pkt[Raw].load += b"X" * 500
            print(f"[AI Decision] Action 2 (Padding lớn) -> Biến đổi gói tin từ {original_len} lên {len(scapy_pkt)} bytes")
        elif action == 3:
            # Action 3: Bỏ qua / Không đổi kích thước (hoặc Delay)
            print(f"[AI Decision] Action 3/0 (Giữ nguyên hoặc Delay) -> Bỏ qua.")
        else:
            print(f"[AI Decision] Action 0 -> Giữ nguyên gói tin.")

        # 5. Tính toán lại Checksum để gói tin không bị hủy ở tầng Network
        if scapy_pkt.haslayer(IP):
            del scapy_pkt[IP].len
            del scapy_pkt[IP].chksum
        if scapy_pkt.haslayer(TCP):
            del scapy_pkt[TCP].chksum
            
        packet.set_payload(bytes(scapy_pkt))
        
    packet.accept()

# Khởi động NetfilterQueue bắt gói tin qua iptables
nfqueue = NetfilterQueue()
nfqueue.bind(1, process_packet)
try:
    print("[*] Interceptor đang hoạt động với trí thông minh nhân tạo. Nhấn Ctrl+C để dừng.")
    nfqueue.run()
except KeyboardInterrupt:
    print("\n[*] Đang dọn dẹp NetfilterQueue...")
    nfqueue.unbind()