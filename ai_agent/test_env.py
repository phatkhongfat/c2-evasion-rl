from C2EvasionEnv import C2EvasionEnv

# Khởi tạo môi trường độc lập
env = C2EvasionEnv()

print("--- Đang test trực tiếp hàm reset() ---")
# Gọi reset thủ công để xem lệnh print [DEBUG] có hiện ra không
obs, info = env.reset()
print(f"Trạng thái ban đầu được cấp phát thành công! Shape: {obs.shape}")