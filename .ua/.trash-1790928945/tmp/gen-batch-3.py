#!/usr/bin/env python3
# Build batch-3 GraphNode/GraphEdge output (Vietnamese content).
import json, math, os

OUT = "/root/.hermes/c2-evasion-rl/.ua/intermediate"
BATCH = 3

# file -> (summary, tags, complexity, languageNotes|None)
FILES = {
 "ai_agent/ablate_actions.py": ("Script ablation từng action/mutation đơn lẻ trên các flow C2 thật để đo tác động lên số alert của Snort, hỗ trợ chẩn đoán cơ chế né tránh.", ["entry-point","ablation","evaluation","c2-evasion","snort"], "moderate", None),
 "ai_agent/c2_evasion_env.py": ("Môi trường RL flow-level mô phỏng né Snort: trích xuất đặc trưng flow, dùng surrogate IDS và bộ phân loại judge để chấm điểm, thưởng cho hành vi né tránh.", ["rl-environment","c2-evasion","gymnasium","surrogate","reward-shaping"], "complex", None),
 "ai_agent/callback_metric_proof.py": ("Script chứng minh callback metric: nạp model PPO đã huấn luyện, chạy nhiều episode và thống kê tỷ lệ né tránh để xác thực số liệu.", ["evaluation","proof","ppo","metrics","c2-evasion"], "moderate", None),
 "ai_agent/config.py": ("Tập trung hằng số cấu hình: đường dẫn data/model, đặc trưng observation, reward shaping, chi phí mutation và siêu tham số PPO.", ["configuration","constants","hyperparameters","reward-shaping","paths"], "simple", None),
 "ai_agent/enhanced_packet_level_env.py": ("Biến thể packet-level nâng cao của môi trường RL, nơi TTL, phân mảnh và chồng lấp TCP thực sự ảnh hưởng tới reward qua enhanced replica Snort.", ["rl-environment","packet-level","ttl","fragmentation","c2-evasion"], "moderate", None),
 "ai_agent/eval_cross_capture.py": ("Harness đánh giá cross-capture: huấn luyện trên một capture và đánh giá trên capture khác để kiểm tra khả năng tổng quát hóa của agent.", ["evaluation","cross-capture","generalization","ppo","c2-evasion"], "moderate", None),
 "ai_agent/eval_enhanced_agent.py": ("Đánh giá agent PPO trên EnhancedPacketLevelEnv, thống kê tỷ lệ né tránh và mức thay đổi gói tin qua nhiều episode.", ["evaluation","packet-level","ppo","metrics"], "moderate", None),
 "ai_agent/eval_masked_ppo_test.py": ("Script kiểm thử agent MaskablePPO trên HiddenDefenderEnv, đếm tần suất chọn từng cơ chế né tránh và ghi kết quả JSON.", ["evaluation","maskable-ppo","hidden-defender","mechanism-analysis"], "moderate", None),
 "ai_agent/eval_packet_level_agent.py": ("Đánh giá agent packet-level PPO so với baseline ngẫu nhiên trên Snort replica với 80 episode cố định seed, ghi báo cáo JSON.", ["evaluation","packet-level","ppo","baseline","snort"], "moderate", None),
 "ai_agent/eval_real_snort_agent.py": ("Đánh giá agent PPO chống lại Snort thật: đo số alert trước/sau mutation và so sánh với mutation ngẫu nhiên, xuất báo cáo JSON.", ["evaluation","real-snort","packet-level","ppo","reporting"], "moderate", None),
 "ai_agent/evaluate.py": ("Cung cấp hàm nạp test pool các flow botnet từ dữ liệu parquet để phục vụ đánh giá.", ["utility","data-loading","test-pool","evaluation"], "moderate", None),
 "ai_agent/evasion_metrics_callback.py": ("Callback Stable-Baselines3 ghi các metric né tránh (evasion, padding, jitter, độ dài episode) vào logger trong quá trình huấn luyện.", ["callback","metrics","monitoring","training","stable-baselines3"], "moderate", None),
 "ai_agent/flow_features.py": ("Suy diễn các đặc trưng flow cấp cao (tỷ lệ gói, entropy payload, cờ TCP) từ flow thô để cấp cho surrogate Snort và candidate vector.", ["feature-engineering","flow-features","utility","c2-evasion"], "moderate", None),
 "ai_agent/hidden_defender_env.py": ("Môi trường RL 14 cơ chế né tránh (hidden defender): biến đổi gói tin C2 thật, kiểm tra ngữ nghĩa còn nguyên vẹn và chấm điểm bằng Snort thật, có action masking.", ["rl-environment","hidden-defender","packet-mutation","action-masking","c2-evasion"], "complex", None),
 "ai_agent/packet_level_env.py": ("Môi trường RL packet-level dùng PacketModifier để biến đổi gói tin và replica_snort_verdict để chấm điểm né tránh.", ["rl-environment","packet-level","packet-mutation","snort-replica"], "moderate", None),
 "ai_agent/packet_modifier.py": ("Lớp tiện ích áp dụng action lên danh sách gói tin và chuyển kết quả thành đặc trưng flow.", ["utility","packet-mutation","feature-extraction"], "moderate", None),
 "ai_agent/pool_loader.py": ("Nạp pool flow botnet từ kho parquet, lọc theo nhãn botnet và chuẩn hóa tên cột thành các flow dùng cho huấn luyện.", ["data-loading","utility","botnet-pool","preprocessing"], "moderate", None),
 "ai_agent/real_packet_env.py": ("Môi trường RL packet-level thao tác trên PCAP thật: nạp flow, áp mutation, hỏi SnortBatchService và tính reward dựa trên alert thật.", ["rl-environment","packet-level","pcap","real-snort","batch-service"], "complex", None),
 "ai_agent/snort_bandit.py": ("Bandit policy-gradient học mặt nạ corrupt gói tin để né Snort thật, kèm baseline ngẫu nhiên và phân tích chi phí/hiệu quả.", ["bandit","policy-gradient","c2-evasion","real-snort","experiment"], "complex", None),
 "ai_agent/train_agent.py": ("Script huấn luyện PPO trên C2EvasionEnv với các tham số dòng lệnh cấu hình timesteps và đường dẫn model.", ["training","ppo","c2-evasion","entry-point"], "moderate", None),
 "ai_agent/train_enhanced.py": ("Huấn luyện PPO trên EnhancedPacketLevelEnv để TTL/phân mảnh/chồng lấp ảnh hưởng tới reward, có checkpoint và metadata.", ["training","ppo","packet-level","enhanced","entry-point"], "moderate", None),
 "ai_agent/train_enhanced_packet_agent.py": ("Huấn luyện PPO agent với EnhancedPacketLevelEnv, lưu checkpoint và metadata huấn luyện.", ["training","ppo","packet-level","enhanced","entry-point"], "moderate", None),
 "ai_agent/train_hidden_defender_ppo.py": ("Huấn luyện MaskablePPO trên HiddenDefenderEnv với BatchEnv bọc và QueryCounter theo dõi số truy vấn Snort.", ["training","maskable-ppo","hidden-defender","action-masking","entry-point"], "moderate", None),
 "ai_agent/train_packet_level_agent.py": ("Huấn luyện PPO agent packet-level với reward từ replica Snort (không dùng surrogate), lưu model và metadata.", ["training","ppo","packet-level","snort-replica","entry-point"], "moderate", None),
 "ai_agent/train_packet_level_tcp10.py": ("Huấn luyện PPO packet-level trên tập con TCP có >=10 gói để có tín hiệu sạch hơn, lưu model và metadata.", ["training","ppo","packet-level","tcp10","entry-point"], "moderate", None),
}

# (path, kind, name, lineRange, summary, tags, complexity)
SUBS = [
 ("ai_agent/ablate_actions.py","function","run",[31,56],"Áp dụng một mutation đơn lẻ với cường độ và tỷ lệ chỉ định lên flow, chấm điểm qua Snort replica và trả về số alert.",["ablation","mutation","scoring"],"moderate"),
 ("ai_agent/ablate_actions.py","function","main",[59,104],"Chạy ablation toàn bộ action space trên tập flow, in bảng so sánh số alert so với baseline và mutation ngẫu nhiên.",["entry-point","ablation","reporting"],"moderate"),
 ("ai_agent/c2_evasion_env.py","class","C2EvasionEnv",[31,363],"Lớp Gymnasium flow-level với action space liên tục gồm byte padding, jitter và thay đổi đặc trưng; dùng surrogate Snort và bộ phân loại judge để tính reward evasion.",["rl-environment","surrogate","reward-shaping","gymnasium"],"complex"),
 ("ai_agent/callback_metric_proof.py","function","main",[22,84],"Nạp pool botnet và model PPO, chạy các episode đánh giá, tổng hợp cờ phát hiện và tỷ lệ né tránh để kiểm chứng metric của callback.",["proof","metrics","ppo","evaluation"],"moderate"),
 ("ai_agent/enhanced_packet_level_env.py","class","EnhancedPacketLevelEnv",[20,163],"Môi trường packet-level dùng PacketModifier và enhanced_replica_snort_verdict để phạt/thưởng theo TTL, phân mảnh và chồng lấp gói tin.",["rl-environment","packet-level","ttl","fragmentation"],"moderate"),
 ("ai_agent/eval_cross_capture.py","function","eval_policy",[38,69],"Chạy policy trên pool chỉ định trong nhiều episode, so sánh né tránh giữa agent và baseline ngẫu nhiên.",["evaluation","policy","generalization"],"moderate"),
 ("ai_agent/eval_cross_capture.py","function","main",[72,137],"Chia dữ liệu theo capture train/eval, nạp model PPO và chạy đánh giá chéo rồi ghi báo cáo JSON.",["entry-point","cross-capture","reporting"],"moderate"),
 ("ai_agent/eval_enhanced_agent.py","function","eval_policy",[36,74],"Chạy policy trên môi trường enhanced trong n episode, ghi lại kết quả phát hiện và biến đổi gói tin.",["evaluation","packet-level","metrics"],"moderate"),
 ("ai_agent/eval_masked_ppo_test.py","function","main",[28,84],"Nạp model MaskablePPO, chạy các flow với action mask, thống kê cơ chế được chọn và xuất báo cáo JSON.",["entry-point","maskable-ppo","mechanism-analysis"],"moderate"),
 ("ai_agent/eval_real_snort_agent.py","function","main",[30,102],"Chạy agent và baseline ngẫu nhiên trên các flow thật qua SnortBatchService, tổng hợp alert counts và ghi báo cáo.",["entry-point","real-snort","reporting"],"moderate"),
 ("ai_agent/evaluate.py","function","load_test_pool",[8,27],"Đọc và gộp các file parquet, lọc các dòng nhãn botnet và chuẩn hóa thành danh sách flow phục vụ đánh giá.",["data-loading","test-pool","utility"],"simple"),
 ("ai_agent/evasion_metrics_callback.py","class","EvasionMetricsCallback",[4,66],"Kế thừa BaseCallback, thu thập info từ mỗi bước và ghi trung bình các metric né tránh vào TensorBoard/logger.",["callback","metrics","stable-baselines3"],"moderate"),
 ("ai_agent/flow_features.py","function","_f",[98,105],"Chuyển giá trị sang float an toàn, trả về mặc định khi giá trị thiếu hoặc không hợp lệ.",["utility","numeric-safety"],"simple"),
 ("ai_agent/flow_features.py","function","derive_flow_features",[108,195],"Tính toán bộ đặc trưng flow dẫn xuất (kích thước, tốc độ, entropy, cờ TCP, tỷ lệ hướng) từ một flow thô.",["feature-engineering","flow-features"],"complex"),
 ("ai_agent/flow_features.py","function","candidate_vector",[198,201],"Tạo vector đặc trưng theo thứ tự feature_names từ flow, phục vụ surrogate/judge.",["utility","feature-extraction"],"simple"),
 ("ai_agent/hidden_defender_env.py","function","payloads_of",[90,91],"Trích xuất danh sách payload bytes từ các gói tin.",["utility","payload"],"simple"),
 ("ai_agent/hidden_defender_env.py","function","framing_of",[94,98],"Phát hiện kiểu framing của chuỗi payload sau khi ghép.",["framing","utility"],"simple"),
 ("ai_agent/hidden_defender_env.py","function","semantics_intact",[101,140],"Kiểm tra lệnh C2 gốc vẫn được parse đúng sau khi biến đổi để đảm bảo ngữ nghĩa không đổi.",["validation","semantics","c2"],"moderate"),
 ("ai_agent/hidden_defender_env.py","function","mech_applicable",[143,157],"Xác định một cơ chế né tránh có áp dụng được cho framing hiện tại hay không.",["action-masking","validation"],"moderate"),
 ("ai_agent/hidden_defender_env.py","function","apply_mech",[160,276],"Áp dụng một cơ chế biến đổi (phân mảnh, chồng lấp, TTL, padding...) lên danh sách gói và trả về gói đã sửa.",["packet-mutation","fragmentation","c2-evasion"],"complex"),
 ("ai_agent/hidden_defender_env.py","function","load_corpus",[279,282],"Nạp corpus flow đã đóng gói (pickle) theo split train/test.",["data-loading","utility"],"simple"),
 ("ai_agent/hidden_defender_env.py","class","HiddenDefenderEnv",[285,417],"Môi trường Gymnasium với 14 cơ chế né tránh, action mask động, kiểm tra ngữ nghĩa và chấm điểm bằng SnortBatchService thật.",["rl-environment","hidden-defender","action-masking","c2-evasion"],"complex"),
 ("ai_agent/packet_level_env.py","class","PacketLevelEnv",[20,195],"Môi trường Gymnasium packet-level: action MultiDiscrete điều khiển TTL, phân mảnh, padding; reward từ replica Snort.",["rl-environment","packet-level","packet-mutation","snort-replica"],"moderate"),
 ("ai_agent/packet_modifier.py","class","PacketModifier",[10,85],"Áp dụng các action (TTL, phân mảnh, chồng lấp, padding) lên gói tin và tính đặc trưng flow sau biến đổi.",["utility","packet-mutation","feature-extraction"],"moderate"),
 ("ai_agent/pool_loader.py","function","load_malicious_pool",[35,83],"Quét các file parquet trong archive, lọc flow botnet, đổi tên cột và trả về danh sách flow đã chuẩn hóa.",["data-loading","botnet-pool","preprocessing"],"moderate"),
 ("ai_agent/real_packet_env.py","function","_capture_pcap",[74,84],"Tìm file PCAP tương ứng với tên capture trong các thư mục dữ liệu.",["utility","pcap","data-loading"],"simple"),
 ("ai_agent/real_packet_env.py","function","corruptable",[100,107],"Xác định gói tin có thể bị corrupt (có payload) hay không.",["utility","packet-mutation"],"simple"),
 ("ai_agent/real_packet_env.py","function","payload_indices",[110,112],"Trả về chỉ số các gói có payload có thể biến đổi.",["utility","payload"],"simple"),
 ("ai_agent/real_packet_env.py","function","_capture_dir_for",[115,118],"Xác định thư mục chứa capture.",["utility","pcap"],"simple"),
 ("ai_agent/real_packet_env.py","class","RealPacketEnv",[121,541],"Môi trường Gymnasium với action MultiDiscrete cho TTL/phân mảnh/chồng lấp/padding; dùng SnortBatchService để chấm điểm alert và reward né tránh.",["rl-environment","packet-level","real-snort","pcap"],"complex"),
 ("ai_agent/snort_bandit.py","function","break_even_cost",[91,104],"Tính chi phí corrupt hòa vốn dựa trên số gói có thể sửa.",["utility","cost-analysis"],"moderate"),
 ("ai_agent/snort_bandit.py","function","write_json_atomic",[107,113],"Ghi JSON nguyên tử (ghi file tạm rồi replace) để tránh hỏng file.",["utility","serialization"],"simple"),
 ("ai_agent/snort_bandit.py","function","corrupt_targets",[119,128],"Xác định các gói mục tiêu từ mặt nạ corrupt.",["utility","packet-mutation"],"simple"),
 ("ai_agent/snort_bandit.py","function","apply_corrupt_mask",[131,159],"Áp dụng mặt nạ corrupt lên danh sách gói, sửa byte payload trong giới hạn cho phép.",["packet-mutation","c2-evasion"],"moderate"),
 ("ai_agent/snort_bandit.py","function","prefix_entropy",[162,176],"Tính entropy của n byte đầu payload.",["utility","entropy","features"],"moderate"),
 ("ai_agent/snort_bandit.py","function","packet_features",[179,245],"Trích xuất vector đặc trưng gói tin (kích thước, inter-arrival, entropy) làm input cho policy.",["feature-engineering","packet-level"],"complex"),
 ("ai_agent/snort_bandit.py","class","PacketPolicy",[251,268],"Mạng neural nhỏ xuất logits Bernoulli cho từng gói; sample mặt nạ corrupt và tính log-prob.",["policy","neural-network","bandit"],"simple"),
 ("ai_agent/snort_bandit.py","function","score",[271,283],"Chấm điểm né tránh cho một lô flow qua SnortBatchService, có thể khởi động lại service.",["scoring","real-snort"],"moderate"),
 ("ai_agent/snort_bandit.py","function","control_evasion",[286,295],"Chạy đối chứng baseline với hàm mặt nạ cho trước để so sánh né tránh.",["baseline","evaluation"],"moderate"),
 ("ai_agent/snort_bandit.py","function","run_bandit",[298,417],"Vòng lặp huấn luyện bandit policy-gradient qua nhiều round, tính reward từ alert Snort và ghi lịch sử.",["bandit","policy-gradient","training"],"complex"),
 ("ai_agent/snort_bandit.py","function","load_env",[420,427],"Tạo RealPacketEnv cho một capture với số flow và batch chỉ định.",["utility","environment"],"simple"),
 ("ai_agent/snort_bandit.py","function","run_configs",[430,480],"Chạy bandit cho nhiều cấu hình (chi phí, scale, capture) và tổng hợp kết quả.",["experiment","orchestration"],"moderate"),
 ("ai_agent/snort_bandit.py","function","main",[483,583],"Điểm vào CLI: parse tham số, khởi động ResidentSnortService, chạy sweep cấu hình và xuất báo cáo JSON.",["entry-point","cli","reporting"],"complex"),
 ("ai_agent/train_agent.py","function","parse_args",[32,47],"Định nghĩa và parse các tham số CLI cho quá trình huấn luyện (timesteps, seed, đường dẫn model).",["cli","configuration"],"moderate"),
 ("ai_agent/train_hidden_defender_ppo.py","class","BatchEnv",[39,74],"Lớp bọc môi trường HiddenDefenderEnv để hỗ trợ huấn luyện theo batch và chuyển tiếp action mask.",["wrapper","rl-environment"],"moderate"),
 ("ai_agent/train_hidden_defender_ppo.py","class","QueryCounter",[77,95],"Callback đếm số truy vấn Snort và theo dõi các flow đã giải quyết trong quá trình học.",["callback","monitoring"],"moderate"),
 ("ai_agent/train_hidden_defender_ppo.py","function","main",[98,162],"Điểm vào huấn luyện: tạo BatchEnv, MaskablePPO, chạy learn và lưu model cùng báo cáo JSON.",["entry-point","training","maskable-ppo"],"complex"),
]

nodes = []
edges = []

def fnode(path, s, tags, cx, ln=None):
    n = {"id": f"file:{path}", "type": "file", "name": os.path.basename(path),
         "filePath": path, "summary": s, "tags": tags, "complexity": cx}
    if ln: n["languageNotes"] = ln
    return n

def snode(path, kind, name, lr, s, tags, cx):
    return {"id": f"{kind}:{path}:{name}", "type": kind, "name": name, "filePath": path,
            "lineRange": lr, "summary": s, "tags": tags, "complexity": cx}

# Build all nodes and edges
by_file = {}
for path,(s,tags,cx,ln) in FILES.items():
    fn = fnode(path,s,tags,cx,ln)
    nodes.append(fn)
    by_file[path] = fn

for (path,kind,name,lr,s,tags,cx) in SUBS:
    sn = snode(path,kind,name,lr,s,tags,cx)
    nodes.append(sn)
    edges.append({"source":f"file:{path}","target":sn["id"],"type":"contains","direction":"forward","weight":1.0})
    edges.append({"source":f"file:{path}","target":sn["id"],"type":"exports","direction":"forward","weight":0.8})

# Batch import data is empty -> zero imports edges.
print("total nodes", len(nodes), "total edges", len(edges))

# Partition
paths_sorted = sorted(FILES.keys())
N = len(paths_sorted)
parts = math.ceil(max(len(nodes)/60, len(edges)/120))
chunk = math.ceil(N/parts)
print("parts", parts, "chunk", chunk)

for k in range(parts):
    group = set(paths_sorted[k*chunk:(k+1)*chunk])
    pnodes = [n for n in nodes if (n.get("filePath") in group)]
    pids = {n["id"] for n in pnodes}
    pedges = [e for e in edges if e["source"] in pids]
    out = {"nodes": pnodes, "edges": pedges}
    fp = os.path.join(OUT, f"batch-{BATCH}-part-{k+1}.json")
    with open(fp, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    print("wrote", fp, "nodes", len(pnodes), "edges", len(pedges))
