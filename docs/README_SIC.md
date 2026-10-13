# C2 Evasion RL — README theo khung SIC CRISP-DM

> **Tiếng Việt** (thuật ngữ kỹ thuật giữ nguyên tiếng Anh).
> Bản tiếng Anh: [`../README.md`](../README.md). Bản tiếng Việt đầy đủ: [`../README.vi.md`](../README.vi.md).
> Luận văn: [`docs/thesis_vi.tex`](thesis_vi.tex) · [`docs/thesis_vi.pdf`](thesis_vi.pdf).

Tài liệu này trình bày dự án theo **CRISP-DM** (Cross-Industry Standard Process for
Data Mining) — sáu giai đoạn chuẩn của quy trình khai phá dữ liệu — như một phần của
khung **SIC AI** (6-phase AI lifecycle). Mỗi mục nêu ngắn gọn: *làm gì* và *bằng
chứng đo được từ đâu*.

**Một câu tóm tắt:** một agent học tăng cường (\RL, cụ thể \texttt{MaskablePPO}) biến
đổi gói tin beacon C2 thật để **né Snort 2.9.20 (bộ luật ET Open C2)**, trong khi luồng
C2 vẫn còn hoạt động được. Mọi con số chính đều được chấm bởi **nhị phân Snort thật**.

**Kết quả chính:** **40/40** luồng held-out né hợp lệ dưới Snort thật, đối chiếu
**control âm tính** 40/40 luồng gốc bị báo động.

---

## 1. Business Understanding — Hiểu bài toán kinh doanh/an ninh

**Vấn đề.** Kênh C2 (command-and-control) là điểm sống còn của botnet. IDS chữ ký như
Snort bắt các mẫu byte đặc trưng. Câu hỏi: *có thể tự động hoá việc tạo biến đổi gói
tin để né IDS, mà không phá kênh C2, không?*

**Mục tiêu đo được.**
- Agent chọn một cơ chế biến đổi cho mỗi luồng sao cho Snort **không** báo động
  (*né tránh*), **và** ngữ nghĩa C2 còn nguyên (*giữ ngữ nghĩa*).
- Tối thiểu hoá **chi phí biến đổi** (số gói/byte bị sửa).

**Tiêu chí thành công.** Tỷ lệ né *hợp lệ* (né **và** giữ ngữ nghĩa) trên tập test
held-out, chấm bằng Snort thật, **kèm control âm tính**.

**Bằng chứng:** `README.md` (đoạn đầu), `docs/RESULTS_PRESENTATION.md` (threat model),
`docs/SIC_AI_FRAMEWORK_VALIDATION.md` (ánh xạ pha), `snort_bandit.py::break_even_cost`
(hình thức hoá đánh đổi chi phí, ngưỡng né $\approx 3{,}2$ gói).

---

## 2. Data Understanding — Hiểu dữ liệu

**Nguồn dữ liệu.** Các capture malware thật từ **Stratosphere IPS**
(CTU-13 / MCFP) — lưu lượng botnet đã ẩn danh, kèm nhãn lành tính/botnet.

| Capture | Vai trò |
|---|---|
| `botnet-capture-20110811-neris` | train + test |
| `botnet-capture-20110819-bot` | train + test |
| `botnet-capture-20110810-neris` | kiểm tra chéo capture |
| `capture-win13` | kiểm tra chéo capture (Cybersure) |

Cả hai capture chính đều **có mặt trong cả train và test**, để một phương pháp không
thể "thắng" bằng cách nhận diện "đây là capture nào".

**Đặc điểm dữ liệu quan trọng.**
- Mỗi luồng có một **framing**: `neris` (chuỗi bản ghi nhị phân, thường UDP) hoặc
  `http` (HTTP request, TCP). Framing quyết định cơ chế nào áp dụng được.
- Tập test held-out: 24 luồng `neris` + 16 luồng `http`.
- `capture-win13` gần như **không có payload** (0/97 gói có `Raw`) — một đặc điểm dữ
  liệu quyết định kết quả 0% của nó (xem §5).

**Bằng chứng:** `docs/dataset-sources.md`, `snort_validation/reports/hidden_defender_corpus.json`,
`data/stratosphere_captures.json`, `snort_validation/corpus_config.py`.

---

## 3. Data Preparation — Chuẩn bị dữ liệu

**Lọc luồng.** Chỉ giữ các luồng mà Snort thật **thật sự phát hiện** — vì nếu Snort
không bắt được luồng gốc thì không có gì để né.

**Phân chia train/test (xác định).** `corpus_config.py` dùng `random.Random(SEED=42)`
để shuffle rồi lấy 40 luồng đầu làm test:

| Tham số | Giá trị |
|---|---|
| `n_train` | **1 153** |
| `n_test` | **40** |
| `SEED` | 42 |
| `obs_dim` | 8 |

Test cố ý giữ ở **40 luồng** để mọi eval/control trước đó vẫn so sánh được.

**Trích đặc trưng.** Mỗi luồng → vector quan sát **8 chiều** (black-box, agent **không**
thấy bộ luật): `is_udp`, `n_pkts_norm`, `tot_bytes_norm`, `n_payload_pkts_norm`,
`payload_mean_norm`, `payload_std_norm`, `payload_max_norm`, `payload_min_norm`.

**Bằng chứng:** `snort_validation/corpus_config.py`, `ai_agent/hidden_defender_env.py`
(`_extract_features`), `tests/test_packet_features.py`.

---

## 4. Modeling — Mô hình hoá

**Môi trường:** `HiddenDefenderEnv` (Gymnasium). Một episode = một luồng = một quyết định.

**Không gian hành động:** **14 cơ chế** biến đổi payload, mỗi cơ chế có một chi phí:

| Cơ chế | Chi phí | Cơ chế | Chi phí |
|---|---|---|---|
| `split8` | 0,60 | `corrupt8` | 0,40 |
| `split16` | 0,50 | `overlap8` | 0,35 |
| `split24` | 0,40 | `noop` | 0,00 |
| `prepend4/8/12` | 0,20 | `http_header_pad` | 0,05 |
| `pad16` | 0,10 | `length_wrapper` | 0,25 |
| `reorder` | 0,35 | `ttl` | 0,10 |

**Action masking.** `mech_applicable()` lọc các cơ chế mà framing của luồng không thể
mang (ví dụ `http_header_pad` chỉ cho HTTP). Mask là một **bộ lọc tính khả thi**:
`MaskablePPO` đặt logit hành động bị mask về $-\infty$ trước softmax, nên hành động
không khả thi không bao giờ được lấy mẫu. Cơ chế không áp dụng được **bị loại khỏi mẫu
số**, nên mọi tỷ lệ % đều tính trên các cơ chế *có thể* tác động lên luồng đó.

**Hàm thưởng.**

| Tình huống | Phần thưởng |
|---|---|
| Né được **và** giữ ngữ nghĩa | $+10$ |
| Né được **nhưng** phá ngữ nghĩa | $-10$ |
| Vẫn bị báo động | $-1$ |

Cộng thưởng nhỏ $+0{,}15$ chỉ khi biến đổi đã né hợp lệ bằng `http_header_pad` trên
luồng HTTP (nên không thể chế ra né tránh); trừ chi phí cơ chế.

**Thuật toán.** `MaskablePPO` (MlpPolicy): `n_steps = batch_size = n_flows`,
`n_epochs=10`, `learning_rate=3e-4`, `ent_coef=0.0151`, `gamma=0.0` (mỗi luồng độc lập),
`seed=42`, dừng khi đạt $\ge 90\%$.

**Hai bộ chấm điểm (có chủ đích).**
- **Surrogate nhanh** (`RealRulesReplica`) để *huấn luyện* — parse bộ luật ET Open thật,
  nhưng **bỏ sót 20,6%** luật (`pcre`, `byte_test`, `byte_extract`, `byte_jump`).
- **Snort thật** (`--real-snort`) để *đo kết quả chính*.

**Bằng chứng:** `ai_agent/hidden_defender_env.py`, `ai_agent/train_hidden_defender_ppo.py`,
`ai_agent/eval_masked_ppo_test.py`, `tests/` (69 test pass).

---

## 5. Evaluation — Đánh giá

Mọi con số dưới đây đọc từ file JSON trong `snort_validation/reports/`. Không con số
nào được ước lượng.

### 5.1 Kết quả chính (Snort thật) — `ppo_masked_test.json`

| Chỉ số | Giá trị |
|---|---|
| method | `maskable_ppo` |
| scorer | `real_snort` |
| n_flows | 40 |
| **alerted** | **0** |
| **valid_evasion** | **40 / 40 (100,0%)** |
| masked_actions_used | 0 |

Policy dùng đúng **hai** cơ chế: `split8` (24 luồng `neris`) và `split24` (16 luồng
`http`). Mọi luồng đều `semantics_ok = true`.

### 5.2 Control âm tính — `control_noop_real_snort.json`

40 luồng **không** biến đổi → **40/40 bị báo động**, tỷ lệ né **0%**. Đây là bằng
chứng định lượng rằng 40/40 của agent là thật.

### 5.3 Ma trận cơ chế (Snort thật, 8 luồng HTTP) — `hidden_defender_matrix_test.json`

| Cơ chế | Né được | Né **và** giữ ngữ nghĩa |
|---|---|---|
| `split8` / `split16` / `split24` | 8/8 | **8/8** |
| `http_header_pad` | 8/8 | **8/8** |
| `prepend4/8/12`, `overlap8`, `length_wrapper` | 8/8 | 0/8 |
| `corrupt8` | 1/8 | 0/8 |

**Sáu cơ chế né 8/8 nhưng 0/8 hợp lệ** — chúng phá kênh C2, không đánh bại IDS. Đây là
lý do phải kiểm tra ngữ nghĩa, không chỉ đếm alert.

### 5.4 RL có cần thiết không? — `hidden_defender_real_snort_test.json`

| Phương pháp | Queries | Né được |
|---|---|---|
| `random_sweep` | 25 | 8/8 |
| `greedy` | 13 | 8/8 |
| `supervised_tree` | 8 | 8/8 |
| **ppo** | **8** | **8/8** |

Trên tập train 64 luồng: `greedy` né 58/64 với **149** queries; PPO né 58/64 nhưng tốn
**704** queries — gấp **4,7×**. Kết luận trung thực: *dưới defender tĩnh này, bài toán
quá dễ để RL tạo thêm giá trị — hành động thắng gần như cố định theo framing.*

### 5.5 Kiểm tra chéo capture — `cross_capture_summary.json`

| Capture | Baseline bị bắt | Policy né | Corrupt-all né | Kết luận |
|---|---|---|---|---|
| `20110810-neris` | 23/24 | 4 | 4 | hoà |
| `20110811-neris` | 24/24 | 24 | 24 | hoà |
| `capture-win13` | 24/24 | 0 | 0 | hoà |

**Trung bình 38,89%, độ lệch chuẩn 43,74%** (min 0%, max 100%). Policy **hoà** control
"corrupt-everything" trên cả 3 capture → con số né chéo capture **không** phải thành tựu
của RL.

### 5.6 Surrogate so với thật — `surrogate_sweep_14mech.json`

Đồng thuận tổng thể 161/224 (71,9%); trên ô áp dụng được 103/116 (88,8%);
**surrogate false-safe = 0** (không bao giờ báo né khi Snort đang báo động — chế độ thất
bại nguy hiểm nhất).

### 5.7 Scale-up — `final_scale_up_summary.json`

| Số luồng | Né được | Tỷ lệ né |
|---|---|---|
| 24 | 24 | 100,0% |
| 100 | 94 | 94,0% |
| 300 | 287 | 95,7% |
| 323 | 69 | **21,4%** |

Không đơn điệu — sụp ở 323 luồng, chưa giải thích được.

**Kỷ luật đo lường:** một cặp (flow, cơ chế) mỗi pcap; control âm tính bắt buộc; trần
oracle; **verifier tự động 81/81 kiểm tra** (`controls/verify_report_claims.py`) tái suy
diễn mọi con số từ JSON gốc và thất bại nếu trôi dạt.

---

## 6. Deployment — Triển khai & vận hành

**Cài đặt.** `.venv` cục bộ trong repo là interpreter duy nhất có đủ dependency
(Python 3.11). Snort 2.9.20 cần cài cho đường chấm điểm thật (`snort -V`).

```bash
cd /root/.hermes/c2-evasion-rl
python3.11 -m venv .venv
.venv/bin/pip install "torch==2.14.*+cpu" --index-url https://download.pytorch.org/whl/cpu
.venv/bin/pip install "numpy>=2.0" "pandas>=2.2" "scipy>=1.11" "scikit-learn>=1.4" \
    "pyarrow>=15.0" "joblib>=1.3" "xgboost>=2.0" "scapy==2.7.0" \
    "stable-baselines3==2.9.0" "sb3-contrib==2.9.0" "gymnasium==1.3.0" "pytest==9.1.1"
```

**Các bước chạy** (luôn cần `PYTHONPATH=ai_agent:snort_validation`):

```bash
# 1. Train surrogate nhanh  -> reports/ppo_hidden_defender.json
PYTHONPATH=ai_agent:snort_validation .venv/bin/python3 ai_agent/train_hidden_defender_ppo.py

# 2. Train với Snort thật chấm điểm  (~2 giờ)
PYTHONPATH=ai_agent:snort_validation .venv/bin/python3 ai_agent/train_hidden_defender_ppo.py --real-snort

# 3. Đánh giá checkpoint held-out (kết quả chính)  -> reports/ppo_masked_test.json
PYTHONPATH=ai_agent:snort_validation .venv/bin/python3 ai_agent/eval_masked_ppo_test.py --real-snort

# 4. Control âm tính  (phải là 40/40 bị báo động)
PYTHONPATH=ai_agent:snort_validation .venv/bin/python3 controls/control_noop_real_snort.py

# 5. Test + verifier
.venv/bin/python3 -m pytest tests/ -q
PYTHONPATH=ai_agent:snort_validation .venv/bin/python3 controls/verify_report_claims.py   # 81/81
```

**Build luận văn.**

```bash
cd docs
pdflatex thesis_vi && bibtex thesis_vi && pdflatex thesis_vi && pdflatex thesis_vi
# -> thesis_vi.pdf  (hoặc dùng Makefile trong docs/thesis/)
```

**Vận hành & giám sát.** Kết quả JSON được ghi vào `snort_validation/reports/`; verifier
và bộ test là cổng chặn — một file tổng hợp lỗi thời sẽ làm verifier **thất bại** thay vì
được công bố. **Thứ tự demo:** control trước, kết quả chính sau — đó là câu chuyện.

---

## 7. Hạn chế trung thực (đọc trước khi trích dẫn)

- **Train và eval dùng hai bộ chấm khác nhau.** Surrogate nhanh dùng để train; con số
  40/40 đo bằng Snort thật. Surrogate cảnh báo thừa, nên 99,2% khi train không phải
  cùng đại lượng với 90,6% (train bằng Snort thật) — và cả hai dừng ở ngưỡng 90%, không
  phải trần hội tụ.
- **Surrogate bỏ sót 20,6% luật thật.** Với corpus này không ảnh hưởng (chỉ 3 sid kích
  hoạt mỗi capture) nhưng sẽ ảnh hưởng với lưu lượng khác.
- **Kết quả chính là một seed, một cặp capture.** 1 153 train / 40 test, đều từ hai
  capture cùng họ.
- **RL chưa vượt baseline.** PPO tốn 4,7× queries so với `greedy` cho cùng tỷ lệ né.
- **Không tổng quát hoá chéo capture.** `capture-win13` ở 0% vì luồng của nó không có
  payload để biến đổi (giới hạn *không gian hành động*, không phải kết luận về họ botnet).
- **Cả hai cơ chế thắng đều là phân mảnh** (`split8`, `split24`) — không phải kho cơ chế
  đa dạng.
- **Scale không đơn điệu** (sụp ở 323 luồng) chưa được giải thích.

---

## 8. Tài liệu & tham chiếu

- `docs/RESULTS_PRESENTATION.md` — cách mọi con số chính được tạo ra và kiểm chứng.
- `docs/surrogate_vs_reality_audit.md` — audit surrogate so với Snort thật (224 lần gọi).
- `docs/REPORT_WRITING_GUIDE.md` — cấu trúc 8 chương + dữ liệu đã kiểm chứng.
- `docs/SIC_AI_FRAMEWORK_VALIDATION.md` — ánh xạ pha SIC AI ↔ CRISP-DM.
- `docs/thesis_vi.tex` / `docs/thesis_vi.pdf` — luận văn tiếng Việt 8 chương.

**Nguồn ngoài:** [Stratosphere / CTU-13](https://www.stratosphereips.org/datasets-ctu13) ·
[ET Open rules](https://rules.emergingthreats.net/open/) · [Snort 2.9](https://www.snort.org/) ·
[Stable-Baselines3](https://stable-baselines3.readthedocs.io/) ·
[Gymnasium](https://gymnasium.farama.org/).
