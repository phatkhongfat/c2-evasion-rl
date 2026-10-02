# C2 Evasion RL

[English](README.md) · **Tiếng Việt**

Agent red-team dùng RL để biến đổi gói tin beacon C2 thật nhằm **né Snort 2.9.20 (bộ luật
ET Open C2)**, đồng thời giữ cho lưu lượng trông như C2 vẫn hoạt động. Mọi kết quả chính đều
được chấm bởi chính nhị phân Snort thật.

**Kết quả chính:** 16/16 luồng held-out né được Snort thật, đối chiếu với control âm tính
(lưu lượng chưa biến đổi) là 16/16 đều bị báo động.

---

## Bố cục

- `ai_agent/` — agent. `hidden_defender_env.py` là môi trường: 14 kiểu biến đổi gói tin, action
  masking, kiểm tra ngữ nghĩa C2. `train_hidden_defender_ppo.py` để train.
  `eval_masked_ppo_test.py` để đánh giá checkpoint.
- `snort_validation/` — tích hợp Snort thật: bộ luật, bộ chấm điểm replica, harness, script audit.
- `controls/` — control kiểm chứng (control âm tính, audit surrogate so với Snort thật).
- `data/`, `snort_validation/pcaps/` — kho capture. `models/` — checkpoint.
  `snort_validation/reports/` — toàn bộ kết quả JSON.

Hệ thống hiện tại là `HiddenDefenderEnv` 14 cơ chế, train bằng MaskablePPO. Các hệ thống cũ
(bandit, continuous packet-level) chỉ còn trong `docs/` như lịch sử.

## Cài đặt

`.venv` cục bộ trong repo là interpreter duy nhất có đủ dependency (python3 hệ thống không có;
chạy từ thư mục con sẽ hỏng import). Python 3.11.

```bash
cd /root/.hermes/c2-evasion-rl
python3.11 -m venv .venv
.venv/bin/pip install "torch==2.14.*+cpu" --index-url https://download.pytorch.org/whl/cpu
.venv/bin/pip install "numpy>=2.0" "pandas>=2.2" "scipy>=1.11" "scikit-learn>=1.4" \
    "pyarrow>=15.0" "joblib>=1.3" "xgboost>=2.0" "scapy==2.7.0" \
    "stable-baselines3==2.9.0" "sb3-contrib==2.9.0" "gymnasium==1.3.0" "pytest==9.1.1"
```

Cần cài Snort cho đường chấm điểm bằng Snort thật (`snort -V` → 2.9.20 GRE). Dùng conda thì:
`conda env create -f environment.yml && conda activate rl_c2_evasion`.

Mọi lệnh dưới đây đều cần `PYTHONPATH=ai_agent:snort_validation`.

## Chạy

### 1. Train (surrogate nhanh)

```bash
PYTHONPATH=ai_agent:snort_validation .venv/bin/python3 \
  ai_agent/train_hidden_defender_ppo.py
```

MaskablePPO, 64 luồng, dừng khi đạt ≥90% né hợp lệ. → `reports/ppo_hidden_defender.json`.
Đạt 95,3% (61/64) @ 704 query / 11 epoch.

### 2. Train với Snort thật chấm điểm

```bash
PYTHONPATH=ai_agent:snort_validation .venv/bin/python3 \
  ai_agent/train_hidden_defender_ppo.py --real-snort
```

~1,3 giây/luồng → khoảng 2 giờ. Đạt 90,6% (58/64) @ 640 query / 10 epoch.

### 3. Đánh giá checkpoint trên luồng held-out (kết quả chính)

```bash
PYTHONPATH=ai_agent:snort_validation .venv/bin/python3 \
  ai_agent/eval_masked_ppo_test.py --real-snort
```

16/16 né hợp lệ (100%) dưới Snort thật. Policy chỉ dùng đúng hai cơ chế: `split8` (UDP) và
`http_header_pad` (HTTP). → `reports/ppo_masked_test.json`.

### 4. Control và audit surrogate

```bash
# control âm tính: C2 chưa biến đổi phải bị báo động
PYTHONPATH=ai_agent:snort_validation .venv/bin/python3 \
  controls/control_noop_real_snort.py     # -> 16/16 bị báo động

# surrogate so với Snort thật, từng luồng
PYTHONPATH=ai_agent:snort_validation .venv/bin/python3 \
  controls/surrogate_vs_real_snort.py     # -> 8/8 khớp

# 14 cơ chế x 16 luồng đối chiếu Snort thật
PYTHONPATH=ai_agent:snort_validation .venv/bin/python3 \
  controls/surrogate_sweep_14mech.py      # -> 161/224 khớp, 0 false-safe
```

### 5. Chạy test

```bash
.venv/bin/python3 -m pytest tests/ -q
```

## Cờ train

`--real-snort` (chấm bằng nhị phân thật) · `--n-flows N` (mặc định 64) ·
`--max-epochs N` (mặc định 40) · `--seed N` (mặc định 42) · `--out PATH`.

## Lưu ý trung thực

- **Train và eval dùng hai bộ chấm khác nhau.** Surrogate nhanh dùng để train; con số 16/16 được
  đo bằng Snort thật. Surrogate cảnh báo thừa, nên ~95% khi train không phải cùng đại lượng với
  90,6% khi train bằng Snort thật (và lần đó cũng dừng ở ngưỡng 90% — chưa lần nào là trần hội tụ
  với nhiều seed).
- **Surrogate bỏ sót 20,6% luật thật** (`pcre`, `byte_test`, `byte_extract`, `byte_jump`).
  Với bộ dữ liệu này không ảnh hưởng (chỉ 3 sid thực sự kích hoạt mỗi capture) nhưng với lưu
  lượng khác thì sẽ có vấn đề.
- **Số mẫu nhỏ** (64 train / 16 test, một seed duy nhất).

## Tài liệu

`docs/surrogate_vs_reality_audit.md` — audit đầy đủ surrogate so với Snort thật (224 lần gọi
Snort thật). `docs/RESULTS_PRESENTATION.md` — cách mọi số liệu chính được tạo ra và kiểm chứng.

## Tham khảo

[Stratosphere / CTU-13](https://www.stratosphereips.org/datasets-ctu13) ·
[Luật ET Open](https://rules.emergingthreats.net/open/) · [Snort 2.9](https://www.snort.org/) ·
[Stable-Baselines3](https://stable-baselines3.readthedocs.io/) ·
[Gymnasium](https://gymnasium.farama.org/)
