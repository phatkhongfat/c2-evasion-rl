# C2 Evasion RL

[Tiếng Anh](README.md) · **Tiếng Việt**

Agent red-team dùng RL để biến đổi gói tin beacon C2 thật nhằm **né Snort 2.9.20 (bộ luật
ET Open C2)**, đồng thời giữ cho lưu lượng trông như C2 vẫn hoạt động. Mọi con số trong bảng
kết quả dưới đây đều do chính nhị phân Snort thật sinh ra.

**Kết quả chính:** trên 40 luồng held-out, policy né được Snort thật ở **16/40 (40,0%)**,
đối chiếu với control âm tính (lưu lượng chưa biến đổi) là 40/40 đều bị báo động. 16 luồng
mà policy né được đúng bằng 16 luồng beacon C2 có trong tập — riêng trên lưu lượng C2 thì
là **16/16 (100%)**.

---

## Đọc trước: tập test thực chất chứa gì

40 luồng held-out **không phải** 40 beacon C2.

| nhóm | capture | SID bắt | classtype | số luồng |
|---|---|---|---|---:|
| **c2-http** | `botnet-capture-20110811-neris` | 2012627, 2018983, 2039514, 2042945 | `trojan-activity` | 16 (40,0%) |
| **p2p-dht** | `botnet-capture-20110819-bot` | 2008581, 2008583 | `policy-violation` | 24 (60,0%) |

Nửa `p2p-dht` là BitTorrent DHT, không phải C2: **194/194 gói UDP decode được thành Bencode
KRPC** (`ping` 26, `find_node` 52; `ping`→`{id}`, `find_node`→`{id, target}`) — đúng chuẩn
BEP 5. Snort bắt vì ET Open có các luật `ET P2P BitTorrent DHT`, nhưng đây là lưu lượng nền
peer-to-peer. Tập train cũng tỉ lệ tương tự (455 C2 + 697 DHT = 1153 luồng).

Điều này quyết định cách đọc mọi kết quả dưới đây: **không cơ chế biến đổi nào né được luồng
DHT** (0/24 với cả 17 cơ chế), nên trần khả thi trên tập 40 luồng luôn thấp hơn 100% bất kể
policy là gì.

---

## Bố cục

- `ai_agent/` — agent. `hidden_defender_env.py` là môi trường: **17** kiểu biến đổi gói tin,
  action masking, kiểm tra ngữ nghĩa C2. `train_hidden_defender_ppo.py` để train.
  `eval_masked_ppo_test.py` để đánh giá checkpoint.
- `snort_validation/` — tích hợp Snort thật: bộ luật, bộ chấm điểm replica, harness, script audit.
- `controls/` — control kiểm chứng và các probe một lần (`probe_*.py`).
- `data/`, `snort_validation/pcaps/` — kho capture. `models/` — checkpoint.
  `snort_validation/reports/` — toàn bộ kết quả JSON.
- `thesis/` — bản luận văn (`main.tex`).

Hệ thống hiện tại là `HiddenDefenderEnv` 17 cơ chế, train bằng MaskablePPO. Các hệ thống cũ
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

### 1. Train

```bash
PYTHONPATH=ai_agent:snort_validation .venv/bin/python3 \
  ai_agent/train_hidden_defender_ppo.py --real-snort --seed 42 --n-flows 64
```

`--real-snort` chấm bằng nhị phân thật (~1,3 giây/luồng). Bỏ cờ này để train trên surrogate
nhanh. → `snort_validation/reports/train_post_p14_rs_s42.json`.

### 2. Đánh giá checkpoint trên luồng held-out (kết quả chính)

```bash
PYTHONPATH=ai_agent:snort_validation .venv/bin/python3 \
  ai_agent/eval_masked_ppo_test.py --real-snort --model /tmp/model_full_p16d_120ep
```

→ `snort_validation/reports/p16d_eval_real_snort.json`. Khoảng 15 phút cho 40 luồng × 17 action.

### 3. Sweep cơ chế — trần khả thi

```bash
PYTHONPATH=ai_agent:snort_validation .venv/bin/python3 \
  controls/probe_mech_sweep_real_snort.py
```

17 cơ chế × 40 luồng = 680 query gửi tới nhị phân thật (~47 s), báo cáo oracle
(`best_single`) và headroom so với policy. → `p17_mech_sweep_real_snort_d8.json`.

### 4. Control

```bash
# control âm tính: C2 chưa biến đổi phải bị báo động, nếu không con số né là vô nghĩa
PYTHONPATH=ai_agent:snort_validation .venv/bin/python3 \
  controls/control_noop_real_snort.py      # -> 40/40 bị báo động

# surrogate so với Snort thật, từng luồng
PYTHONPATH=ai_agent:snort_validation .venv/bin/python3 \
  controls/surrogate_vs_real_snort.py      # -> 8/8 khớp

# surrogate phải tái lập được cả engine thứ hai (ma trận 100 cell)
.venv/bin/python3 -m pytest tests/test_replica_matches_suricata.py -q   # -> 7 passed, 100/100 khớp
```

### 5. Chạy test

```bash
.venv/bin/python3 -m pytest tests/ -q     # -> 383 passed, 1 skipped
```

## Cờ train

`--real-snort` (chấm bằng nhị phân thật) · `--n-flows N` (mặc định 64) ·
`--max-epochs N` (mặc định 40) · `--seed N` (mặc định 42) · `--out PATH` ·
`--split {train,test}` · `--corpus PATH` · `--capture NAME` · `--model-out PATH`.

## Kết quả

Đều đo bằng nhị phân Snort 2.9.20 thật, ET Open C2 ruleset, 40 luồng held-out.

**Policy so với trần**

| đại lượng | giá trị | nguồn |
|---|---:|---|
| policy evasion | **16/40 = 40,0%** | `p16d_eval_real_snort.json` |
| control âm tính (`noop`) | 40/40 bị báo động ✅ | `control_noop_real_snort.json` |
| oracle, cơ chế đơn tốt nhất | **23/40 = 57,5%** (`split_slow`) | `p17_mech_sweep_real_snort_d8.json` |
| headroom | **17,5 pp** | |
| policy riêng trên tập C2 | **16/16 = 100%** | `p17_evasion_by_framing.json` |
| train, Snort thật, seed 42 | 48,4% (31/64) | `train_post_p14_rs_s42.json` |
| cùng 680 query dưới Suricata 7.0.3 | **0/40 = 0,0%** | `p16d_mech_sweep_suricata.json` |

**Theo từng cơ chế, Snort thật** (`noop` bắt buộc phải là 0)

| cơ chế | né /40 | C2 /16 | DHT /24 | giữ nguyên byte? |
|---|---:|---:|---:|---|
| `split_slow` | **23** | 16 | 7 | có |
| `split8` / `split16` / `split24` | **16** | 16 | 0 | có |
| `http_header_pad` | **16** | 16 | 0 | không |
| `http_header_case` | **16** | 16 | 0 | không |
| `reorder`, `ttl`, `overlap8`, `noop`, `query_param_prepend` | 0 | 0 | 0 | — |
| `prepend4/8/12`, `pad16`, `corrupt8`, `length_wrapper` | 0 | 0 | 0 | không (vỡ ngữ nghĩa) |

Histogram của policy là `http_header_pad` ×16 + `noop` ×24 — nó né được mọi luồng C2 và cố
tình không làm gì trên 24 luồng DHT, nơi không cơ chế nào ăn.

## Lưu ý trung thực

- **Headline 40/40 ở các bản cũ là sai** và đã bị gỡ. Nó đến từ `ppo_masked_test.json`, được
  chấm trước khi mô hình fragment reassembly được sửa. Đánh giá hiện tại chạy đúng 40 luồng
  đó qua nhị phân thật và báo 16/40. `controls/verify_report_claims.py` vẫn còn khẳng định
  các con số 40/40 cũ và được ghi nhận là stale.
- **60% tập test là P2P, không phải C2.** Xem bảng đầu. Mọi con số "trần" đều bị giới hạn bởi
  điều này. Con số trung thực riêng cho C2 là 16/16.
- **Có hai họ action thắng, bằng hai nguyên lý độc lập.** `split*` giữ nguyên byte và thắng
  bằng cách đánh bại cơ chế tái ghép `frag3` của Snort; `http_header_pad` /
  `http_header_case` đổi byte và thắng qua payload match. Dưới cổng ngữ nghĩa byte-equality
  nghiêm ngặt, các action header đạt 0/16 và chỉ còn `split*` — oracle 57,5% được đo dưới
  cổng lỏng mà reward thực sự dùng.
- **Cổng reward lỏng là chủ ý.** Sửa HTTP header không bao giờ byte-preserving được, nên đòi
  điều đó sẽ khiến `http_header_*` bị coi là không chạm được chứ không phải sai.
  `semantics_ok_reward` là cổng mà môi trường chấm qua (`hidden_defender_env.py`).
- **Train và eval dùng hai bộ chấm khác nhau** trừ khi có `--real-snort`. Surrogate nhanh dùng
  để train; kết quả chính là nhị phân thật. Cả 48,4% lúc train lẫn 40,0% lúc eval đều chưa
  phải trần hội tụ đa seed.
- **Một seed, một cặp capture, 40 luồng test.** Tập test cố ý giữ ở 40 luồng để mọi lần đánh
  giá và control trước đó vẫn so sánh được.
- **Suricata 7.0.3 không né được gì (0/40) trên cùng 680 query.** Khả năng né gắn với cấu
  hình `frag3` của Snort, không phải điểm yếu chung của IDS.
- **Surrogate là bản replica, không phải Snort.** Nó khớp Suricata 100/100 cell test và khớp
  Snort trên control mẫu, nhưng vòng đời session `frag3` (Paxson & Shankar 2003, mặc định
  60 s) và anomaly rejection chỉ mới trung thành ở các commit gần đây — các con số surrogate
  trước đó đều có trước bản sửa đó.

## Tài liệu

`docs/surrogate_vs_reality_audit.md` — audit đầy đủ surrogate so với Snort thật.
`docs/RESULTS_PRESENTATION.md` — cách mọi số liệu chính được tạo ra và kiểm chứng.

## Tham khảo

[Stratosphere / CTU-13](https://www.stratosphereips.org/datasets-ctu13) ·
[Luật ET Open](https://rules.emergingthreats.net/open/) · [Snort 2.9](https://www.snort.org/) ·
[Stable-Baselines3](https://stable-baselines3.readthedocs.io/) ·
[Gymnasium](https://gymnasium.farama.org/) ·
[Paxson & Shankar, *Real-world detection of attacks through prefractured TCP* (2003)](https://www.usenix.org/legacy/events/sec03/tech/full_papers/paxson/paxson.pdf)
