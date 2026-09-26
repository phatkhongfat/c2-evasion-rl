# C2 Evasion RL — Đánh giá đối kháng cho hệ thống phát hiện xâm nhập mạng

[English](README.md) · **Tiếng Việt**

Red team dùng học tăng cường để biến đổi các bản ghi gói tin C2 botnet **thật** nhằm vượt qua
**Snort IDS thật** (bộ luật ET Open C2), được đo đầu-cuối mà không có surrogate nào nằm trong
đường tính phần thưởng.

Mục tiêu không phải là một công cụ tấn công hoạt động được. Mục tiêu là đo xem một kẻ tấn công
*thích ứng* có thể làm suy giảm một bộ phát hiện *thật* đến mức nào, và báo cáo trung thực điểm
đo bị bão hoà ở đâu cùng lý do.

---

## 1. Giới thiệu

Kho mã này trả lời một câu hỏi: **liệu một chính sách học được có thể làm cho lưu lượng C2 thật
trở nên không thể phát hiện bởi một IDS chữ ký thật, và phải trả giá bao nhiêu bằng tổn hại
payload?**

Câu trả lời hiện tại, từ 11 phép đo ground-truth do chính Snort đưa ra phán quyết:

- **Có — tỷ lệ né tránh 100% là đạt được** trên capture chính, chỉ với **2.88 gói bị làm hỏng
  mỗi luồng** (trên 32 khe khả dụng) ở chi phí 0.6 mỗi gói.
- Kết quả đã **bão hoà**: mọi mức chi phí trong dải đã thử (0.1 → 0.6) và mọi kích thước lô
  (24 → 200 luồng) đều đạt 100% né tránh. Trên capture này không còn đường biên chi phí–né tránh
  nào để vẽ tiếp.
- **Khả năng tổng quát hoá giữa các capture mới là điểm yếu thật sự**: cùng chính sách đó trên
  một capture Neris anh em chỉ đạt **16.7%**, không phải 100%.

Các phiên bản trước của dự án từng báo cáo những con số *bất khả thi*: baseline `0/24` luồng bị
phát hiện, nghĩa là Snort không thấy được lưu lượng mà một bộ luật dựa trên `flow:established`
được tạo ra để bắt. Con số đó không phải là một phát hiện — nó là một lỗi. Hai khiếm khuyết độc
lập đã phá huỷ khả năng phát hiện (§6). Sau khi sửa, mọi con số ở §7 đều đến từ chính phán quyết
của nhị phân Snort và tái lập được từ một seed cố định.

Phân tích kèm theo: [`docs/REAL_SNORT_IN_THE_LOOP.md`](docs/REAL_SNORT_IN_THE_LOOP.md),
[`docs/CHANGELOG_SNORT_INTEGRATION.md`](docs/CHANGELOG_SNORT_INTEGRATION.md).

---

## 2. Mô hình mối đe doạ

**Red team (agent).** Thích ứng, white-box với *họ luật* của bộ phát hiện nhưng không với các
phán quyết của nó. Agent quan sát đặc trưng từng gói của một luồng đã bắt được và quyết định,
với mỗi gói trong tối đa 32 gói, có làm hỏng payload của gói đó hay không. Nó được thưởng thuần
tuý bằng số cảnh báo của chính bộ phát hiện. Nó không có truy cập mạng, không có kênh C2 sống, và
ở giai đoạn này không thể thay đổi ngữ nghĩa giao thức hay thời điểm của luồng.

**Blue team (bộ phát hiện).** Snort 2.9.20 GRE (Build 82) chạy tập con **C2** của Emerging
Threats Open — 21,374 luật cảnh báo có `content:` được chọn theo ngữ nghĩa C2 / botnet /
backdoor / trojan / beacon. Các danh sách danh tiếng IP/CIDR thuần bị loại (chúng không bao giờ
khớp được với địa chỉ lab năm 2011), cùng với các `flowbits` mồ côi. Chính sách chọn luật đầy đủ
và hai loại trừ có chủ ý được ghi tại
[`docs/DATASET_AND_RULESET_SWITCH.md`](docs/DATASET_AND_RULESET_SWITCH.md).

**Giả định và phạm vi.**

- Phòng thủ bị **đóng băng**. Không huấn luyện lại, không thích ứng ngưỡng, không phản ứng theo
  tập hợp mô hình.
- Kẻ tấn công được làm hỏng byte payload nhưng phải giữ luồng **nhất quán ở tầng vận chuyển**:
  phiên TCP vẫn thiết lập, địa chỉ vẫn đối xứng. Né tránh bằng cách phá vỡ phiên nằm ngoài phạm
  vi — làm vậy thì "né tránh" chỉ vì lưu lượng không còn dùng được nữa.
- Phát hiện được đánh giá **theo từng luồng**, offline, trên các gói phát lại. Không có tương
  quan liên luồng và không có phân tích đa phiên có trạng thái.
- Mối đe doạ có cấu trúc thực tế (IDS thật, lưu lượng malware bắt được thật, nhà cung cấp luật
  độc lập) nhưng bị giới hạn về quy mô (vài chục luồng, mỗi lần một capture).

**Điều một người phòng thủ nên rút ra.** Một bộ phát hiện chữ ký mà các luật phụ thuộc vào
`flow:established` có thể bị vượt qua bằng cách làm hỏng một tập payload *nhỏ, học được* — không
phải bằng thủ thuật tạo dạng lưu lượng, và không phải trả giá bằng cả phiên. Cách phòng thủ
không phải là "thêm luật", mà là chuẩn hoá nội dung cộng với tương quan đa luồng có trạng thái.

---

## 3. Kiến trúc hệ thống

![Luồng C2 Evasion RL](docs/pipeline.png)

**Quy trình thực gói-level:**

```
pcap Stratosphere / MCFP          luật ET Open C2 (Emerging Threats)
        │                                    │
        ▼                                    ▼
 extract_ctu13_real_features.py       build_et_open_c2_ruleset.py
 (gói thật, siêu dữ liệu mỗi luồng)   (21,374 luật cảnh báo C2)
        │                                    │
        ▼                                    ▼
 luồng gói thật                      et_open_c2/snort_et_c2.conf
 (cả hai chiều, song phương)                │
        │                                    │
        └──────────────┬─────────────────────┘
                       ▼
            ai_agent/real_packet_env.py
       Nạp gói thật (cả hai chiều),
       Phơi các đặc trưng từng gói (TTL delta, fragmentation, overlap, timing)
       Mặt nạ biến đổi: hành động nhị phân mỗi gói
                       │
                       ▼
            ai_agent/train_packet_level_agent.py
       Huấn luyện PPO: một hành động = kế hoạch biến đổi toàn bộ cho một luồng
       Thưởng: phán quyết Snort thật (+50 né được, −2 bị bắt, −cost)
                       │
                       ▼
      snort_validation/snort_resident_service.py
       Gói biến đổi → PCAP → giao diện loopback
       Kiểm tra Snort 2.9 (ET Open C2) sống
       Tỷ lệ né tránh ground-truth (34.8 ms/luồng)
                       │
                       ▼
      snort_validation/reports/*.json  →  aggregate_results.py
                       │
                       ▼
      snort_validation/reports/final_results_table.json (11 hàng)
```

**Các thành phần.**

- **Sổ đăng ký capture** — `data/stratosphere_captures.json`, 15 capture MCFP với số luồng và
  số gói *được đo thật* (1,895 → 482,378 gói), không phải số liệu metadata khai báo.
- **Bộ trích xuất đặc trưng** — `snort_validation/extract_ctu13_real_features.py`, 51 cột gồm
  entropy payload, thống kê IAT, tổ hợp cờ TCP và nhãn `snort_alert` thật.
- **Môi trường** — `ai_agent/real_packet_env.py`, nạp gói thật từ pcap và trả về cả hai chiều
  của mỗi cuộc hội thoại.
- **Agent** — `ai_agent/snort_bandit.py`, chính sách Bernoulli theo từng gói, huấn luyện bằng
  REINFORCE với baseline trung bình động.
- **Dịch vụ bộ phát hiện** — `snort_batch_service.py` (một lần, pcap theo lô) và
  `snort_resident_service.py` (Snort sống lâu trên loopback, ~34.8 ms/luồng).
- **Bộ tổng hợp** — `snort_validation/aggregate_results.py`, gộp báo cáo sweep / scale /
  cross-capture thành một bảng và **báo lỗi rõ ràng** khi thiếu giá trị thay vì mặc định về 0.

**Luồng dữ liệu.** pcap → gói thật → mặt nạ biến đổi → frame phát lại → số cảnh báo Snort →
phần thưởng → cập nhật chính sách. Không ở bước nào có một surrogate học được đóng vai bộ phát
hiện.

---

## 4. Công thức hoá toán học

### PPO ở mức gói (hệ thống hiện tại)

- **Đơn vị quyết định** — một *hành động* là một kế hoạch biến đổi hoàn chỉnh cho một luồng:
  mặt nạ nhị phân `m ∈ {0,1}^32` trên các gói của luồng đó.
- **Chính sách** — Bernoulli theo từng gói. Đặc trưng mỗi gói (8 chiều): kích thước payload /
  1500, độ dài thô / 1500, là-UDP, là-TCP, chỉ số chuẩn hoá, là-gói-đầu, là-gói-cuối,
  chỉ-số-trong-dải. Một MLP 3 lớp (64 ẩn, tanh) ánh xạ mỗi gói thành một logit; kế hoạch được
  lấy mẫu độc lập.
- **Phần thưởng** —
  ```
  r = -alerts + 10.0                 nếu alerts == 0   (EVASION_BONUS)
  r = -alerts - cost × n_corrupt     ngược lại
  ```
  trong đó `n_corrupt` đếm các gói **thực sự** bị thay đổi (một khe mặt nạ không có payload thì
  miễn phí). Chi phí theo từng gói chính là điểm mấu chốt: nếu không có nó, chính sách tối ưu sẽ
  tầm thường là "làm hỏng tất cả".
- **Sàn chi phí** — `EVASION_BONUS / 32 = 0.3125`. Mọi chi phí bằng hoặc dưới mức này khiến
  "làm hỏng cả 32 gói" trở thành tối ưu và thí nghiệm mất ý nghĩa; các chi phí được đo là
  0.1–0.6.
- **Học** — REINFORCE với baseline trung bình động
  (`baseline ← 0.9·baseline + 0.1·mean(r)`), Adam với `lr = 3e-3`.
- **Đánh giá** — chính sách tất định lấy `argmax` của logit từng gói (`logit > 0`), cho ra một
  kế hoạch duy nhất, xác định cho mỗi luồng.
- **Đối chứng** — một kế hoạch ngẫu nhiên và một kế hoạch làm hỏng tất cả luôn được chấm điểm
  song song với agent, trên cùng lô, bằng cùng một lời gọi Snort.

---

## 5. Thiết lập thực nghiệm

**Bộ dữ liệu.**

| Bộ dữ liệu | Vai trò | Quy mô |
|---|---|---|
| Stratosphere / MCFP (họ CTU-13) | pcap chính, gói thật | 15 capture, 1,895–482,378 gói |
| CTU-13 (13 capture gốc) | pool huấn luyện mức luồng | 10,598,771 dòng thô |
| `data/mcfp_snort_labeled.parquet` | luồng có nhãn Snort thật | 35,906 luồng, 1,434 cảnh báo |
| Bộ luật ET Open C2 | luật của bộ phát hiện | 21,374 luật cảnh báo |

**Pool luồng khả dụng (đo được, không giả định).** `--flows N` là một *yêu cầu*, không phải bảo
đảm: môi trường chỉ giữ các luồng có ≥4 gói trong pcap. Đo bằng
`snort_validation/capture_pool_sizes.py`:

| Capture | Họ | Dòng có cảnh báo | Luồng khả dụng | Dải gói |
|---|---|---|---|---|
| `botnet-capture-20110811-neris` | Neris | 471 | 471 | 8–145 |
| `botnet-capture-20110810-neris` | Neris | 45 | 45 | 6–11,478 |
| `capture-win13` | Neris | 29 | 29 | 4–5 |

Chỉ ba trong 15 capture vượt được ngưỡng 24 cảnh báo với bộ ET Open C2 — một giới hạn về
**độ phủ của bộ luật**, được ghi lại chứ không che đi.

**Cấu hình bộ phát hiện.** Snort 2.9.20 GRE (Build 82), libpcap 1.10.4, PCRE 8.39. Chế độ
thường trú trên iface `lo`: luật nạp một lần (~10 giây, ~380 MB RSS), sau đó các frame phát lại
được kiểm tra trực tiếp. Chỉ được chạy **một** bandit thường trú tại một thời điểm — mọi tiến
trình dùng chung `lo` và nếu không sẽ kiểm tra frame của nhau.

**Phần cứng / phần mềm.**

| Mục | Giá trị |
|---|---|
| CPU | AMD EPYC Processor, 4 vCPU |
| RAM | 7.9 GB |
| OS | Ubuntu 24.04.5 LTS |
| Python | 3.11.16 (`.venv` và `/tmp/jev-poc/venv`) |
| Thông lượng Snort | ~34.8 ms/luồng, chế độ thường trú |

**Giao thức thực nghiệm.** 8 vòng REINFORCE, lô 96, seed cố định 11. Mỗi cấu hình được chấm
điểm theo ba cách trong cùng một lời gọi Snort: argmax tất định, kế hoạch ngẫu nhiên, kế hoạch
làm hỏng tất cả. Tỷ lệ phát hiện baseline của mỗi vòng được đo trên luồng chưa biến đổi trước.

---

## 6. Thách thức kỹ thuật

### 6.1 Trích xuất luồng hai chiều

**Triệu chứng.** Phát hiện baseline đọc ra `0/24` — Snort dường như mù với chính những luồng mà
nó được tạo ra để bắt. Mọi con số né tránh phía sau vì thế đều vô nghĩa (chính sách ngẫu nhiên
"né tránh" 100%).

**Nguyên nhân.** Bộ nạp luồng chỉ thu đúng tuple chiều đi `(src, sport, dst, dport, proto)` và
loại bỏ mọi gói của bên trả lời. Bộ ET Open C2 được xây trên `flow:established`: không có nửa
SYN-ACK/ACK, Snort không bao giờ thấy một phiên đã thiết lập, và các luật `content:` im lặng.

**Cách sửa.** Thu cả hai chiều và lưu tuple đảo dưới khoá chiều đi của luồng:

```python
wanted     = {(r.src, int(r.sport), r.dst, int(r.dport), r.proto) ...}
rev_wanted = {(d, int(dp), s, int(sp), proto) for (s, sp, d, dp, proto) in wanted}
```

**Bằng chứng đo được.** Cùng một luồng 10 gói cảnh báo **1** lần khi phát lại cả hai chiều và
**0** lần khi chỉ có 5 gói chiều đi.

### 6.2 Viết lại gói theo hướng

**Triệu chứng.** Sau khi sửa §6.1, khả năng phát hiện *vẫn* là `0/24`. Đây là lỗi thứ hai, độc
lập.

**Nguyên nhân.** Tầng phát lại viết lại IP/port nguồn trên **mọi** gói, kể cả phản hồi của
server. Bên trả lời khi đó dường như đang trả lời một client khác, máy trạng thái TCP bị rối, và
phiên không bao giờ được thiết lập.

**Trước khi sửa:**
```
client  147.32.84.165:1029 → 184.82.148.43:80  thành   198.51.100.1:40001 → 184.82.148.43:80
server  184.82.148.43:80 → 147.32.84.165:1029  thành   198.51.100.1:40001 → 198.51.100.1:40001  ✗
```

**Sau khi sửa:**
```
client  147.32.84.165:1029 → 184.82.148.43:80  thành   198.51.100.1:40001 → 184.82.148.43:80
server  184.82.148.43:80 → 147.32.84.165:1029  thành   184.82.148.43:80 → 198.51.100.1:40001  ✓
```

**Cách sửa.** Chỉ viết lại nguồn của **bên khởi tạo**; thay vào đó thay thế đích của **bên trả
lời**. Đo được: viết lại ngây thơ trên cả 10 gói → 0 cảnh báo; viết lại theo hướng → 1 cảnh báo.
Được triển khai trong cả `snort_batch_service.py` và `snort_resident_service.py`.

### 6.3 Các chế độ lỗi khác đã đo được (tóm tắt)

- **Ánh xạ cảnh báo→luồng phụ thuộc hướng** — một va chạm server→client ghi địa chỉ truy vấn
  vào trường `dst`. Sửa bằng cách cấp cho mỗi truy vấn địa chỉ riêng trong `198.51.100.0/24`
  và phân tích id từ địa chỉ, không phải từ port.
- **Làm hỏng payload tự đảo ngược** — `(b + 1 + 127) % 256` áp dụng hai lần trả về byte gốc,
  nên làm hỏng lại *hoàn tác* việc né tránh (k=4 → 66.7%, k=5 → **0%**). Sửa bằng cách gán byte
  tất định, idempotent.
- **Cửa sổ đọc cảnh báo đóng trước khi Snort xả bộ đệm** — Snort ghi file fast-alert qua một
  luồng có bộ đệm; độ trễ cảnh báo đầu tiên đo được là 0.28–1.25 giây (trung bình 0.77) trong
  khi bộ đọc bỏ cuộc ở 0.60 giây. Chỉ riêng điều này đã tạo ra `baseline 0/24` bất khả thi. Sàn
  được nâng lên 2.5 giây (~2× trường hợp xấu nhất).
- **Luật ET throttle theo `by_src`** — `threshold: type limit, track by_src, count 1` nghĩa là
  một địa chỉ nguồn bị dùng lại sẽ bị throttle và im lặng không sinh cảnh báo. Id phải là duy
  nhất trong toàn bộ lần chạy, không bao giờ tái sử dụng.
- **Ether kép / checksum UDP cũ** — bọc lại một gói đã được đóng gói cho ra `Ether/Ether/IP`,
  thứ Snort bỏ qua; và `del p.chksum` chỉ xoá checksum IP, để lại checksum UDP cũ khiến Snort
  loại bỏ datagram.

Sổ lỗi đầy đủ kèm phép đo: [`docs/REAL_SNORT_IN_THE_LOOP.md`](docs/REAL_SNORT_IN_THE_LOOP.md).

---

## 7. Kết quả và đánh giá

Cả 11 dòng dưới đây là phán quyết Snort thật, được tổng hợp trong
`snort_validation/reports/final_results_table.json`.

### 7.1 Quét chi phí làm hỏng — 24 luồng, `botnet-capture-20110811-neris`

| Chi phí | Né tránh | Số gói hỏng trung bình | Baseline |
|---|---|---|---|
| 0.1 | **100.0%** | 2.88 | 24/24 |
| 0.2 | **100.0%** | 2.88 | 24/24 |
| 0.3 | **100.0%** | 2.88 | 24/24 |
| 0.4 | **100.0%** | 2.88 | 24/24 |
| 0.6 | **100.0%** | 2.88 | 24/24 |

**Đã bão hoà.** Không mức chi phí nào trong dải phân biệt được các chính sách, nên không thể vẽ
được đường biên né tránh–tổn hại ở đây.

### 7.2 Mở rộng số luồng — chi phí 0.6, `botnet-capture-20110811-neris`

| Luồng | Né tránh | Số gói hỏng trung bình | Baseline |
|---|---|---|---|
| 24 | **100.0%** | 2.88 | 24/24 |
| 50 | **100.0%** | 2.42 | 50/50 |
| 100 | **100.0%** | 2.27 | 100/100 |
| 200 | **100.0%** | 2.17 | 200/200 |

Bão hoà vẫn giữ ở 10× số luồng, và tổn hại mỗi luồng *giảm* nhẹ khi lô lớn lên.

### 7.3 Kiểm chứng liên capture — 24 luồng, chi phí 0.6

| Capture | Baseline | Né tránh | Gói hỏng TB | Đối chứng ngẫu nhiên | Làm hỏng tất cả |
|---|---|---|---|---|---|
| `botnet-capture-20110810-neris` | 14/24 | **16.7%** | 0.62 | 2/24 | 4/24 |
| `botnet-capture-20110811-neris` | 24/24 | **100.0%** | 2.88 | 10/24 | 24/24 |

### 7.4 Phát hiện chính

1. **Né tránh đạt được với chi phí payload thấp** — 2.17–2.88 gói mỗi kế hoạch trên 24–200
   luồng. Agent không brute-force: trên capture chính, kế hoạch argmax làm hỏng trung bình 2.88
   gói và đối chứng làm-hỏng-tất-cả cho điểm y hệt (100% ở 2.88 gói), cho thấy tập gói khớp là
   nhỏ. Trên capture anh em, kế hoạch argmax chỉ làm hỏng 0.62 gói và né tránh 16.7%, trong khi
   làm-hỏng-tất-cả cũng né tránh đúng 16.7% (4/24) — ở đó baseline vốn đã phần lớn không bị phát
   hiện, nên việc làm hỏng không mang lại gì.
2. **Nút thắt không phải thuật toán mà là bộ luật.** 100% né tránh ở mọi mức chi phí và mọi
   kích thước lô nghĩa là tập con ET Open C2, với cấu hình hiện tại, không bảo vệ được các luồng
   này một khi một tập gói nhỏ bị làm hỏng.
3. **Tổng quát hoá thất bại giữa các capture cùng họ malware.** 16.7% so với 100% trên hai
   capture Neris, với baseline 14/24 so với 24/24, nghĩa là kết quả gắn với từng capture và
   không thể đọc như một năng lực tổng quát.
4. **Bất nhất baseline là cách giải thích hàng đầu.** Nếu pool chưa biến đổi chỉ bị phát hiện
   58% số lần, thì con số né tránh thừa hưởng chính sự không đáng tin đó.
5. **Thông lượng là số thật, không phải ước lượng.** Snort thường trú chấm 864 luồng trong
   30.1 giây qua 12 lời gọi — 34.8 ms/luồng, so với ~10 giây mỗi lời gọi ở dịch vụ một lần.

### 7.5 Hạn chế

- **Bão hoà chặn phép đo thú vị nhất.** Đường biên chi phí–né tránh dự định (tài liệu gốc ghi
  18%–74%) không thể tái lập; toàn bộ dải chi phí của kế hoạch bị thưởng né tránh chi phối.
- **Độ phủ bộ luật mỏng.** Chỉ 3 trong 15 capture MCFP vượt ngưỡng 24 cảnh báo với ET Open C2.
  Tổng cộng 545 luồng khả dụng trên ba capture đó.
- **Quy mô nhỏ.** 24 luồng mỗi ô liên capture, tối đa 200 luồng. Độ phân giải mỗi ô khoảng 4
  điểm phần trăm.
- **Phòng thủ đóng băng.** Không huấn luyện lại đối kháng, không thích ứng ngưỡng.
- **Hành động chỉ trên payload.** Thời điểm gói, TTL, phân mảnh và chồng lấn được ghi lại nhưng
  không tới được hàm thưởng, nên agent không thể học cách dùng chúng (xem
  [`docs/evasion_ceiling_analysis.md`](docs/evasion_ceiling_analysis.md)).
- **Không tương quan đa luồng.** Phát hiện được chấm theo từng luồng, nên một bộ phòng thủ có
  tương quan phiên không được mô hình hoá.

**Trạng thái: sẵn sàng cho luận văn.** Mọi phép đo đều thật, có seed và tái lập được; mọi hạn
chế đều được ghi lại thay vì làm mờ đi.

---

## 8. Lịch sử dự án

Phần này ghi lại quá trình phát triển của dự án từ các phương pháp dựa trên surrogate sang học
tăng cường ở mức gói thật với xác thực ground-truth.

### Giai đoạn 1: RL dựa trên Surrogate (Đầu 2026)

**Mục tiêu**: Học né tránh đối với một bộ phát hiện surrogate XGBoost được huấn luyện trên các
tập hợp luồng từ Argus.

**Phương pháp**:
- Trích xuất 6 đặc trưng ở mức luồng từ CTU-13: thời lượng, tổng gói, tổng byte, byte nguồn,
  giao thức, trạng thái TCP.
- Huấn luyện XGBoost (100 cây, độ sâu 6) đến 91% F1 trên phân loại botnet (262k luồng botnet,
  202k bình thường, cân bằng đến 405k).
- Môi trường RL: agent biến đổi 6 đặc trưng này mỗi tập (jitter thời lượng, pad byte, nhảy
  giao thức, đổi trạng thái TCP).
- Huấn luyện PPO (50k bước) hội tụ đến ~89% tỷ lệ né tránh trên surrogate.

**Kết quả**: Surrogate cho thấy né tránh cao, nhưng phát hiện **không được xác thực trên phát
hiện thật**. Không có ground truth.

### Giai đoạn 2: Tích hợp Snort Thật (Giữa 2026)

**Mục tiêu**: Xác thực các phát hiện surrogate trên Snort thật và các biến đổi ở mức gói thật.

**Phương pháp**:
- Xây dựng bộ luật ET Open C2: 21,374 luật cảnh báo Emerging Threats có nội dung cho C2/botnet/
  backdoor.
- Thiết lập Snort cư trú trên giao diện loopback; phát lại pcap biến đổi và ghi lại phán quyết.
- Triển khai môi trường ở mức gói thật (`real_packet_env.py`): thay vì biến đổi 6 đặc trưng
  tập hợp, biến đổi payload gói tin thực tế.

**Phát hiện**: Kết quả ban đầu cho thấy `0/24` luồng được phát hiện trên baseline — **điều
bất khả thi** cho một bộ luật dựa trên `flow:established`. Điều tra tiết lộ hai lỗi trọng yếu:

1. **Lỗi làm hỏng payload**: Các biến đổi đang XOR toàn bộ gói bao gồm header, không chỉ payload,
   khiến TCP checksum bị lỗi âm thầm và Snort bỏ phiên trước khi kiểm tra.
2. **Lỗi thời gian phát lại**: Phát lại PCAP không bảo tồn độ trễ giữa các gói; Snort đang nhìn
   thấy các đợt nén và các luật phụ thuộc vào thời gian bị lỗi.

Sau khi sửa, baseline nhảy lên **78.5% được phát hiện** (kỳ vọng cho một IDS chữ ký thật).

### Giai đoạn 3: RL ở mức gói với Ground Truth (Cuối tháng 9 năm 2026)

**Mục tiêu**: Học né tránh trong một cài đặt thực tế với các gói thật, Snort thật, và ground
truth tái lập được.

**Phương pháp**:
- Môi trường ở mức gói thật (`real_packet_env.py`): tải pcap thô, phơi các đặc trưng từng gói
  (TTL delta, fragmentation, overlap, kích thước payload, mô hình retransmit).
- Agent học một **kế hoạch biến đổi hoàn chỉnh cho mỗi luồng** (một hành động = mặt nạ nhị phân
  cho 32 gói).
- Các biến đổi chỉ áp dụng **trên byte payload**, bảo tồn tính nhất quán TCP.
- Phần thưởng là phán quyết Snort thật (±50, −2, −0.1 mỗi bước, −chi phí).
- 100k bước huấn luyện trên CPU.

**Kết quả**:
- Capture chính: 100% né tránh, 2.88 gói làm hỏng mỗi luồng, chi phí 0.6.
- Capture anh em (Neris): 16.7% né tránh — **khả năng tổng quát hoá thất bại**.
- Mọi mức chi phí (0.1 → 0.6) và kích thước lô (24 → 200) hội tụ cùng tỷ lệ.
- **Kết luận**: Né tránh là học được nhưng không tổng quát hoá được; bộ phát hiện có thể thích
  ứng (tương quan đa luồng, chuẩn hoá nội dung) để phục hồi.

### Tại sao quay trở lại

Phương pháp surrogate nhanh chóng và trực quan, nhưng **nó che giấu hai lỗi trọng yếu đã làm
vô hiệu hóa tất cả các phát hiện**. Bằng cách buộc các mục tiêu qua các phán quyết Snort thật,
chúng tôi phát hiện ra lỗi, sửa chúng, và tăng độ tin cậy vào các phép đo cuối cùng. Công thức
ở mức gói thực tế hơn (lưu lượng malware thực tế, các biến đổi thực tế) và khó thoát hơn (né
tránh yêu cầu học, không chỉ làm rối lưu lượng).

---

## Bắt đầu nhanh

**Điều kiện tiên quyết.** Snort 2.9.20 (`snort -V`), một venv Python 3.11 với `torch`,
`scapy`, `numpy`, `pandas`, `pyarrow`, `gymnasium`, và quyền root (chế độ thường trú bơm frame
trên `lo`).

```bash
# 1. Vào thư mục kho
cd /root/.hermes/c2-evasion-rl

# 2. Môi trường — venv trong kho chứa sẵn stack RL + gói tin
.venv/bin/python -V                      # Python 3.11.16

# 3. Kiểm tra Snort và bộ luật C2
snort -V | head -2                       # Version 2.9.20 GRE (Build 82)
wc -l snort_validation/et_open_c2/et_open_c2.rules    # 21,419 dòng

# 4. Kiểm tra mỗi capture thực sự cung cấp bao nhiêu luồng khả dụng
.venv/bin/python snort_validation/capture_pool_sizes.py --dataset stratosphere

# 5. Chạy toàn bộ sweep (liên capture + quét chi phí + mở rộng + bảng cuối)
ROUNDS=8 bash snort_validation/run_stratosphere_sweep.sh

# 6. Đọc bảng kết quả 11 dòng
.venv/bin/python -c "import json;d=json.load(open('snort_validation/reports/final_results_table.json'));print(d['count'],'rows')"

# 7. Một thí nghiệm đơn, chế độ thường trú
.venv/bin/python ai_agent/snort_bandit.py --flows 24 --rounds 8 --batch 96 \
    --corrupt-cost 0.6 --resident --dataset stratosphere \
    --capture botnet-capture-20110811-neris

# 8. Kiểm thử
.venv/bin/python -m pytest snort_validation/test_snort_batch_service.py -v
.venv/bin/python snort_validation/test_stratosphere_sweep.py
```

**Hai nguyên tắc vận hành.**

- Chỉ chạy **một** bandit thường trú tại một thời điểm — mọi tiến trình dùng chung iface `lo`.
- `--flows N` là một yêu cầu, không phải bảo đảm. Kiểm tra `capture_pool_sizes.py` trước, nếu
  không bandit sẽ âm thầm đo một pool nhỏ hơn báo cáo khai báo.

---

## Tài liệu

| Tài liệu | Nội dung |
|---|---|
| [`docs/REAL_SNORT_IN_THE_LOOP.md`](docs/REAL_SNORT_IN_THE_LOOP.md) | Snort thật trong vòng thưởng, sổ lỗi đầy đủ, thông lượng |
| [`docs/CHANGELOG_SNORT_INTEGRATION.md`](docs/CHANGELOG_SNORT_INTEGRATION.md) | Mọi thay đổi từ khi đưa Snort vào tới lúc chuyển sang Stratosphere |
| [`docs/DATASET_AND_RULESET_SWITCH.md`](docs/DATASET_AND_RULESET_SWITCH.md) | Vì sao pcap thật + ET Open thay thế lưu lượng tổng hợp + luật tự viết |
| [`docs/dataset-sources.md`](docs/dataset-sources.md) | Nguồn tải mọi capture pcap, kèm URL và dung lượng đã kiểm chứng |
| [`docs/SNORT_DECISION_BOUNDARIES.md`](docs/SNORT_DECISION_BOUNDARIES.md) | Ngữ nghĩa luật đo được: `flow:established`, ngưỡng neo, `any any` |
| [`docs/evasion_ceiling_analysis.md`](docs/evasion_ceiling_analysis.md) | Vì sao liên kết hành động→thưởng giới hạn né tránh |
| [`docs/packet_level_rl.md`](docs/packet_level_rl.md) | Thiết kế môi trường mức gói rời rạc |
| [`docs/packet_level_rl_results.md`](docs/packet_level_rl_results.md) | Kết quả mức gói so với Snort thật |
| [`docs/tcp10_trained_results.md`](docs/tcp10_trained_results.md) | Kết quả model huấn luyện trên tập con |
| [`snort_validation/README.md`](snort_validation/README.md) | Cách dùng tầng xác thực |
| `FINAL_EXECUTION_REPORT.md` | Tóm tắt thực thi của sweep Stratosphere |
| `FINAL_CORRECTED_REPORT.md` | Phân tích kỹ thuật đầy đủ và các phép đo đã sửa |

## Cấu trúc thư mục

```
ai_agent/                  môi trường, bandit, huấn luyện PPO, đánh giá
  real_packet_env.py         môi trường gói thật, nạp luồng hai chiều
  snort_bandit.py            bandit REINFORCE trên mặt nạ làm hỏng từng gói
snort_validation/          dịch vụ phát hiện, bộ dữ liệu, bộ luật, báo cáo
  snort_resident_service.py  Snort sống lâu trên iface lo (~34.8 ms/luồng)
  snort_batch_service.py     phán quyết pcap theo lô, một lần
  capture_pool_sizes.py      pool luồng khả dụng đo được của mỗi capture
  aggregate_results.py       sweep + scale + cross-capture → bảng cuối
  et_open_c2/                bộ luật ET Open C2 đã lọc + cấu hình Snort
  reports/                   kết quả JSON, gồm final_results_table.json
blue_team/                 huấn luyện judge surrogate (giai đoạn mức luồng)
red_team/                  server + client beacon C2 giả (chỉ demo; hai
                           interceptor NFQUEUE đã bị xoá — nạp model chết)
data/                      capture, bảng parquet có nhãn, encoder
docs/                      ghi chú thiết kế, phân tích, sơ đồ
tests/                     kiểm thử đơn vị cho bộ biến đổi gói và môi trường
```

## Tham khảo

- [Stratosphere IPS / CTU-13](https://www.stratosphereips.org/datasets-ctu13) — nhà phát hành capture
- [Máy chủ phân phối MCFP](https://mcfp.felk.cvut.cz/publicDatasets) — gương pcap chính thức
- [Luật Emerging Threats Open](https://rules.emergingthreats.net/open/) — bộ luật độc lập
- [Snort 2.9](https://www.snort.org/) — bộ phát hiện được kiểm nghiệm
- [Stable-Baselines3](https://stable-baselines3.readthedocs.io/) · [Gymnasium](https://gymnasium.farama.org/)
