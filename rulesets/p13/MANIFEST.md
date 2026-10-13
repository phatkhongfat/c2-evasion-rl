# MANIFEST — ruleset ứng viên P13

Ghi **trước** mọi phép đo headroom. Commit này là bằng chứng chống benchmark
thiên lịch: danh sách ứng viên bị đóng băng ở đây, và mọi dòng kết quả (kể cả
dòng cho `headroom = 0`) đều phải được báo cáo.

Không commit file `.rules` / `.tar.gz` (~30 MB). Chỉ commit manifest này.

---

## Ứng viên A — ET Open 3.0.0 (`emerging.rules.tar.gz`)

| Mục | Giá trị |
|---|---|
| URL | `https://rules.emergingthreats.net/open/snort-3.0.0/emerging.rules.tar.gz` |
| Kích thước | **5 743 875 byte** (khớp số đã kiểm chứng trước khi viết plan) |
| sha256 | `54cead46d842ef668c6f05f5adc767f537dacd34960bce6284826f568b0d83f1` |
| Tải về | 2026-10-13 |
| Số SID duy nhất | **71 399** |
| Khoảng SID | **2000005 – 2527043** |
| Số rule (`alert\|drop\|pass\|reject\|log`) | **52 500** |
| Bộ lọc C2 | chưa áp — giữ **toàn bộ** 52 500 rule để tránh rơi vào bẫy "lọc bớt rồi tự tạo headroom" |

### So với extract hiện tại (`snort_et_c2.conf`)

| | Extract hiện tại | ET Open 3.0.0 | Chênh |
|---|---:|---:|---|
| Số rule | 21 374 | 52 500 | **×2,46** |
| Khoảng SID | 2000015–2102587 | 2000005–2527043 | rộng hơn ~4× |
| SID 2012627 (FakeAV C2) | có | **có, rule trùng khớp từng byte** | — |

### SID ta quan tâm — tất cả đều còn (2026-10-13)

`2012627` · `2019471` · `2019486` · `2012533` · `2014169` · `2014635` · `2016413`
→ đều **CÓ**. Ứng viên A là **superset** của extract hiện tại, không phải tập rời.

### Điều ứng viên A **KHÔNG** làm được (ghi trước để không bị bất ngờ)

**SID bắt header evasion vẫn vắng mặt**: `1-38381`, `1-38601`, `1-39320` — **KHÔNG**
có trong 71 399 SID của ứng viên A. Đây là các SID namespace `1-xxxxx` thuộc ET
Open *full*, không thuộc subset *emerging*. Nghĩa là **ứng viên A không làm khó
thêm trục `http_header_case`** — nó chỉ lớn hơn trên cùng namespace `2-xxxxxx`.

→ Nếu `http_header_case` cần được dập bởi rule thật thì ứng viên A **không** phục
vụ mục tiêu đó. Ghi nhận đây là kết quả **trước khi đo**, không phải lý do bỏ ứng
viên (mọi ứng viên vẫn phải được đo và báo cáo).

### Phân bố nhóm rule

| File | Số rule |
|---|---:|
| `emerging-trojan.rules` | 19 207 |
| `emerging-malware.rules` | 626 |
| `emerging-dns.rules` | 54 |
| `emerging-botcc.rules` | 10 |

---

## Ứng viên B — không tải, chỉ định danh

| Mục | Giá trị |
|---|---|
| Tên | ET Open **full** (không phải subset emerging) — chứa SID namespace `1-xxxxx` |
| Lý do chưa tải | `ceiling_v4_both_test` đã đo trên "default (ET Open full)" rồi — 600 cell, kết quả đã ghi |
| Vai trò | Đây là **ứng viên đã đo**, không phải ứng viên mới |

---

## Quy tắc bất biến của Phase 3

1. Chạy **mọi** ứng viên vượt S1, không chọn lọc.
2. Báo cáo **kể cả** ứng viên cho `headroom = 0`.
3. Nếu sau này cần thêm ứng viên, phải ghi lý do **trước khi** đo ứng viên đó
   vào file này, commit riêng.
4. Không hạ bar, không thêm action chỉ để mở headroom.