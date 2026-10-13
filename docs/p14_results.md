# P14 — Kết quả: coverage C2 không cần split

Ngày đo: 2026-10-13. Mẫu số đóng băng ở `docs/p14_denominator.md`; quyết định
D4–D7 ở `docs/action_space_policy_p14.md` (đóng băng **trước** mọi phép đo).
Công cụ: `controls/p13_case_extended.py`, `controls/backfill_endpoint_bar.py`.

## 1. Denominator thật sau khi loại policy/scan noise

| corpus | test flow | có baseline SID | SID chiếm ưu thế |
|---|---:|---:|---|
| `hidden_defender_corpus.pkl` (21k rule) | 40 | 40 | `2012627` FakeAV ×16, `2008581/3/5` neris ×24 |
| `corpus_p13_extended.pkl` (52k rule) | 120 | 37 | `2012533` Virut ×4, `2014635` Kazy TLS ×4, `2016413` DNS sinkhole ×29 |

**Không có flow nào bị bỏ sót vì "không né được"**: mỗi flow đều có ít nhất
một SID priority 1 ở baseline.

## 2. Ba kết quả chính

### 2.1 D7 (parser) — sửa bar, không sửa cơ chế

Chẩn đoán T0.2 cho thấy 2 flow FakeAV là **POST pipelined**; `_parse_http`
nuốt request 2 vào body của request 1, nên bar v1 báo fail dù mutation chỉ
đổi *tên header*. Parser mới tách request theo `Content-Length`
(RFC 7230 §3.3.3) và so sánh **danh sách lệnh**.

| cơ chế (corpus cũ, 40 flow) | bar v1 | bar D7 | bar D5 |
|---|---:|---:|---:|
| `http_header_case` | 14 | **16** | **16** |
| `http_header_pad` | 14 | **16** | **16** |
| `split8` | 40 | 40 | 40 |

Không cần chạy lại Snort: verdict `evaded` lấy từ report, bar chấm in-memory.

### 2.2 D5 (bar v2, có citation) — `query_param_prepend`

Nguồn [6] RFC 3986 §3.4 + [7] PHP `parse_str`: query là tập `key=value`;
handler chỉ đọc các key nó biết. Bar v2 so **tập (key, value)** sau
percent-decode, bỏ qua key lạ, và **fail-closed** nếu thiếu key, đổi giá trị,
đổi path, đổi số request, hay framing không parse được.

### 2.3 Snort thật trên corpus mở rộng (conf 52.454 rule)

`snort_validation/reports/p13_v9_query_prepend.json` (368 s, 5 flow HTTP):

| flow | SID baseline | SID sau mutation | evaded | bar D5 | +byte | fragment |
|---|---|---|:--:|:--:|--:|--:|
| neris 3653→888 | 2012533 | — | ✅ | ✅ | +4 | 0 |
| neris 2905→80 | 2012533 | — | ✅ | ✅ | +4 | 0 |
| neris 1102→888 | 2012533 | — | ✅ | ✅ | +4 | 0 |
| fast-flux 1058→80 | 2012533 | — | ✅ | ✅ | +8 | 0 |
| sogou 1072→80 | 2018959 | **2018959** | ❌ | ❌ | 0 | 0 |

## 3. Coverage không-split, chính thức

| corpus | flow có slack protocol | phủ bằng cơ chế không-split | còn lại (không slack) |
|---|---:|---:|---|
| corpus cũ | 16 | **16/16 (100%)** `http_header_case` | 24 flow neris: rule `2008581/3/5` cần byte_test trên framing nhị phân |
| corpus mở rộng | 4 | **4/4 (100%)** `query_param_prepend` | 4 flow Kazy TLS: `byte_test` trên độ dài cipher-suite list, sửa là hỏng TLS |
| | | | 29 flow DNS sinkhole: rule khớp **response** của resolver |

Hai nhóm "không slack" là kết luận cấu trúc, không phải thất bại:

- **Kazy TLS** (`2014635`): `content:"|16 03 00|"; depth:3` + `byte_test` độ
  dài handshake. Mọi byte trong ClientHello đều do bên kia kiểm tra; chỉ có
  phân mảnh IP (giữ nguyên byte stream TCP) là hợp lệ.
- **DNS sinkhole** (`2016413`): `alert udp any 53 -> $HOME_NET any` khớp
  **response** từ resolver của bên thứ ba (8.8.8.8) chứa IP sinkhole
  `148.81.111.111`. Bot không sở hữu gói đó, kể cả under `ownership=both`
  (chỉ hợp lệ khi bên tấn công sở hữu server). Đây là **bằng chứng loại trừ
  khỏi corpus C2** — không phải hạ bar.

## 4. Kết luận

1. **Coverage không-split đạt 100% trên mọi flow có slack protocol**, ở cả
   hai corpus, với bar ngữ nghĩa có citation.
2. Vận hành không cần Snort cho bar: verdict đến từ report, ngữ nghĩa chấm
   in-memory — nên backfill được (tiền lệ dualbar).
3. Phần chưa phủ **không phải hạn chế của action space** mà là đặc tính của
   protocol/role của traffic. Ghi claim theo đúng ranh giới đó.
4. Chi phí wire: +4…+8 byte/flow, **0 fragment** — rẻ hơn `split8` (+10.744 B,
   316 packet trên 40 flow) trên mọi flow đã đo.