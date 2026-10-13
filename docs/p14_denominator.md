# P14 — Mẫu số threat-model đóng băng (đo TRƯỚC mọi phép thử cơ chế mới)

Ngày đóng băng: 2026-10-13. Nguồn: `snort_validation/reports/p13_v7_noop.json`
(120 test flow × noop, conf `rulesets/p13/snort_et3000.conf` 52.454 rule),
`ceiling_v4_both_test_dualbar.json`, `ceiling_v6_case_fullrules_dualbar.json`,
rule text dump từ `rulesets/p13/et_open_3000.rules`.

## Chính sách mẫu số (D4, mở rộng từ quyết định đóng băng P12 về P2P)

Flow thuộc mẫu số C2 iff `baseline_alert=True` và `baseline_sids` chứa ≥1 SID
có classtype trojan/malware. Loại: `policy-violation` (tiền lệ: user đã đóng
băng loại BitTorrent DHT `{2008581,2008583,2008585}` khỏi corpus C2),
scan/recon (`attempted-recon`, `bad-unknown` ET SCAN). Classtype là metadata
tác giả rule, cố định trước mọi phép đo. **Mọi báo cáo nêu cả số thô lẫn
số threat-model.**

## Corpus cũ (hidden_defender_corpus.pkl, test = 40 flow)

| nhóm | flow | SID | ghi chú |
|---|---:|---|---|
| ngoài mẫu số (P2P DHT, policy-violation) | 24 | 2008581/83/85 | đóng băng từ P12 |
| **mẫu số C2** | **16** | 2012627 FakeAV | 14 endpoint-valid với `http_header_case`; 2 flow fail do **bug parser** (xem D7), không phải do cơ chế |

## Corpus mở rộng (corpus_p13_extended.pkl, test = 120 flow)

115 flow có baseline alert. Phân loại classtype: loại 78 flow
(`attempted-recon` 56, `bad-unknown` 9, `protocol-command-decode` 12,
`policy-violation` 1). **Mẫu số C2 = 37 flow:**

| SID | flow | rule match | slack client-side? |
|---|---:|---|---|
| 2012533 Virut.BN checkin | 4 | `content:"list.php?c=" within:32` + `&v=`/`&t=` distance:0 + `pcre:/c\x3d[0-9A-F]{100}/i`, hướng to_server, HTTP GET | **CÓ** — chèn param lạ sau `?` phá literal chain, query parser chuẩn vẫn đọc đúng `c/v/t` → cơ chế `query_param_prepend` |
| 2014635 Kazy SSL hello | 4 | `|16 03 00|` depth:3 + byte_extract/byte_test trên trường độ dài ClientHello | **KHÔNG** — bytes TLS handshake protocol-fixed; đổi độ dài = hỏng TLS. Chỉ split (IP-frag dưới tầng TCP) |
| 2016413 DNS sinkhole reply | 29 | `alert udp any 53 -> $HOME_NET` — match **RESPONSE** của resolver (IP sinkhole cert.pl `|00 04 94 51 6f 6f|`) | **KHÔNG — ngoài threat model**: bot không sửa được response từ resolver bên thứ ba (8.8.8.8) với bất kỳ ownership model nào. Đây là traffic đã bị sinkhole từ 2013 |

→ **Mẫu số REACHABLE (client-ownership) của v8 = 4 flow Virut.** Mục tiêu
`query_param_prepend`: 4/4. Hai nhóm kia báo cáo trung thực là không-slack /
ngoài threat model, KHÔNG đếm vào coverage đạt được.

## D7 (mới, từ chẩn đoán T0.2) — endpoint parser phải đọc Content-Length

Hai flow FakeAV fail-endpoint với `http_header_case` **không phải do cơ chế**:
stream client chứa 2 request POST pipelined; cơ chế hạ case field name của cả
hai (đúng RFC 7230 §3.2, và cần thiết để rule chết trên cả hai request),
nhưng `_parse_http` lấy *mọi thứ sau `\r\n\r\n` đầu tiên* làm body nên
"lệnh" của request 1 bao gồm nguyên văn request 2 → so sánh byte fail.

Fix: parser tôn trọng Content-Length (RFC 7230 §3.3.3) và trả về **danh
sách lệnh của từng request** trong stream pipelined (§6.3.2). Đây là sửa
bug độ chính xác của mô hình endpoint (handler thật đọc theo CL, không nuốt
request kế tiếp vào body), áp dụng đồng đều cho MỌI cơ chế, bar v1 giữ
nguyên để đối chiếu — theo đúng tiền lệ two-bar. Endpoint validity tính
in-memory nên backfill vào report cũ không cần chạy lại Snort.

## Ngân sách đo còn lại

Probe 4 flow Virut × 3 mech (noop/query_param_prepend/split8) × ~70s ≈ 15
phút conf 52k. Không chạy sweep đầy trước khi probe qua gate.
