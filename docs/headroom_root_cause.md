# Root cause: vì sao oracle = fragmentation (và oracle ≠ split8)

Ngày: 2026-10-12. Phân tích read-only trên artifact sẵn có; không train, không sweep mới.

## TL;DR

`headroom = 0` là **hệ quả cấu trúc của corpus**, không phải giới hạn của thuật toán.
Cả 5 SID family trong corpus v3fixed đều có pattern kích hoạt **≤ 11 byte** và/hoặc là
hội của nhiều content, nên **mọi fragmentation unit ≥ 8 byte đều phá vỡ chúng một
cách giống hệt nhau**. Hành động fragmentation tạo ra một lớp tương đương, không phải
một lựa chọn duy nhất — vì vậy oracle co về một điểm và không gì có thể vượt.

## Bằng chứng 1 — geometry của 5 SID family (đọc từ `et_open_c2.rules`, đúng ruleset eval)

| SID | family | framing | số content | độ dài content | điều kiện |
|---|---|---|---|---|---|
| 2016413 | DNS reply sinkhole | dns | 2 | 4, 6 | distance+within |
| 2014169 | DNS .su TLD | dns | 3 | 1, 7, 4 | depth+offset+fast_pattern |
| 2012533 | Virut HTTP checkin | http | 4 | 4, 11, 3, 3 | pcre + flow:established,to_server |
| 2014635 | Kazy TLS ClientHello | http | 2 | 3, 1 | byte_jump + byte_test |
| 2017287 | IRCBot PRIVMSG | irc | 2 | 8, 8 | within:100 + flow:established,from_server |

Độ dài đo bằng `controls/rule_geometry.py` (đọc trực tiếp `et_open_c2.rules`).
Lưu ý: pattern hex trộn ASCII phải đếm theo byte đã decode — `|02|su|00|` là
1 + 2 + 1 = 4 byte, không phải 2. Parser ban đầu của tôi đếm sai và đã bị test bắt.

Pattern dài nhất toàn corpus: **11 byte**. Đơn vị fragmentation nhỏ nhất trong action
space là `split8`. Một content chỉ sống sót nếu nằm trọn trong một đơn vị; với pattern
11 byte (2012533) thì **không đơn vị nào với U ≤ 11 giữ được nó**, và các content còn lại
của rule đó (4, 3, 3 byte) nằm rải rác nên hội conjunction gần như chắc chắn bị phá.

**Vì mọi rule đều chết dưới `split8`, chúng chết dưới `split16` và `split24` y hệt** —
fragmentation lớn hơn chỉ làm pattern khó sống sót hơn, không làm nó sống lại. Đó chính
là lý do oracle trùng với "một action bất kỳ trong họ fragmentation", không phải với
`split8` cụ thể.

Đây là giải thích cấu trúc, không phải suy luận từ hành vi: nó đọc trực tiếp từ ruleset.

## Bằng chứng 2 — đối chiếu với số đo thực nghiệm (không cần chạy lại)

Các phép đo real-Snort đã commit đều cho kết quả **giống hệt nhau** giữa các
fragmentation, đúng như dự đoán:

| cơ chế | valid evasion (test 40) | nguồn |
|---|---|---|
| split8 | 40/40 | `ppo_v3_both_test_s*.json` |
| split16 | 40/40 | `ppo_v3_both_test_s*.json` |
| split24 | 40/40 | `ppo_v3_both_test_s*.json` |
| split_slow | 40/40 | `ceiling_v3_splitslow_fixed.json` |
| reorder / ttl | 0/40 | `ceiling_v3_reorder_ttl_fixed.json` |

Tức là vùng hành vi gồm đúng **hai** lớp: fragmentation (thắng tuyệt đối) và mọi thứ
khác (0/40). Đó là hình dạng của một action space bị **chia đôi theo vùng**, không phải
một bài toán lựa chọn có headroom.

## Bằng chứng 3 — công thức tạo headroom > 0 (đã kiểm chứng trên ruleset)

Muốn `best_single < oracle`, cần một flow mà **ngưỡng phân biệt nằm giữa hai
fragmentation unit**. Quy tắc với content dài `L` sẽ:
- chết dưới unit `U < L`,
- sống nếu `U ≥ L` và offset may mắn khớp.

Nên nếu corpus chứa flow alert dưới rule có `16 ≤ L < 24`, thì `split8` phá được
nhưng `split24` không — và ngược lại ở flow khác. Đó chính là per-flow selection.

Ruleset hiện có **rất nhiều** rule thuộc vùng đó — không phải giới hạn của nguồn:

| bucket (L = content dài nhất) | số rule |
|---|---|
| L ≥ 32 | 2623 |
| 24 ≤ L < 32 | 2261 |
| 16 ≤ L < 24 | 5013 |
| 8 ≤ L < 16 | 6852 |
| L < 8 | 4611 |

(21374 alert rules; 14 rule không có `content` nào — chỉ pcre/byte_test.)

Corpus v3fixed chỉ rơi trúng bucket `L < 8` và `8 ≤ L < 16`. Đây là lựa chọn khi
build corpus, không phải hạn chế của ET Open.

## Hai lỗi integrity phát hiện khi audit (ảnh hưởng trích dẫn, không đổi verdict)

**L1 — `div_probe.json` không có đủ positive examples.**
12 flow trong pool, nhưng **chỉ 8 flow alert ở baseline**; 4 flow có
`baseline_alert = False` và `sids = []` (2 neris DNS, 2 rbot IRC). Gọi "valid_evasion"
trên flow không alert là vô nghĩa — không có gì để né.

Tính lại trên đúng 8 flow baseline-positive:

| chỉ số | giá trị |
|---|---|
| oracle | 8/8 |
| best_single (split8) | 8/8 |
| headroom | **0** |

→ Verdict NO-CLAIM **vẫn đúng**, nhưng con số "12/12" trước đó phải rút lại thành 8/8.
`div_probe.json` không có `noop` nên không thể dùng làm noop control.

**L2 — `/tmp/div_probe_pool.pkl` nhân bản train/test.**
`train` (6 flow) trùng **chính xác** 6 flow đầu của `test` (12 flow); overlap = 6/6.
Pool này chỉ dùng cho sweep đọc, chưa từng train, nên chưa làm hỏng kết quả nào —
nhưng nó **không dùng được để train** nếu ai đó định dùng lại.

## Hệ quả cho bài

Được claim, và nay có **cơ chế giải thích** thay vì chỉ có số:
> Trên corpus v3fixed, mọi SID family đều kích hoạt bằng pattern không vượt quá 11 byte
> với điều kiện depth/offset/within, nên toàn bộ nhóm fragmentation (split8/16/24,
> split_slow) là các hành động tương đương về hiệu quả trên corpus này. Oracle trùng
> với lớp tương đương ấy, nên headroom bằng 0 là thuộc tính của corpus.

Không được claim: "RL chọn mechanism thông minh hơn heuristic", hay bất kỳ phát biểu
nào ngụ ý có per-flow selection.

## Hướng tiếp theo, theo thứ tự rẻ trước đắt

1. **Chọn lại corpus theo geometry, không theo SID identity.** `build_corpus_v3.py`
   đã có hạ tầng lọc theo SID; cần thêm bước chọn flow theo *độ dài content dài nhất
   của rule alert nó*, mục tiêu có flow trong bucket `16 ≤ L < 24`. Đây là thay đổi
   nhỏ nhất có khả năng tạo headroom.
2. **Chỉ chạy gate H1 (đo headroom bằng sweep) sau khi chọn được corpus mới.** Không
   train trước — bài học P4/P6 đã phải trả giá 2 lần cho việc train khi headroom = 0.
3. Nếu (1) không tìm được flow phù hợp trong capture hiện có, **dừng và trình bày
   negative result có kiểm soát** thay vì mở rộng scope.

## Ghi chú phương pháp

- Phân tích này chỉ đọc `et_open_c2.rules`, `snort_et_c2.conf` và các report JSON đã
  có. Không thay đổi ruleset, không thêm action, không sửa số trong report.
- Conf eval (`snort_et_c2.conf`) **không có** directive `reassemble` nào; chỉ
  `stream5_tcp: policy first, use_static_footprint_sizes`. Đây là điều kiện để
  fragmentation có tác dụng và nên được nêu rõ khi mô tả setup.
- Trường `sid` trong `div_probe.json` là list; phải kiểm `baseline_sids` trên corpus
  thay vì `alert_sids` (pickle v3fixed dùng `baseline_sids`, rỗng với pool probe).