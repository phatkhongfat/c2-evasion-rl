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

Số rule trong vùng đó **rất nhiều** — không phải giới hạn của ruleset:

| bucket (L = content dài nhất) | số rule |
|---|---|
| L ≥ 32 | 2623 |
| 24 ≤ L < 32 | 2261 |
| 16 ≤ L < 24 | 5013 |
| 8 ≤ L < 16 | 6852 |
| L < 8 | 4611 |

(21374 alert rules; 14 rule không có `content` nào — chỉ pcre/byte_test.)

**Nhưng bucket đó rỗng với dữ liệu capture.** Xem mục kế tiếp.

## Feasibility — công thức trên **không khả thi** với bộ capture hiện có (đã kiểm tra)

Đo toàn bộ 16 capture trong `/tmp/cov`. Chỉ **6 SID duy nhất** từng fire:

| SID | alert line | capture | L | pcre |
|---|---|---|---|---|
| 2016413 | 939 | win13 | 6 | no |
| 2019486 | 738 | rbot, rbot-dos | 8 | yes |
| 2014169 | 290 | neris | 7 | no |
| 2019471 | 16 | rbot, rbot-dos | 8 | yes |
| 2012533 | 10 | neris, fast-flux | 11 | yes |
| 2014635 | 6 | fast-flux | 3 | no |

Không SID nào có `L ≥ 16`. **Bucket `16 ≤ L < 24` và `L ≥ 32` — nơi fragmentation
phân kỳ — không có một flow nào trong dữ liệu này.** Đây là hạn chế của *capture*,
không phải của ruleset: ET Open có 9897 rule ở các bucket đó, nhưng không traffic nào
trong CTU-13 kích hoạt chúng.

**Sửa một suy luận sai.** `L < 8` **không** có nghĩa fragmentation không phá được flow
đó — chỉ là pattern *có thể* sống sót nếu khớp ranh giới đơn vị. Các rule `L < 8`
(2016413, 2014169, 2014635) đều mang điều kiện `offset`/`depth`/`distance`/`within`,
nên pattern vẫn bị cắt khi trải qua ranh giới đơn vị — và đo thực nghiệm xác nhận:
`split8` vẫn né thành công **33/33 dns** và **6/6 http**. Phát biểu đúng là:

> Fragmentation đã ở **trần** trên toàn corpus (100% ở cả 5 SID có mặt), và không
> cơ chế nào phá được nhiều hơn thế. Tương đương giữa split8/16/24/split_slow là
> hệ quả của việc **cả nhóm đã chạm trần**, không phải vì chúng giống nhau về cấu trúc.

`L` cho ta **điều kiện cần** để phá (L > U ⟹ chắc chắn bị cắt), không phải điều kiện
đủ — `offset`/`within` mới quyết định phần còn lại, và phần đó chỉ giải được bằng
sweep thật, không suy ra được từ ruleset.

**Cơ chế phân kỳ duy nhất trong toàn bộ capture: SID 2017287** (IRCBot PRIVMSG —
2 content dài 8, không pcre). Ở đây L = 8 *bằng* đúng đơn vị nhỏ nhất, nên pattern sống
sót *nếu* align: `split8` phá gần như chắc chắn, `split24` phá ít hơn nhiều. Nhưng
**2017287 không xuất hiện trong bất kỳ capture nào**, và corpus v3fixed chỉ có 1 IRC flow.

**Hệ quả cho "per-flow selection".** Kể cả khi headroom > 0, kết quả sẽ là chọn
fragmentation với kích thước khác nhau theo flow — selection *trong một họ cơ chế*,
chưa phải chọn *giữa các họ*. Muốn luận điểm mạnh hơn, corpus phải có flow thuộc họ
khác (byte-preserving không phải fragmentation). Điều kiện này chưa được đăng ký
trước và không nên thêm giữa chừng.

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
> Trên corpus v3fixed, fragmentation đạt 100% ở mọi SID family có mặt, nên `oracle`
> trùng `best_single` và headroom bằng 0. Đây là thuộc tính của **corpus**: 5 SID
> family duy nhất mà CTU-13 sinh ra đều kích hoạt bằng pattern ngắn (≤ 11 byte) với
> điều kiện depth/offset/within, nên không có ngưỡng phân biệt nào giữa các kích thước
> phân mảnh.

Không được claim: "RL chọn mechanism thông minh hơn heuristic", hay bất kỳ phát biểu
nào ngụ ý có per-flow selection. Cũng không được claim rằng fragmentation "vô dụng"
với mọi rule — nó **tối ưu** cho các rule có pcre hoặc L ≥ 8, và **thua** cho rule có
L < 8 mà điều kiện offset/within vô hại.

## Hướng tiếp theo — câu 1 đã được trả lời, và câu trả lời là "không"

1. ~~Chọn lại corpus theo geometry, mục tiêu bucket `16 ≤ L < 24`.~~
   **Đã kiểm tra 2026-10-12: bất khả thi.** Không capture nào sinh SID có `L ≥ 16`
   (bảng ở mục Feasibility). Đây là hạn chế dữ liệu, không phải việc chờ thêm nỗ lực.
2. **Đã đạt** — không train trước khi đo headroom (bài học P4/P6).
3. ~~Nếu (1) không tìm được flow phù hợp, dừng và trình bày negative result có kiểm
   soát.~~ **Điều kiện này đã kích hoạt.** Đây là kết luận của bài hiện tại.

Nếu muốn mở lại hướng headroom > 0, cần **data acquisition mới** — một capture có
traffic kích hoạt rule C2 có `L ≥ 16`, hoặc một family không phải fragmentation.
Đó là thu thập dữ liệu, không phải thí nghiệm để chạy trên dữ liệu hiện có. Khi có,
chạy lại gate H1 trước, theo đúng kỷ luật đã đăng ký.

## Ghi chú phương pháp

- Phân tích này chỉ đọc `et_open_c2.rules`, `snort_et_c2.conf` và các report JSON đã
  có. Không thay đổi ruleset, không thêm action, không sửa số trong report.
- Conf eval (`snort_et_c2.conf`) **không có** directive `reassemble` nào; chỉ
  `stream5_tcp: policy first, use_static_footprint_sizes`. Đây là điều kiện để
  fragmentation có tác dụng và nên được nêu rõ khi mô tả setup.
- Trường `sid` trong `div_probe.json` là list; phải kiểm `baseline_sids` trên corpus
  thay vì `alert_sids` (pickle v3fixed dùng `baseline_sids`, rỗng với pool probe).