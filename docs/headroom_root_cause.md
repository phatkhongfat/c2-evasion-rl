# Root cause: vì sao oracle = fragmentation (và oracle ≠ split8)

Ngày: 2026-10-12. Bắt đầu là phân tích read-only trên artifact sẵn có (P7–P9); từ
**P11 trở đi đã chạy sweep Snort thật** — xem `ceiling_v4_*.json`.

## TL;DR

`headroom = 0` là **hệ quả cấu trúc của corpus**, không phải giới hạn của thuật toán.
Cả 5 SID family trong corpus v3fixed đều có pattern kích hoạt **≤ 11 byte** và/hoặc là
hội của nhiều content, nên **mọi fragmentation unit ≥ 8 byte đều phá vỡ chúng một
cách giống hệt nhau**. Hành động fragmentation tạo ra một lớp tương đương, không phải
một lựa chọn duy nhất — vì vậy oracle co về một điểm và không gì có thể vượt.

**P11 bổ sung hai điều, một trong đó đảo chiều cách hiểu ở trên.** (a) `headroom = 0`
không phải artifact của cấu hình đo: bật `stream5_tcp: policy last` **hay**
`frag3_engine: policy last` đều không đổi một số nào, vì frag3 Snort 2.9 chỉ chọn
fragment để đối chiếu chứ không dựng lại rồi detect. (b) Trên tập flow hợp lệ — 16
flow có baseline C2 thật (`2012627`), đã loại 102 luật BitTorrent DHT — mọi biến thể
fragmentation đều 16/16, nên `headroom = 0` là kết quả **sạch**. Chi tiết ở P11.

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
| L ≥ 32 | 2391 |
| 24 ≤ L < 32 | 2894 |
| 16 ≤ L < 24 | 8387 |
| 8 ≤ L < 16 | 6382 |
| L < 8 | 1306 |

(21374 alert rules; 13 rule không có `content` nào — chỉ pcre/byte_test.)

> **Đã hiệu chỉnh 2026-10-12.** Bảng trên ban đầu ghi 2623/2261/5013/6852/4611, tính bằng
> parser đang đọc nhầm token hex trần (`d1`, `ad2`) là byte hex thay vì ASCII. Đã sửa
> parser + thêm test khoá. Lưu ý: **số ở Bảng 1 (5 SID family của corpus) không đổi** —
> không SID nào của corpus v3fixed có token hex trần, nên kết luận root cause vẫn đứng.

**Nhưng bucket đó rỗng với dữ liệu capture.** Xem mục kế tiếp.

## Feasibility — **đã kiểm, và kết luận đầu tiên sai** (vì quét thiếu 6/21 capture)

> **Hiệu chỉnh quan trọng, 2026-10-12.** Mục này ban đầu kết luận "bất khả thi". Kết luận
> đó dựa trên `/tmp/cov/*/alert` — tức **15 capture đã quét**. Nhưng máy có **21 pcap**
> trong `data/stratosphere/`, và **2 capture chưa từng chạy Snort** (Botnet-43 neris
> 35M, CTU-13 #12 bot 282M). Quét chúng đã sinh **SID mới chưa từng có trong bảng coverage**.
> Đừng kết luận "dữ liệu không có" trước khi đối chiếu số pcap trên đĩa với số capture
> đã quét — chỉ là `ls /tmp/cov` và không thấy gì.

Đo 15 capture đã quét. Chỉ **6 SID duy nhất** từng fire:

| SID | alert line | capture | L | pcre |
|---|---|---|---|---|
| 2016413 | 939 | win13 | 6 | no |
| 2019486 | 738 | rbot, rbot-dos | 8 | yes |
| 2014169 | 290 | neris | 7 | no |
| 2019471 | 16 | rbot, rbot-dos | 8 | yes |
| 2012533 | 10 | neris, fast-flux | 11 | yes |
| 2014635 | 6 | fast-flux | 3 | no |

Trong 15 capture này, không SID nào có `L ≥ 16`. Nhưng **2 capture chưa quét** đã cho kết quả khác.

### Kết quả quét 2 capture còn lại

| capture | SID mới | alert | L | classtype | là C2? |
|---|---|---|---|---|---|
| Botnet-43 neris (35M) | **2012627** | 481 flow | 78 | trojan-activity | ✅ FakeAV check-in HTTP |
| CTU-13 #12 bot (282M) | 2008581 | 3192 flow | 12 | policy-violation | ❌ BitTorrent DHT |
| | 2008583 | 204 flow | 12 | policy-violation | ❌ BitTorrent DHT |
| | 2008585 | 234 flow | 22 | policy-violation | ❌ BitTorrent DHT |

**Hai kết luận tách biệt:**

1. **SID phân biệt thì có, nhưng là P2P.** `2008581` (L=12) và `2008585` (L=22) nằm đúng
   bucket `8 ≤ L < 24` — `split8` phá được, `split24` thì không. Nhưng `classtype:
   policy-violation`, msg `"ET P2P BitTorrent DHT ..."`. Đưa BitTorrent DHT vào corpus
   "C2 evasion" là **gán nhãn sai đối tượng** — sẽ làm hỏng luận điểm của cả bài.
   **Không dùng.**

2. **SID C2 mới thì không phân biệt theo độ dài.** `2012627` là FakeAV check-in thật
   (`trojan-activity`, 481 flow riêng biệt, beacon HTTP tới 184.82.155.107:80) nhưng
   L = 78 > 24 ⇒ mọi fragmentation đều phá, thuộc lớp tương đương. Theo geometry nó
   **không** tạo headroom.

   Nhưng geometry chỉ cho *điều kiện cần*, không phải điều kiện đủ: `2012533` (L=11,
   cũng `< 24`) lại cho `split24` 40/40 khi đo thực nghiệm. Nên **chưa thể kết luận**
   `2012627 không phân kỳ — phải sweep thật trên 481 flow đó mới biết. Đây là gate H1
   trên vật liệu C2 mới, chưa chạy.

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

## Cơ chế thật: `pcre`, không phải độ dài content

Băng phân biệt **không trống** — `8 ≤ L < 24` có 6 SID trong capture. Trong đó:

| SID | L | matcher quyết định | là C2? |
|---|---|---|---|
| 2012533 | 11 | `depth:4` + `distance:0` + `within:32` + `pcre /c\x3d[0-9A-F]{100}/i` | ✓ Virut HTTP |
| 2019471 | 8 | `depth:8` + `pcre /^[^\r\n]*?.../ ` neo đầu dòng | ✓ Rbot IRC |
| 2019486 | 8 | `depth:8` + `pcre /^[^\r\n]*?.../` neo đầu dòng | ✓ Rbot IRC |
| 2008581 | 12 | **chỉ** `content:"d1:ad2:id20:"; depth:12` | ✗ BitTorrent DHT |
| 2008583 | 12 | chỉ content, `depth:12` | ✗ BitTorrent DHT |
| 2008585 | 22 | chỉ content, `depth:14` | ✗ BitTorrent DHT |

**Ba SID C2 đầu bị phá bởi `pcre`, không bởi L.** `2012533` cần một run 100 ký tự hex liên tục (`c=<cookie>`); `2019471`/`2019486` neo regex vào đầu dòng. Một `pcre` neo đầu dòng bị đứt bởi **mọi** đơn vị phân mảnh — nên đổi đơn vị không thay đổi kết quả. Đây chính là lý do đo thực nghiệm cho `split8 = split16 = split24 = 40/40`.

**Hệ quả:** với 3 SID C2 này, L không bao giờ là ràng buộc ràng buộc (binding constraint). Muốn L thành ràng buộc thật thì cần rule **chỉ dùng `content` + `depth`, không pcre** — và rule duy nhất như vậy trong toàn bộ capture là **BitTorrent DHT**, `classtype:policy-violation`, tức **P2P không phải C2**.

Đây là phát biện thay thế cho công thức ban đầu: ràng buộc không phải *harvest SID có `16 ≤ L < 24`*, mà là *harvest rule C2 không dùng `pcre`*. Trong ET Open + CTU-13, loại đó **không tồn tại**.

---

## Hướng tiếp theo — đã mở lại sau khi phát hiện 2 capture chưa quét

1. ~~Chọn lại corpus theo geometry, mục tiêu bucket `16 ≤ L < 24`.~~ **Đã đối chiếu
   lại 2026-10-12 và kết luận cũ sai** (quét thiếu 2/21 capture). Bucket đó **có**
   SID thật trong dữ liệu, nhưng SID đó là BitTorrent P2P, không phải C2 — không dùng.
2. **Đã đạt** — không train trước khi đo headroom (bài học P4/P6).
3. ~~Nếu (1) không tìm được flow phù hợp, dừng và trình bày negative result.~~ Điều kiện
   này **chưa hợp lệ nữa** — việc kiểm tra trước đó chưa đầy đủ.

**Việc kế tiếp cụ thể, chờ duyệt:** sweep `split8` vs `split16` vs `split24` vs
`split_slow` trên **481 flow FakeAV check-in (SID 2012627)** lấy từ `Botnet-43`. Đây là
vật liệu C2 thật chưa từng nằm trong corpus. Geometry dự đoán headroom = 0 (L=78 > 24),
nhưng `2012533` đã bác bỏ dự đoán tương tự một lần, nên **phải đo**, không được suy.

Nếu sweep đó cho headroom = 0 (khả năng lớn), negative result vẫn đứng, và phạm vi
kết luận được nới đúng chỗ: **đã quét 21/21 capture, 10 SID, 0 SID C2 nào có
`8 ≤ L < 24`** — đó mới là phát biểu đủ sức để viết vào bài.

## P11 — fragmentation không phải lỗi cấu hình, và 24/40 flow nằm ngoài threat model

### P11.1 Ba cấu hình reassembly cho kết quả giống hệt

Trước P11, giả thuyết đang bị đặt là "conf ship không reassembly nên `split8 =
split16 = split24` là artifact của cấu hình đo". Đo thật trên 40 flow test,
`ownership = both`, mỗi conf đổi **đúng một** directive:

| conf | split8 | split16 | split24 | split_slow |
|---|---:|---:|---:|---:|
| gốc (`stream5 first` + `frag3 first`) | 40 | 16 | 16 | — |
| `stream5_tcp: policy last` | 40 | 16 | 16 | 40 |
| `frag3_engine: policy last` | 40 | 16 | 16 | 40 |

Không một ô nào đổi. Report: `ceiling_v4_both_reassemble.json`,
`ceiling_v4_both_frag3last.json`.

**Nguyên nhân.** frag3 của Snort 2.9.20 chỉ *chọn fragment nào để đối chiếu rule*
(`first` hoặc `last`); nó **không** có chế độ "dựng lại rồi detect". `snort -T` xác
nhận: `policy reassemble`, `policy first_only`, `policy metis` đều
`Bad policy name` → **fatal=2**; chỉ `first` và `last` hợp lệ.

Hệ quả trực tiếp, và đây là điểm đảo chiều của P10: vì frag3 chỉ soi một fragment,
nên chữ ký trải trên nhiều fragment không bao giờ được khớp, **bất kể conf**. IP
fragmentation né được ET Open C2 vì giới hạn *cấu trúc* của frag3, không phải vì
thiếu cấu hình. Số liệu `split8 = 40/40` vốn bị nghi ngờ là artifact hoá ra là
điểm yếu thật, và nó độc lập cấu hình.

### P11.2 24/40 flow chỉ alert được nhờ BitTorrent DHT

Ruleset 21.419 rule được thu hoạch bằng cách "giữ mọi rule từng bắn", nên nuốt
luôn **102 rule `classtype:policy-violation`** (SID `2008581`/`2008583`/`2008585`,
BitTorrent DHT) — không thuộc threat model C2. Bằng chứng trên 40 flow test:

| nhóm | n | framing | SID baseline |
|---|---:|---|---|
| C2 thật | 16 | http (16) | `2012627` — ET TROJAN FakeAV Check-in |
| chỉ P2P | 24 | neris (24) | `2008581`×24, `2008583`×19, `2008585`×4 |

Phép thử quyết định: lọc bỏ 102 rule `policy-violation` (còn 21.317 rule, `snort -T`
pass) rồi chạy lại `noop` → **16/16 flow http vẫn alert** (`2012627`), **24/24 flow
neris mất sạch alert**. Tức 24 flow đó vốn chỉ "được phát hiện" nhờ luật P2P, không
có baseline C2 nào, và phải loại khỏi mọi phép đo evasion.
Report: `ceiling_v4_nop2p_noop.json`.

### P11.3 Số đúng trên tập hợp lệ

Trên **16 flow có baseline C2 thật** (không P2P):

| cơ chế | valid evasion |
|---|---:|
| `noop` | 0/16 |
| `split8` | 16/16 |
| `split16` | 16/16 |
| `split24` | 16/16 |
| `split_slow` | 16/16 |

`oracle = 16`, `best_single = 16` → **`headroom = 0`**. Lần này `headroom = 0` là số
**sạch**: đo trên flow có C2 thật, trên conf đã loại P2P, và đã chứng minh
độc lập với cấu hình reassembly. `split16 = split24 = 16` trùng đúng tập 16 flow
C2, tức fragmentation thắng ở C2 và **không** thắng ở P2P — hai kết luận khác nhau
bị trộn lẫn trước đây.

### P11.4 Sai sót của chính phân tích này

Khi đọc report lần đầu, tôi kết luận "0/40 flow có SID C2". Sai: `baseline_sids`
là **int**, so với chuỗi `"2012627"` nên phép `in` luôn cho `False`. Số đúng là
16/40. Bảng P11.2 là sau khi sửa. Ghi lại vì đây là dạng lỗi âm thầm — phép so
sánh kiểu dữ liệu lệch không báo lỗi, chỉ ra số sai.

### P11.5 Bảng trần đầy đủ — 15 cơ chế, 40 flow, `ceiling_v4_both_test.json`

Đây là bảng ceiling chuẩn của dự án: 40 flow × 15 cơ chế = 600 cell, không thiếu ô nào,
`ownership=both`, `split=test`, `snort -T` exit 0, 6996 s.

| cơ chế | baseline | evaded | `sem_ok` | **VALID** |
|---|---:|---:|---:|---:|
| `split8` | 40 | 40 | 40 | **40** |
| `split_slow` | 40 | 40 | 40 | **40** |
| `split16` | 40 | 16 | 40 | 16 |
| `split24` | 40 | 16 | 40 | 16 |
| `corrupt8` | 40 | 24 | **0** | 0 |
| `http_header_pad` | 40 | 16 | 24 | 0 |
| `length_wrapper` | 40 | 15 | **0** | 0 |
| `overlap8` | 40 | 24 | 16 | 0 |
| `noop` *(đối chứng)* | 40 | **0** | 40 | **0** |
| `pad16` | 40 | 0 | **0** | 0 |
| `prepend4` / `prepend8` / `prepend12` | 40 | 40 | **0** | 0 |
| `reorder` | 40 | 0 | 37 | 0 |
| `ttl` | 40 | 0 | 40 | 0 |

Cột `VALID` là `evaded AND semantics_ok` — chỉ nó mới đếm được là né IDS thật.

**Đọc bảng:**

- `noop` chặn 40/40 flow, `evaded = 0` → **harness lành tính**: cơ chế không bị áp thì IDS
  bắn. Nếu `noop` có `evaded > 0` thì mọi dòng khác trong bảng là vô nghĩa.
- **6 cơ chế có `evaded > 0` nhưng `sem_ok = 0`** (`corrupt8`, `length_wrapper`, `prepend*`,
  `pad16` và một phần `overlap8`): chúng "né" được IDS **bằng cách phá hủy kênh C2**.
  `prepend4/8/12` né 40/40 — con số đẹp nhất bảng và hoàn toàn vacuous. Cột `sem_ok` loại
  chúng ra; đây là lý do cột này phải có mặt.
- Chỉ **4** cơ chế tạo ra né hợp lệ, và chỉ **2** đạt 40/40: `split8` và `split_slow`.
- `controls/rl_headroom.py` trên file này: `best_single = split8 (40)`, `oracle = 40`,
  **`headroom = 0`**, `unique_winner_sets = 2`.

**Giới hạn đã biết của bảng này:** nó chạy trên conf gốc còn BitTorrent, nên `split16`/`split24`
= 16 là **tập 16 flow C2 thật** (xem P11.2) và 24 flow kia không phải C2. Bảng trần trên
conf đã lọc P2P (`ceiling_v4_nop2p_frags.json`) là bảng được trích dẫn cho claim C2.

### P11.6 Quét trên ruleset chỉ-C2 — `headroom = 0` sạch, và mẫu số đúng là 16

`snort_validation/reports/ceiling_v4_nop2p_frags.json` — 200 cell (40 flow × 5 cơ chế),
`conf = snort_et_c2_nop2p.conf`, `bar = two_stream_byte_equality`,
`scorer = real_snort`, `ownership = both`, `wall_s = 2460.4` (41′).

| cơ chế | `baseline_alert` | `evaded` | `sem_ok` | `valid_evasion` | http | neris |
|---|---:|---:|---:|---:|---|---|
| `noop` *(đối chứng)* | **16** | 24 | 40 | 24 | **0/16** | **24/24** |
| `split8` | 16 | 40 | 40 | 40 | 16/16 | 24/24 |
| `split16` | 16 | 40 | 40 | 40 | 16/16 | 24/24 |
| `split24` | 16 | 40 | 40 | 40 | 16/16 | 24/24 |
| `split_slow` | 16 | 40 | 40 | 40 | 16/16 | 24/24 |

`best_per_framing` lưu trong report: `{"http": {"mech": "split8", "evaded": 16,
"flows": 16}, "neris": {"mech": "noop", "evaded": 24, "flows": 24}}`.

**Ba kết luận đo được:**

1. **`baseline_sids` chỉ chứa duy nhất SID `2012627`.** Dưới ruleset chỉ-C2,
   không rule nào khác trong ET Open bắt được bất kỳ flow nào của corpus. Toàn
   bộ 24 alert còn lại trước đây đến từ BitTorrent DHT — khớp P11.2.
2. **24 flow `neris` có baseline rỗng**, nên `noop` "né" 24/24 mà không thay
   đổi gì. Chúng nằm ngoài threat model hai lần: chỉ từng alert nhờ rule mà
   P11 đã loại, và giờ không còn gì để né. `rl_headroom.py` không lọc trường
   hợp này, nên `oracle = 40` và `best_single = 40` đều bị thổi phồng 24.
3. **Mẫu số đúng là 16 flow HTTP có detection.** Trên đó `noop = 0/16` và cả bốn
   cơ chế phân mảnh đều `16/16`. Phát biểu được đưa vào thesis:

   > Trên một ruleset chỉ chứa rule C2, Snort 2.9.20 phát hiện 16/40 flow —
   > toàn bộ là họ FakeAV C2 check-in (SID 2012627) — và **mọi** cơ chế phân
   > mảnh đều vô hiệu hóa cả 16. `headroom = 0`.

**Bất thường `split16`/`split24` đã được giải thích.** Chúng đo `16/16` dưới
`ceiling_v4_both_test.json` (ruleset đầy đủ) và `40/40` ở đây (ruleset chỉ-C2).
Chênh lệch 24 flow là do 102 rule P2P tương tác với phân mảnh, **không** phải
khác corpus. Ở cả hai report, con số "40" luôn là `16 thật + 24 rỗng ở mức noop`.
Không còn gì phải đối chiếu.

**Lỗi script bị lộ ra:** `controls/rl_headroom.py` (1) không có bộ lọc
baseline rỗng và (2) đọc `sys.argv[1]`/`argv[2]` trần, nên `rl_headroom.py
SWEEP.json --corpus X` ném `FileNotFoundError: '--corpus'` *sau khi* đã in
summary — một lần chạy im lặng chạy thiếu. Cả hai được sửa cùng một commit.

## Ghi chú phương pháp

- Phân tích này chỉ đọc `et_open_c2.rules`, `snort_et_c2.conf` và các report JSON đã
  có. Không thay đổi ruleset, không thêm action, không sửa số trong report.
- ~~Conf eval (`snort_et_c2.conf`) **không có** directive `reassemble` nào; chỉ
  `stream5_tcp: policy first, use_static_footprint_sizes`. Đây là điều kiện để
  fragmentation có tác dụng và nên được nêu rõ khi mô tả setup.~~
  **ĐÃ BỊ BÁC BỎ (xem P11 bên dưới).** Hóa ra đây *không* phải lý do
  fragmentation có tác dụng: thêm `stream5_tcp: policy last` **và**
  `frag3_engine: policy last` đều không đổi một số nào. Nguyên nhân sâu hơn nằm ở
  frag3, không ở stream5.
- Trường `sid` trong `div_probe.json` là list; phải kiểm `baseline_sids` trên corpus
  thay vì `alert_sids` (pickle v3fixed dùng `baseline_sids`, rỗng với pool probe).