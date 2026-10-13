# P14.6 — Cost-axis headroom sau khi thêm `query_param_prepend`

Frozen 2026-10-13, sau khi có đủ dữ liệu đo. Mọi con số dưới đây là **kết quả**,
không phải tiêu chí — bar đã đóng băng ở `docs/action_space_policy_p14.md` trước mọi
probe.

## Câu hỏi

P13 kết luận cost-axis headroom dương **nhưng chỉ tồn tại khi fragmentation khả dụng**.
P14 thêm cơ chế không-split. Ba câu hỏi:

1. Headroom có **transfer** sang corpus mở rộng (nơi P13 đo headroom = 0) không?
2. Trong regime **fragmentation bị chặn**, headroom có sống không?
3. Cơ chế mới có làm thay đổi kết luận trên corpus cũ không?

## Dữ liệu

| report | corpus | conf | cells | ghi chú |
|---|---|---|---|---:|
| `p13_v8_case_extended.json` | 5 flow HTTP mở rộng | ET Open 3.0.0 (52.454 rule) | 15 | noop / http_header_case / split8 |
| `p13_v9_query_prepend.json` | cùng 5 flow | cùng conf | 5 | query_param_prepend |
| `p14_v10_qpp_old_corpus.json` | 40 flow test (corpus cũ) | `snort_et_c2.conf` (21k) | 40 | query_param_prepend — **mới** |

`p14_v10` đo để "action space đầy đủ" ở corpus cũ là nghĩa đen: trước P14.6, v6
chỉ chứa 3 cơ chế, nên mọi claim "đầy đủ" trên corpus cũ đều thiếu một cơ chế.

## Kết quả 1 — headroom TRANSFER sang corpus mở rộng (trước P14: 0)

Bar **D5** (`valid_evasion_query`), action space đầy đủ, ownership=both:

| | fixed tốt nhất | per-flow oracle | headroom |
|---|---|---|---:|
| corpus mở rộng, **trước P14** (v8, 3 mech) | `split8` 5/5, +1224 B / +36 pkt | `split8` 5/5, +1224 B | **0** |
| corpus mở rộng, **sau P14** (v8+v9, 4 mech) | `split8` 5/5, +1224 B / +36 pkt | `query_param_prepend`×4 + `split8`×1, **+632 B / +18 pkt** | **−592 B (−48%)** |

Đây là lần đầu cost headroom **dương** trên corpus mở rộng. Không phải vì
`query_param_prepend` mạnh hơn — nó yếu hơn `split8` (`split8` 5/5, nó 4/5) —
mà vì nó **rẻ hơn trên flow mà split8 cũng né được**: +4…+8 B và **0 fragment**
so với +245 B/flow. Oracle chỉ cần `split8` cho đúng 1 flow (sogou, hướng
`to_client`, không có client-side slack).

### Phát hiện quan trọng: kết luận phụ thuộc BAR

Cùng dữ liệu đó, ba bar cho ba kết luận khác nhau:

| bar | oracle evaded | +bytes | distinct mech | dominating fixed? |
|---|---:|---:|---:|---|
| byte (`valid_evasion`) | 5/5 | 1224 | 1 (`split8`) | không (bằng chi phí) |
| endpoint v1 (`valid_evasion_endpoint`) | 5/5 | 1224 | 1 (`split8`) | không (bằng chi phí) |
| **endpoint_q D7** (`valid_evasion_endpoint_q`) | 5/5 | 1224 | 1 (`split8`) | không (bằng chi phí) |
| **query D5** (`valid_evasion_query`) | 5/5 | **632** | **2** | **có** |

Lý do: `query_param_prepend` **cố ý** đổi request line (`GET /x` →
`GET /x?…`), nên bar v1 và D7 — vốn so sánh raw request line — FAIL nó theo
thiết kế. Chỉ D5 (so *tập key→value sau percent-decode*) mới nói đúng "handler
thật vẫn đọc được cùng một lệnh".

Đây không phải chọn bar hậu nghiệm: `--bar` là tham số tên, D5 đã được viết vào
policy **trước** khi cơ chế tồn tại, và D5 fail-closed (thiếu key / đổi giá trị /
đổi số request → False). Nhưng nó là **caveat bắt buộc** khi viết thesis: claim
cost-headroom là claim *conditional on the semantic bar*, và bar v1/D7 cho kết
luận ngược lại. Không được trích claim D5 mà giấu bar v1.

## Kết quả 2 — regime không-fragment: headroom vẫn 0, nhưng coverage đổi

`--no-frag` (loại `split8`, `split16`, `split24`, `split_slow` khỏi **cả** fixed
baseline lẫn oracle):

| corpus | oracle evaded | +bytes | uncovered | dominating fixed? |
|---|---:|---:|---:|---|
| mở rộng (5 flow) | **4/5** | +20 | 1 (sogou) | **có** |
| cũ (40 flow) | **16/40** | +0 | 24 | không — bằng chi phí `http_header_case` |

Hai điều khác nhau:

- **corpus mở rộng**: oracle strictly-dominates mọi fixed mech, vì fixed tốt nhất
  trong regime này chỉ có 1 cơ chế (`query_param_prepend`, 4/5, +28 B) còn oracle
  chỉ dùng đúng cơ chế đó cho 4 flow rẻ nhất (+20 B). Headroom ở đây là **chi phí
  trong cùng một cơ chế**, không phải do chọn giữa nhiều cơ chế — đọc nó là
  "multi-mech RL thắng" sẽ sai. Gọi đúng là: *per-flow adaptation giữa 4 flow có
  slack và 1 flow không có slack*.

- **corpus cũ**: `http_header_case` đã zero-cost 16/16, oracle bằng chi phí →
  headroom 0. **Không có** fragmentation thì không có cost trade-off nào để khai
  thác, vì cơ chế rẻ nhất đã zero-cost.

Điều này **xác nhận** kết luận P13, không phủ định nó: cost headroom vẫn gắn với
điều kiện fragmentation khả dụng. P14 mở rộng *coverage* trong regime đó, không
mở *cost headroom*.

## Kết quả 3 — `query_param_prepend` không phải winner toàn cục

Đo trên corpus cũ (40 flow, conf 21k, 839 s): **0/40 evaded**. 16 flow HTTP đó
là FakeAV check-in (`2012627`) khớp *header block* + `data=` fast_pattern, không
khớp query string — nên thêm `x=0&` vào URI không phá content chain nào.

| cơ chế | corpus cũ (40 flow, bar D5) | corpus mở rộng (5 flow, bar D5) |
|---|---:|---:|
| `http_header_case` | **16/16** flow C2 (0/24 neris) | 0/5 |
| `query_param_prepend` | **0/16** flow C2 | **4/4** flow Virut |
| `split8` | 40/40 (16 C2 + 24 neris) | 5/5 |

(Ở bar v1 `http_header_case` chỉ 14/40; con số 16 là nhờ D7/D5 sửa lỗi parser
pipelined của P14 — xem `docs/p14_results.md`. Bảng này dùng D5 cho nhất quán.)

Hai cơ chế **bổ trợ nhau trên hai threat khác nhau**, không thay thế nhau. Đây là
bằng chứng mạnh nhất cho claim chuyển giao (transfer): cơ chế thắng ở corpus A thua
hoàn toàn ở corpus B, và ngược lại.

## Tổng kết cho thesis

| claim | trạng thái | điều kiện |
|---|---|---|
| Evasion headroom = 0 | **đứng vững** | mọi ruleset, mọi corpus, mọi bar |
| Composite headroom = 0 | **đứng vững** | như trên |
| Cost-axis headroom > 0 | **đúng, và nay có thêm 1 transfer** | (a) fragmentation khả dụng, (b) bar D5 |
| Cost headroom trong regime no-frag | **0** | cơ chế rẻ nhất đã zero-cost |
| Coverage không-split = 100% | 16/16 corpus cũ, 4/4 flow có slack corpus mở rộng | flow có client-side slack |
| Per-mech transfer | `http_header_case` ↔ `query_param_prepend` thắng chéo corpus | — |

Câu hỏi còn mở, **không** nên tuyên bố đã giải: liệu cost headroom có tồn tại dưới
**bar ngữ nghĩa duy nhất** (một bar vừa nới cho `query_param_prepend` vừa không
phá `split8`) — D5 là ứng viên, nhưng nó **được viết sau khi biết cơ chế thắng là
gì**, nên phải ghi trong thesis là post-hoc, không pre-registered.