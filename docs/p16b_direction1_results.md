# P16b — Hướng 1: đổi defender sang engine có reassembly (Suricata 7)

**Verdict: G1a XANH, G1b(i) XANH, G1b(ii) XANH — nhưng headroom vẫn 0.**
Chi tiết dưới. Mọi số đo bằng Suricata 7.0.3 thật, ruleset 21288 rule đã convert,
ownership=client, mẫu số đóng băng 20 flow HTTP-D4.

Ngày đo: 2026-10-13. Gate frozen trước khi đo: `docs/p16_direction_gates.md`.

---

## 1. G1a — harness đúng (control âm tính)

| | |
|---|---:|
| `noop` trên 40 flow test | **40/40 alert** |
| đối chiếu `control_noop_real_snort.json` (Snort 2.9) | 40/40 |
| chi phí | 24,85 s/cell |

Trước đó project **chưa từng có một verdict Suricata nào**: `cross_engine_check.py`
(P4) đếm alert bằng `stdout.count("[**]")` và nuốt exception thành `-1`, nên
`cross_engine_v2.json` có 5/5 cell = −1. Harness mới (`suricata_runner.py`) đếm từ
`fast.log`, đối chiếu `eve.json`, **fail-closed** khi engine rc ≠ 0.

## 2. G1b(i) — split CHẾT (xanh, mạnh hơn dự đoán)

| mech | FakeAV 16 flow | Virut 4 flow | Snort 2.9 (đã commit) |
|---|---:|---:|---:|
| `noop` | 0/16 | 0/4 | 0/40 |
| `split8` | **0/16** | **0/4** | 16/16 http, 7/24 neris (client-only) |
| `split24` | **0/16** | **0/4** | — |

Fragmentation không giảm hiệu quả — nó **về 0**. Suricata reassemble TCP stream
trước khi match, nên IP-frag không còn che được chữ ký. Đây là bằng chứng thực
nghiệm đầu tiên trong project rằng một engine có reassembly vô hiệu toàn bộ họ
split.

## 3. G1b(ii) — heterogeneity SỐNG (xanh)

| mech | FakeAV (SID 2012627) | Virut (SID 2012533) |
|---|---:|---:|
| `http_header_case` | **16/16** | 0/4 |
| `query_param_prepend` | 0/16 | **4/4** |

**Hai nhóm SID cần hai cơ chế khác nhau và không重叠.** Lý do đọc được từ rule text:

- SID 2012627 thuần **stream-anchored**: 4 content clause nối `distance:0` +
  `fast_pattern`, không có `depth:`/`offset:` → đổi hoa/thường tên header phá
  literal, còn chèn param thì không đụng gì tới nó.
- SID 2012533 **head-anchored**: `content:"GET " depth:4` + `content:"list.php?c="
  within:32` + `&v=`/`&t=` `distance:0` + `pcre:/c\x3d[0-9A-F]{100}/i` → chèn param
  lạ sau `?` phá literal chain; đổi hoa/thường header thì không đụng request line.

Điều P13/P14 không thấy: fragmentation che cả hai loại geometry, nên mọi cơ chế
trông như tương đương. Bỏ fragmentation đi thì geometry mới lộ ra.

## 4. Headroom DƯƠNG — lần đầu tiên trong project (đính chính)

> **Đính chính:** bản đầu của mục này (commit `0221032`) viết "headroom vẫn 0" vì
> tôi chỉ so `best_single` với `oracle` **trong từng nhóm SID**. So như vậy là sai
> định nghĩa đã freeze trong gate: `headroom = cost(best_single) − cost(per_flow_oracle)`
> **trên cùng tập flow**. Trên toàn bộ 20 flow, một cơ chế duy nhất **không** đạt
> oracle.

| mech | evaded / 20 flow HTTP-D4 | coverage |
|---|---:|---:|
| `noop` (control âm) | 0/20 | 0,0% |
| `split8` | 0/20 | 0,0% |
| `split24` | 0/20 | 0,0% |
| `http_header_case` | **16/20** | 80,0% ← best single |
| `query_param_prepend` | 4/20 | 20,0% |
| **per-flow oracle** | **20/20** | **100%** |

**Coverage headroom = 20 − 16 = 4 flow = 20 điểm phần trăm.** Số flow không có cơ
chế nào né được: **0/20**.

Đây là lần đầu tiên một phép đo trong project cho headroom dương trên trục
coverage. P13 đo headroom = 0 trên mọi ruleset và mọi corpus dưới Snort 2.9; P14
mở được coverage nhưng `best_single` vẫn chạm oracle; P14.6 chỉ có headroom trên
trục **cost** và chỉ dưới bar D5 post-hoc.

Vì sao lần này khác: **hai nhóm SID cần hai cơ chế rời nhau** (mục 3), nên không
một cơ chế đơn lẻ nào phủ hết mẫu. Một policy cố định phải chọn: hoặc bỏ 4 flow
Virut (80%), hoặc bỏ 16 flow FakeAV (20%). Chỉ per-flow selection đạt 100%.

### Nhưng phải nói rõ policy cố định nào đạt 100%

Có tồn tại một luật tĩnh đạt 20/20: *"chọn cơ chế theo SID của rule đang bắt flow
này"* — vì hai nhóm SID rời nhau. Luật đó **không cần học**, nhưng nó đòi hỏi
kiến thức mà threat model đã đóng băng là attacker **không có** (attacker không
biết SID nào đang bắt mình, không đọc được ruleset của defender). Trong threat
model đã freeze, attacker chỉ quan sát được alert/không-alert → nó phải *thử*, và
một policy học được từ tín hiệu đó chính xác là thứ RL cung cấp.

Đây là điểm khác biệt thực chất so với P13: ở P13 một hành động cố định thắng
mọi flow **mà không cần thông tin riêng**, nên RL không thêm gì. Ở đây hành động
cố định tốt nhất chỉ đạt 80%.

### Trục cost: vẫn 0

Cả 5 mech đều **+0 byte payload** trên flow mẫu (chỉ split tăng số packet 10 → 11),
và hai cơ chế thắng đều có `ACTION_COSTS = 0,05` — bằng nhau. Nên
`cost(best_single) − cost(oracle) = 0`. Headroom dương **chỉ** trên trục coverage.

## 5. Bar semantics — evasion không "rỗng"

Đã verify độc lập trên đúng 20 flow đóng băng:

| mech | byte | D7 | D5 | D8 = byte∨D7∨D5 |
|---|---:|---:|---:|---:|
| `http_header_case` (16 FakeAV) | 0/16 | **16/16** | **16/16** | 16/16 |
| `query_param_prepend` (4 Virut) | 0/4 | 0/4 | **4/4** | 4/4 |

Hai cơ chế thắng theo **hai bar khác nhau** — khớp P14. `query_param_prepend` chỉ
pass D5 (query parser chuẩn vẫn đọc đúng `c/v/t`), fail D7 vì nó đổi request line.

## 6. Chi phí (G1c)

| | cell | phút |
|---|---:|---:|
| G1a noop 40 flow | 40 | 16,6 |
| G1b FakeAV | 80 | 33,1 |
| G1b Virut | 20 | 8,3 |
| **tổng Phase 2** | **100** | **41,5** ≤ 45 ✅ |

Chi phí chi phối bởi **rule load 21288 rule** (~25 s), không phải kích thước pcap.
Đã bỏ `split16` TRƯỚC khi chạy (ghi trong gate doc) vì 6 mech sẽ là 49,7 phút.

## 7. Hai lỗi của chính tôi trong lúc đo (ghi lại để không lặp)

1. **Fixture "known-alerting" đầu tiên sai.** Tôi chọn pcap CTU-Malware-Capture-Botnet-9
   vì skill ghi nó là "known-alerting" — nhưng đo lại thì nó **0 alert dưới Snort
   nữa**, chỉ là "regular file" cho `snort -T`. Đã thay bằng flow HTTP thật từ
   corpus test split, đo tay cả hai engine (1 alert, cùng SID 2012627, fast.log ==
   eve.json) rồi mới pin vào test.
2. **Script đọc log tạm đếm sai.** Dùng `line.startswith("[**]")` trong khi
   fast.log của Suricata bắt đầu bằng timestamp → báo `noop 6/6 evaded`, ngược
   với G1a. Runner thật dùng `"[**]" in line` và đúng. Không số nào trong repo
   bị ảnh hưởng, nhưng nếu tôi tin script tạm thì đã kết luận harness hỏng.

## 8. Kết luận cho thesis

Hướng 1 **triển khai được** và cho **ba kết quả đăng được**:

- **(a) Positive result cho claim RL — lần đầu tiên.** Coverage headroom
  **20 pp** (best single mech 80% vs per-flow oracle 100%) trên mẫu 20 flow
  HTTP-D4 đóng băng, dưới engine thật, 0 flow không có cơ chế nào né được, và
  mọi evasion đều pass bar D8 (D7 hoặc D5). Đây là lần đầu tiên trong project một
  hành động cố định **không** chạm oracle.
- **(b) Khuyến nghị phòng thủ, có bằng chứng:** bật reassembly (Suricata, hoặc
  Snort 3) vô hiệu hoá toàn bộ họ fragmentation mà P3–P13 dựa vào. Con số: split8
  16/16 → **0/16** trên HTTP FakeAV, 4/4 → **0/4** trên Virut.
- **(c) Phát hiện engine-dependence:** cùng một pcap, cùng một ruleset ET Open,
  hai engine cho hai tập cơ chế khả thi **rời nhau**. Mọi con số đã công bố của
  project phải ghi scope "dưới Snort 2.9.20 + conf này", không phải "dưới IDS".

**Giới hạn phải ghi trong thesis:** headroom dương chỉ trên trục **coverage**,
trục cost vẫn 0. Và tồn tại một luật tĩnh đạt 20/20 nếu được biết SID đang bắt
flow — luật đó nằm ngoài threat model đã freeze, nhưng phải nêu ra để không
overclaim.

**Việc còn lại để biến (a) thành claim RL hoàn chỉnh:** train PPO trên harness
Suricata (action space 17 đã có sẵn, bar D8 đã có sẵn) và chứng minh policy học
được tiến gần 20/20 hơn một hành động cố định. Chi phí ước tính: 24,85 s/query ×
số query — **đắt hơn Snort ~2 lần**, nên cần surrogate cho vòng train và chỉ dùng
Suricata thật để eval. Đó là lý do `RealRulesReplica` vẫn còn giá trị, dù calibration
direction của nó đã fail.