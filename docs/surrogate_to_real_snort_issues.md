# Vấn đề khi chuyển từ Surrogate IDS → Real Snort

## 1. **Semantics Bar Thay Đổi — Prepend Variants Bị Từ Chối**

### Surrogate version
- `RealRulesReplica`: bản sao Python của ~20 quy tắc, match bytes độc lập
- Prepend 4/8/12 byte được tính là "giữ nguyên ngữ nghĩa" miễn là payload gốc vẫn ở đó
- **Kết quả**: prepend4 = 4/16, prepend8 = 4/16, prepend12 = 4/16

### Real Snort
- `SnortBatchService`: gọi binary thật (`snort -r`), ET Open C2 ruleset (21,374 quy tắc)
- Semantic check dùng `endpoint_model`: parser C2 theo protocol (HTTP path từ request line, Neris record chain `<tag><len>:<data>`)
- Prepend phá vỡ byte-equality → không thể parse lại command → **0/16 cả ba biến thể**

### Hậu quả
- Surrogate overestimate evasion: prepend thích hợp khi endpoint biết skip junk
- Real Snort: "giữ nguyên ngữ nghĩa" = byte-exact, không chỉ semantic-exact
- **Bài toán khó hơn thực tế, nhưng cũng thật thực hơn**

---

## 2. **Protocol Applicability Không Rõ Ràng**

### Surrogate version
- Toàn bộ 14 cơ chế áp dụng được cho mọi flow (100%)
- Không kiểm tra xem protocol có hỗ trợ cơ chế không
- `http_header_pad` trên Neris flow vẫn được gọi, "evade" dù không hợp lý

### Real Snort
- `mech_applicable()`: loại bỏ cơ chế protocol không mang được
  - `http_header_pad` → chỉ HTTP (8/16 flow)
  - `length_wrapper` → chỉ length-prefixed (0/16 flow, vì corpus không có)
- Chỉ đếm cơ chế áp dụng được trong discrimination analysis

### Hậu quả
- Surrogate: matrix 14×16 = 224 ô, mỗi ô có verdict
- Real Snort: matrix 14×16 = 224 ô, nhưng `http_header_pad` chỉ valid trên 8, `length_wrapper` valid trên 0
- **RL action space hiệu quả nhỏ hơn: thay vì 14 hành động, mỗi flow thấy 12-13 hành động**

---

## 3. **Batch Size & Query Counting Bug**

### Surrogate version
- Eval loop không quan tâm batch size
- Một mechanism-pair pair = 1 query, regardless of implementation

### Real Snort
- **Harness bug (đã fix ở commit 57252e1)**: `SnortBatchService` score theo batch, nhưng matrix.json ghi lại từng query như 1 flow
- Kết quả: nếu batch_size=32, một batch 32 flow → 1 Snort call nhưng được đếm là 32 query
- **Impact**: tất cả baseline và RL numbers trước commit 57252e1 bị sai (overcounted queries)

### Hậu quả hiện tại
- Commit 57252e1 fix: batch_size=1 (1 query = 1 Snort call, đúng)
- Eval chậm: 112 (flow, mechanism) pairs × 10.6 giây/pair = ~20 phút
- **Trade-off**: chính xác vs tốc độ

---

## 4. **Protocol Detection & Neris Grammar**

### Surrogate version
- Tất cả flow được nhãn "http" theo corpus tên file
- `endpoint_model.py` chưa tồn tại; semantic check là string matching trên payload

### Real Snort + Endpoint Model
- `detect_framing()` sử dụng regex để nhận diện:
  - HTTP: `GET|POST|PUT|DELETE|HEAD|OPTIONS|CONNECT|TRACE`
  - Neris: `d\d+:.*e` (bittorrent-style record chain)
- Phát hiện: **80 flow HTTP, nhưng 41 flow "unparseable"** → điều tra → **41 flow là Neris, không HTTP**
- Corpus 50/50 HTTP/Neris, nhưng được nhãn sai

### Hậu quả
- `endpoint_model.parse_command()`: có thể parse HTTP path + Neris record, nhưng Neris còn sơ sài
  - Neris parser: chỉ kiểm tra stream *bắt đầu* đúng format, không full grammar
  - Prepend/pad trên Neris → "unparseable" → `semantics_intact()` return False
- **RL không thể học prepend trên Neris, chỉ fragmentation**

---

## 5. **Action Space Collapse — RL Không Phân Biệt Được Cơ Chế**

### Surrogate version
- Prepend, pad, reorder, ttl, noop: mỗi cái 4-8 flow solved
- RL có nơi để "phân biệt" — có cơ chế tốt hơn cơ chế khác
- Baseline: greedy = 90.6%, RL = 90.6% (để nhưng có sự khác biệt nhỏ trong strategy)

### Real Snort
- Chỉ 4 cơ chế work: split8/16/24 (100%), http_header_pad (100%)
- Còn 9 cơ chế: 0/8 toàn bộ
- **Action space dị hóa**: 14 hành động, nhưng thực chỉ có 2 "tốt" (split24, http_header_pad) + 12 "xấu"

### Hậu quả
- PPO chọn split24 → 8/8 evasion (y hệt greedy, y hệt supervised tree)
- Không thể chứng minh RL học được gì vượt trội
- **Bài toán đã bão hoà: tìm kiếm heuristic (greedy) đủ tốt, nên RL không có lợi thế**

---

## 6. **Test Set Homogeneity**

### Surrogate version
- 16 flow mixed (protocol, payload size, port, direction)
- Đa dạng: có flow "dễ" (prepend dùng được), có flow "khó"

### Real Snort
- HTTP-only: 8 flow, mỗi cái 4 cơ chế work (split8/16/24, http_header_pad)
- Neris: 8 flow, mỗi cái 3 cơ chế work (split8/16/24 chỉ) — chưa eval
- **Surrogate multi-protocol → Real Snort single-protocol test → RL metrics không so sánh được**

### Hậu quả
- Eval HTTP-only: 100% evasion là "tầm thường" (chỉ cần split24)
- Eval full 16-flow: sẽ thấy Neris "khó" hơn (vì http_header_pad fail, chỉ fragmentation), có khả năng RL hơn greedy
- **Cần eval 16-flow mixed để có kết luận có ý nghĩa**

---

## 7. **Semantics Integrity Bugs — Fix sau khi phát hiện**

### Surrogate version
- Không rebuild checksums sau khi rewrite payload → Snort drop packets → mỗi mechanism "evade"
- Không rebuild packet stack (Ether/IP/TCP) → mất Ethernet header → packet invalid

### Real Snort (fixes)
- Commit f7a23e0: `fix_checksums()` rebuild IP.len, TCP.len, checksums
- Commit 6620342: rebuild từ `pkt.__class__` để giữ Ethernet header
- **3 bugs tìm ra bằng TDD**: junk header có extra `\r\n`, IP.len stale, Ethernet header mất

### Hậu quả
- Surrogate: số liệu không đáng tin
- Real Snort: đắt hơn (TDD), nhưng số liệu thật

---

## 8. **Evaluation Speed vs Accuracy Tradeoff**

### Surrogate version
- ~0.1 giây/query (Python string matching)
- Evaluation 224 query = 22 giây
- Nhanh, nhưng sai

### Real Snort
- ~10.6 giây/query (Snort binary, PCAP write/read)
- Evaluation 112 query (batch_size=1) = ~20 phút
- Chậm, nhưng đúng

### Hậu quả
- Không thể chạy large-scale eval dễ dàng
- Phải tính từng query một (batch_size=1) để chính xác
- **Scaling up test set → thời gian tính toán tăng tuyến tính, không feasible cho RL training loop**

---

## 9. **Length Wrapper Dead on Arrival**

### Surrogate version
- `length_wrapper` được tính vào action space (1/14 hành động)
- Áp dụng được cho mọi flow (100%)

### Real Snort
- `length_wrapper` yêu cầu protocol là "length2" (dài 2 byte prefix)
- Corpus: HTTP + Neris, không có flow "length2"
- `mech_applicable()` trả về False cho tất cả 16 flow → **0/16 applicable**

### Hậu quả
- Action space 14 hành động, nhưng 1 hành động (length_wrapper) không thể dùng
- Hoặc: reverse-engineer Neris grammar để nó become "length2" parseable (khó, model chưa đủ)
- Hoặc: bỏ length_wrapper khỏi action space (đơn giản, nhưng giảm diversity)

---

## Summary: Surrogate vs Real Snort

| Aspect | Surrogate | Real Snort | Impact |
|--------|-----------|-----------|--------|
| **Semantics bar** | Loose (prepend ok) | Strict (byte-equal only) | Prepend fails, task harder |
| **Protocol check** | None (toàn 14) | Applicability filter | Effective action space ≤ 12 |
| **Batch counting** | Always 1 query | Buggy → fixed to batch_size=1 | Speed penalty, accuracy gain |
| **Framing detection** | Assumed HTTP | Detected (HTTP/Neris) | Corpus 50/50, not 80/20 |
| **Neris model** | Unknown/ignored | Partial (record chain) | Prepend doesn't work on Neris |
| **Action diversity** | 4-8 mechanisms work | 4 mechanisms work → collapse | RL cannot distinguish |
| **Test coverage** | 16 mixed | 8 HTTP-only (first) | Saturated, needs 16-flow eval |
| **Eval speed** | 22 sec | 20 min | Slower, enables RL training but not large-scale |
| **Length wrapper** | Applicable 16/16 | Applicable 0/16 | Dead mechanism |

---

## Khuyến nghị để tiếp tục

1. **Eval đầy đủ 16-flow mixed** (hiện tại chỉ HTTP-only) → xem Neris có "khó" hơn không
2. **Quyết định length_wrapper**: reverse-engineer Neris, hoặc bỏ khỏi action space
3. **Nếu task vẫn saturated (split24 = 100%)**: pivot sang heterogeneous defender (adaptive + per-flow)
4. **Hoặc**: focus on protocol-aware design (HTTP padding working, Neris fragmentation-only) thay vì RL learning
