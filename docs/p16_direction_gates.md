# P16 — Pre-registered gates cho 3 hướng thay thế (Hướng 1/2/3)

**Nguyên tắc:** gate và metric được viết **trước** khi đo. Không hạ bar, không đổi
mẫu số, không thêm cơ chế chỉ để mở headroom sau khi thấy kết quả. Nếu một hướng
fail gate, viết trung thực rồi **dừng** — "cả ba hướng đều fail" là một kết quả
đạt, vì nó trả lời câu hỏi của thesis.

Ngày freeze: **2026-10-13**, trước lần chạy engine đầu tiên.

---

## Hướng 1 — đổi defender sang engine có reassembly (Suricata 7 / Snort 3)

*Engine hiện tại: Snort 2.9.20 GRE (Build 82) + `snort_validation/et_open_c2/`
(21.374 rule, UNFILTERED theo quyết định 53). Engine mới: Suricata 7.0.3, **cùng
ruleset** đã commit, chuyển đổi không lọc nội dung rule.*

### Ràng buộc mẫu số (chống đọc nhầm)

Hướng 1 chỉ được claim trên **subset HTTP của mẫu D4** = 16 flow FakeAV cũ + 4 flow
Virut mở rộng = **20 flow**. Lý do: semantic-preserving rewrite an toàn **không tồn
tại** trên UDP/binary. Đây là **thu hẹp**, không phải mở rộng. Mọi bảng kết quả phải
in **cả hai** mẫu số: `x/20 (HTTP-D4)` và `x/40 (full test)`.

### G1a — harness phải đúng (control âm tính)

Trên **40 flow test cũ**, `noop` phải **alert 40/40**, đối chiếu
`snort_validation/reports/control_noop_real_snort.json` (= 40/40 dưới Snort 2.9).

Nếu < 40/40 → **DỪNG**, sửa harness (rule convert thiếu, yaml sai, hoặc cách đếm
alert sai). Không diễn giải kết quả evasion của một harness chưa được chứng minh.

### G1b — "split chết" + heterogeneity còn sống (CẢ HAI)

- **(i) split chết:** `split8` valid-evasion trên mẫu HTTP-D4 **giảm** so với số
  Snort 2.9 đã commit (http **16/16** trong `oracle_split8_test.json`). Nếu vẫn
  16/16 → Suricata **không** reassemble theo cách ta cần → Hướng 1 fail, ghi
  trung thực.
- **(ii) heterogeneity sống:** tồn tại **≥ 2 flow** trong mẫu HTTP-D4 mà **cơ chế
  tối ưu khác nhau** (cơ chế tối ưu = cơ chế rẻ nhất còn valid-evasion). Nếu một
  cơ chế duy nhất thắng mọi flow → `best_single = oracle` → headroom = 0 → Hướng 1
  **không** tạo giá trị RL, dù split có chết.

Định nghĩa chính xác: `headroom = cost(best_single) − cost(per_flow_oracle)` trên
cùng tập flow, cùng bar, cùng engine.

### G1c — chi phí engine

Tổng thời gian engine cho **toàn bộ** Phase 2 ≤ **45 phút**. Vượt → giảm mẫu (ghi
rõ đã giảm phần nào), **không** chạy qua đêm không giám sát.

**Đo thực tế 2026-10-13 (G1a, 40 flow noop): 24,85 s/cell**, chi phối bởi rule load
21288 rule chứ không phải kích thước pcap. Suy ra:

| phương án | cell | phút | verdict |
|---|---:|---:|---|
| 20 flow × 6 mech (noop, split8, split16, split24, http_header_case, query_param_prepend) | 120 | **49,7** | **VƯỢT G1c** |
| 20 flow × **5** mech (bỏ `split16`) | 100 | **41,4** | OK |

**Quyết định (ghi TRƯỚC khi chạy):** bỏ `split16`, giữ `split8` + `split24`.
Lý do: cả ba là cùng một họ (IP fragmentation tại các điểm cắt khác nhau), nên
G1b(i) "split chết hay không" chỉ cần hai điểm của họ đó — `split8` là điểm mạnh
nhất (cắt nhỏ nhất, khó reassemble nhất) và `split24` là điểm yếu nhất. Nếu cả hai
đều chết thì `split16` chết; nếu `split8` sống thì kết luận G1b(i) đã đỏ sẵn.
Việc giảm mẫu **không** đụng mẫu số flow (vẫn đủ 20/20 HTTP-D4 đóng băng).

### Rủi ro đã biết trước khi đo (ghi trước để không hậu nghiệm biện minh)

Vị trí chèn an toàn về ngữ nghĩa trên HTTP là **header block sau request line** →
**không dịch được** các byte mà rule head-anchored neo vào (`depth:`/`offset:` ở
đầu payload). Nếu fragmentation chết, nhóm head-anchored có thể trở thành bất
khả xâm phạm bởi rewrite an toàn → coverage **giảm** nhưng headroom **vẫn 0**.
Kết luận đúng trong trường hợp đó: *"Hướng 1 làm bài toán khó hơn, không làm RL cần
hơn"* — là khuyến nghị phòng thủ (bật defrag), không phải positive result.

### Anti-gaming

- Không chọn ruleset con để làm split chết. Dùng **đúng** ruleset đã commit
  (21.374 rule).
- Rule convert **không lọc nội dung**; chỉ loại dòng Suricata từ chối nạp, và **đếm
  + ghi ra** số đã loại. Nếu loại > 0, `suricata_rejected.txt` phải được đọc và số
  đó ghi vào verdict — ruleset bị cắt thì G1b(i) không còn ý nghĩa.
- `HOME_NET`/`EXTERNAL_NET` giữ `any` **có chủ đích**, khớp `snort_et_c2.conf:17-18`
  để hai engine nhìn cùng phạm vi traffic. Ghi rõ lý do trong yaml.
- Cách đếm alert phải **TDD trước**: `cross_engine_v2.json` có 5/5 cell = −1
  (exception) nên chưa từng có verdict Suricata thật nào; đếm bằng
  `stdout.count("[**]")` là **chưa được kiểm chứng**. Đếm từ `fast.log` + đối chiếu
  `eve.json`.

---

## Hướng 2 — defender thích ứng (non-stationary)

Giữ engine, cho blue team vá rule sau khi quan sát evasion, hoặc rotate ruleset.

*(Metric pre-register chi tiết: `survival_rounds`, `queries_to_re_evade`,
`mech_switch`, `reactive_heuristic`, `fixed_best` — xem
`.hermes/plans/2026-10-13_211739-direction2-vs-direction3-feasibility.md`.)*

**Gate sống-chết đã biết:** extended corpus chỉ có **5/120 flow không alert** →
không có benign pool đủ để chống defender "vá bằng cách alert bừa". Phải đo
trước (T3.1, 60 flow) trước khi tin vào bất kỳ con số headroom nào.

---

## Hướng 3 — mở action space thành parameterized / compositional

*(Gate G3 chi tiết: `.hermes/plans/2026-10-13_211739-…`.)*

Phát hiện cấu trúc tính trước khi đo: `split_fragments(payload, split_at=8)` **đã
parameterized sẵn** ở tầng primitive, nhưng mọi SID trong mẫu D4 là **AND-chain**
(`2012533` = `GET ` ∧ `list.php?c=` ∧ `&v=` ∧ `&t=` ∧ pcre) nên phá 1 clause là rule
chết → **mọi tham số cho cùng kết quả**. Vùng tham số non-equivalent (chèn vào giá
trị `c=`) thì **fail bar D5**. Rule có geometry anchored thật (`2023753` offset:5
depth:6, `2014169` offset:2 depth:1) bị **D4 loại** → nạp vào là đổi threat model đã
đóng băng → **cấm**.

---

## Baseline dùng để so (bắt buộc đọc trước khi so sánh)

`docs/baseline_ownership_provenance.md` — `ppo_masked_test.json` (40/40) là
**both-ownership + relaxed bar**, sinh tại `e6fb02d` (2026-10-04), trước `40fffdf`
(2026-10-05). Baseline client-only + strict bar hợp lệ duy nhất:
`oracle_split8_test.json` = **23/40** (http 16/16, neris 7/24).