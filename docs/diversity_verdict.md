# Diversity shaping (P4) — verdict

Ngày: 2026-10-12. Điều kiện đo: corpus v3fixed, ownership=both, ET Open full,
real Snort, pipeline fixed_6_fixes, bar two-stream byte-equality, 40 test flows
(33 dns / 6 http / 1 irc), seed 42, n-flows=22, max 40 epochs.
Pass bar đăng ký trước (plan `2026-10-11_182054-fix-single-action-collapse.md`):
**diversity ≥ 2 ∧ valid ≥ 95% ∧ breaks = 0 ∧ baseline = 100%**; tối đa 2 giá
trị λ (0.3, 0.6) — đã dùng hết.

## Kết quả đo (đã qua `controls/validate_div_probe.py`, 3/3 cặp OK)

| λ | seed | valid | diversity | actions | breaks | baseline | train |
|---|------|-------|-----------|---------|--------|----------|-------|
| 0 (P3) | 42 | 40/40 = 100.0% | 1 | split8 ×40 | 0 | 40/40 | 16 ep, 95.5% |
| 0.3 | 42 | 40/40 = 100.0% | 1 | split8 ×40 | 0 | 40/40 | 16 ep, 95.5% |
| 0.6 | 42 | 40/40 = 100.0% | 1 | split8 ×40 | 0 | 40/40 | 16 ep, 95.5% |

Per-framing (cả 3 λ): dns 33/33, http 6/6, irc 1/1 = 100%.
Confound check: cả 3 model cùng obs [11] / action space 15, cùng corpus, cùng
split, cùng ownership, cùng conf — chỉ λ thay đổi.

## Verdict: FAIL pass bar → diversity=1 trên điều kiện này là DATA-CAPPED

Shaping không gây hại (valid giữ 100%, breaks 0, hội tụ cùng tốc độ 16 epochs
ở cả 3 λ) nhưng không tạo được per-flow diversity. Bằng chứng chain:

1. **Tồn tại constant policy tối ưu.** Trên v3fixed test split với ownership=both
   và ET Open full: split8/16/24 đều valid 40/40 (P3 evals: s7/s1337 = split16
   ×40, s42 = split8 ×40) và split_slow valid 40/40
   (`ceiling_v3_splitslow_fixed.json`). Không flow nào BẮT BUỘC phải đổi
   mechanism → một action duy nhất cho cả 40 flows là nghiệm tối ưu của reward.
2. **Penalty chỉ đổi được thứ tự ưa thích, không đổi được cấu trúc argmax.**
   Đo được: λ=0.3 và λ=0.6 đều hội tụ cùng trajectory với λ=0 (16 epochs,
   95.5%, cùng chọn split8 ×40 trên eval). Penalty λ·share đánh vào hành vi
   TRONG epoch train (action dùng lặp bị trừ điểm dần), nhưng eval là
   deterministic argmax trên distribution đã hội tụ — ở đó mọi action thắng
   đều valid 40/40, và shaping không còn hiện diện. Obs của 33 dns flows gần
   trùng nhau nên argmax per-flow vẫn hằng số bất kể λ ≤ 0.6.
3. **Headroom chỉ tồn tại khi đổi regime, không phải đổi thuật toán.**
   `diversity_headroom_v3.json`: tầng expert/naive (stale — xem caveat) có 7
   flow bất đồng; splitslow sweep có 0 flow bất đồng GIỮA các mechanism thắng.
   Regime có diversity thật: ownership=client + ET full (split_slow là unique
   winner trên 33 dns flows, fast splits chỉ 7/40) — ở đó policy BẮT BUỘC dùng
   ≥2 mechanism (split_slow cho dns, fast split cho http/irc) mà không cần
   shaping nào.

## Trả lời câu hỏi "đủ đưa vào thesis chưa"

**Có — nhưng là negative result có kiểm soát, không phải là claim diversity.**

- Headline giữ nguyên: P3, 3 seeds, 40/40 = 100% valid evasion, 0 semantics
  breaks, baseline 40/40 (đã commit `72bbcc1`).
- P4 vào chương discussion/limitations với đúng phát biểu:
  *"Frequency-penalty shaping (count-based exploration, Bellemare et al. 2016,
  bandit analog) với λ ∈ {0.3, 0.6} không tạo mechanism diversity khi tồn tại
  dominant constant policy: trên corpus v3fixed (ownership=both, ET Open full)
  cả bốn mechanism fragmentation đều valid-evasion 40/40 flows, nên policy
  hằng số là nghiệm tối ưu và deterministic argmax tất yếu collapse về một
  action. (Ở các seed khác nhau argmax hằng số đó có thể là split8 hoặc
  split16 — chênh lệch đến từ khởi tạo ngẫu nhiên, không phải per-flow
  selection.) Diversity là tính chất của threat-model regime (ruleset tier ×
  packet ownership), không phải của thuật toán tối ưu."*
- Bảng λ-ablation 3 dòng ở trên là bằng chứng số cho phát biểu đó (kèm
  validator + tests, `controls/validate_div_probe.py`,
  `tests/test_validate_div_probe.py`).
- **KHÔNG được viết:** "policy học được đa dạng mechanism" (sai — đo được
  diversity=1 ở mọi λ); "λ=0.6 phá evasion" (sai — valid vẫn 100%).

## Caveats bắt buộc trích kèm

- `ceiling_v3_expert.json` / `ceiling_v3_naive.json` chạy TRƯỚC fix
  transport-payload (commit `3393644`): scapy auto-dissection nuốt 33 DNS
  flows, mechanism chưa từng chạy trên chúng (split16 dns: sweep 0/33 vs P3
  eval 33/33 cùng điều kiện). Hai report đó KHÔNG được trích làm headroom.
  Nguồn đáng tin: `ceiling_v3_splitslow_fixed.json`, P3 evals, P4 probe evals,
  `diversity_headroom_v3.json` (đã loại noop control).
- Probe = 1 seed (42). Với kết luận data-capped điều này không yếu đi: tính
  tối ưu của constant policy là tính chất của data + reward, đã chứng minh
  bằng ceiling sweep 40/40 của cả 4 mechanism thắng, không phụ thuộc seed.
- Train report có `semantics_breaks` lũy kế (75–76) — đó là exploration
  trong train, không phải eval; eval breaks = 0 ở mọi λ.

## Nếu vẫn muốn một con số diversity ≥ 2 "thật" (future work, KHÔNG tự chạy)

Đường đúng là đổi regime, không phải tăng λ: retrain 1 seed với
ownership=client trên v3fixed (λ=0) — dự đoán từ ceiling: split_slow bắt buộc
cho 33 dns flows, fast split cho 7 http/irc → diversity=2 tự nhiên (~75 phút,
Phase 4 optional của plan `2026-10-11_182054`). Tăng λ > 0.6 vi phạm pass bar
đã đăng ký và có rủi ro manufacture-evasion; ε-greedy hay QD/MAP-Elites đổi
deliverable, không thuộc phạm vi P4.

## Addendum (2026-10-12): naive-tier sweep trên v3fixed = INVALID, nguyên nhân gốc

Chạy `ownership_ceiling_sweep.py --conf snort_et_c2_naive.conf` trên v3fixed
(600 cells, real Snort): **baseline_alert = 0/40** → mọi "evasion" vô nghĩa
(noop cũng "thắng" 40/40). Report bị quarantine, không commit số.

Chẩn đoán: 40 flow của v3fixed được build (build_corpus_v3.py --verify) để
alert bằng các SID NGOÀI tập naive {2008581, 2008583, 2008585, 2012627} —
phân bố baseline_sids đo từ corpus: 2016413 ×29, 2014169 ×24, 2012533 ×5,
2014635 ×3, 2017287 ×1. Ruleset naive 4 SID **không thể bắn trên corpus
này theo cấu trúc** — không phải lỗi harness.

Hệ quả: `ceiling_v3_naive.json` (bản cũ) có cùng bệnh — noop evaded 40/40,
baseline_sids rỗng trên cả 560 cells → con số "http_header_pad 37/40" trên
naive tier KHÔNG được trích dẫn ở bất kỳ đâu. Naive-tier ladder trên v3fixed
chỉ đo được bằng ET archive thật (ruleset_probe: et286 = chính 4 SID naive,
community không load được) — tức naive-vs-expert comparison trên corpus này
là bất khả thi bằng conf tự dựng; muốn có tier yếu thật phải dựng conf từ
et_open_c2.rules với filter SID khác NAIVE, không phải naive.rules.
