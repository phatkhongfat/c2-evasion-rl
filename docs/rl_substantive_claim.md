# RL substantive claim (P5) — verdict: NO-CLAIM trên corpus v3fixed

Ngày: 2026-10-12. Plan: `.hermes/plans/2026-10-12_112442-substantive-rl-claim-client-mixed-tier.md`.
Điều kiện đo (mọi regime): real Snort, pipeline fixed_6_fixes, bar two-stream
byte-equality, corpus v3fixed, ownership=client, baseline alerted 40/40 (test)
và 22/22 (train), noop evaded 0 — integrity sạch toàn bộ.

## Câu hỏi

Tồn tại regime nào trên v3fixed mà một policy RL (chỉ nhìn 11 feature
defender-blind) **vượt được fixed mechanism tốt nhất** không? Định nghĩa:
`headroom = oracle − best_single`, trong đó best_single = số flow valid của
fixed policy "luôn dùng M" tốt nhất, oracle = số flow có ≥1 mechanism valid.
RL chỉ có claim thực chất khi headroom > 0 VÀ cơ chế tối ưu per-flow suy ra
được từ observation.

## Số đo (trace: các file JSON trong `snort_validation/reports/`)

| Regime | best_single | oracle | headroom | nguồn |
|---|---|---|---|---|
| R1: both + ET full (P3, đã có) | split8 40/40 | 40 | **0** | `ppo_v3_both_test_s{7,1337,42}.json`, `ceiling_v3_splitslow_fixed.json` |
| R2: client + ET full, test | split8 15/40 | 15 | **0** | `ceiling_v3_client_test.json` |
| R2: client + ET full, train | split8 18/22 | 18 | **0** | `ceiling_v3_client_train.json` |
| R3: mixed-tier client (http→httpinspect, dns/irc→full), test | split8 15/40 | 15 | **0** | `ceiling_v3_mixed_test.json` (ghép từ `ceiling_v3_client_httpinspect_test.json`) |

Chi tiết cấu trúc winner (client/ET-full, test): 15 flow evadable — 11 flow
thắng bởi {split8, split16, split24, split_slow}, 4 flow bởi {split8, split16,
split_slow}; split24 thua 4 flow nhưng cả 3 mechanism rẻ hơn đều thắng →
constant split8 = oracle. 25 flow (toàn dns) KHÔNG mechanism client-only nào
diệt được (alert bắn trên packet peer — đúng cấu trúc v1 từng đo 17/24).
Mixed-tier: cả 6 http flows thắng đủ 4 fragmentation dưới httpinspect conf,
winner-set giống hệt ET-full → ghép matrix không đổi best_single/oracle.
Train: cùng cấu trúc (18 evadable, split24 kém hơn trên 8 flow, còn lại
thắng đồng loạt) → không có per-flow divergence để học.

## Verdict: GATE H1 FAIL ở cả hai nhánh → NO-CLAIM (Phase 6 của plan)

Trên mọi regime đo được của v3fixed, **tồn tại constant policy đạt đúng
oracle**: split8 (cơ chế fragmentation rẻ nhất) thắng mọi flow mà bất kỳ
mechanism nào thắng được. Do đó không policy nào — RL hay khác — có thể vượt
best fixed mechanism; khoảng cách tối đa có thể đạt là 0. Đây là tính chất
của corpus, không phải của thuật toán:

1. v3fixed được build (`build_corpus_v3.py --verify`) để mọi flow alert bằng
   **đúng một SID family content-based** (test: 2016413 ×25, 2014169 ×8,
   2012533 ×3, 2014635 ×3, 2017287 ×1). Một SID content-based bị diệt bằng
   một kiểu fragmentation đủ nhỏ (unit < pattern length), và cả 4 split đều
   đủ nhỏ → mọi flow evadable đều evadable bằng MỌI fragmentation.
2. Fragmentation là họ cơ chế **đẳng cấu về tác dụng** trên corpus này: không
   có flow nào "chỉ split_slow thắng, split8 thua" (khác giả thuyết đầu plan —
   giả thuyết đó đúng trên corpus v1 cũ với ET full, nơi 17 neris flows cần
   both-ownership; nhưng v3fixed đã đổi SID distribution nên client-only
   không còn cấu trúc đó).

Hệ quả cho thesis (ngôn từ được phép dùng):

- **Được claim (P3, giữ nguyên):** "PPO với real-Snort teacher đạt 40/40 =
  100% valid evasion, bằng đúng measured ceiling, 0 semantics breaks, trên 3
  seeds" — RL *đạt trần*, tự động tìm ra cơ chế thắng mà không thấy ruleset.
- **Được claim (P4, giữ nguyên):** frequency shaping không tạo diversity khi
  constant policy tối ưu — data-capped (`diversity_verdict.md`).
- **KHÔNG được claim:** "RL vượt fixed heuristic / học per-flow mechanism
  selection" — đo headroom = 0 ở mọi regime; claim này sẽ bị bác ngay bởi
  chính ceiling sweep của ta.
- **Đường đúng để có claim mạnh (future work, không làm trong P5):** dựng
  corpus có SID families với match geometry KHÁC nhau — ví dụ trộn rules có
  `depth:`/offset neo đầu payload (chỉ prepend/fragment-offset đặc thù diệt
  được) với rules `fast_pattern` giữa stream (chỉ split unit nhỏ diệt được)
  và rules cần flow-established (chỉ fragmentation đúng thứ tự diệt được).
  Khi đó best_single < oracle theo cấu trúc, và bài toán per-flow selection
  mới tồn tại. `build_corpus_v3.py` đã có sẵn hạ tầng filter-SID để làm việc
  này (cần thêm bước chọn flow theo *tính chất SID*, không chỉ "có SID ngoài
  naive").

## Artifacts

- Sweeps: `ceiling_v3_client_test.json` (600 cells), `ceiling_v3_client_train.json` (330), `ceiling_v3_client_httpinspect_test.json` (90), `ceiling_v3_client_httpinspect_train.json` (30), merged `ceiling_v3_mixed_test.json`.
- Tools: `controls/rl_headroom.py` (+3 tests), `controls/mixed_matrix.py` (provenance của phép ghép R3), flag `--ownership` cho sweep (+3 tests).
- Logs: `logs/sweep_client_{test,train}.log`, `logs/sweep_httpinspect_{test,train}.log`, `logs/headroom_client_test.txt`.
