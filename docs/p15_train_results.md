# P15 — Train với action space hậu-P14 (17 actions)

**Ngày:** 2026-10-13 · Plan: `.hermes/plans/2026-10-13_150427-post-p14-action-space-training.md`
**Policy frozen:** `docs/action_space_policy_p15.md` (D8 reward gate, D9 bar-group
admission, D10 costs) — freeze TRƯỚC mọi code P15 (commit `28fcc33`).

Mọi con số đọc từ JSON trong `snort_validation/reports/`; không số nào ước lượng.

## Phase 1 — Action space 17 (xong, `e1b5f38` + `3be0789` + `557ffa9` + `e651b65`)

- `ACTION_NAMES[15] = http_header_case`, `[16] = query_param_prepend`; idx 0–14 bất biến.
- Reward gate D8: `semantics_ok_reward = byte ∨ D7 ∨ D5` (disjunction — plan draft viết
  `D7∧D5` là **tự mâu thuẫn**: bằng chứng committed `p13_v9_query_prepend.json` cho
  thấy qpp có D7=False, D5=True trên cả 4 flow nó evade; sửa trong
  `action_space_policy_p15.md` mục "Correction vs. the P15 plan draft").
- Mask: 15/16 chỉ mở trên framing http; 16 thêm điều kiện owned payload chứa `?`.
- Regression: 344 passed (6 fail duy nhất = count-pin cũ 15, đã sửa thành 17 trong
  `e651b65` và verify riêng 21+7 passed); named tests P15: 26 passed.

## Phase 2 — Train 3 seed surrogate (`d01f4da`)

| seed | epochs | queries | pct epoch cuối | wall |
|---:|---:|---:|---:|---:|
| 42 | 30 | 1920 | 46.9% | 51s |
| 7 | 30 | 1920 | 43.8% | 47s |
| 1337 | 30 | 1920 | 43.8% | 44s |

Eval surrogate trên 40 flow test (`/tmp/p15_surr_eval_s*.json`):

| seed | valid | mech trên 16 flow HTTP | mech trên 24 flow neris |
|---|---:|---|---|
| 42 | 16/40 | `http_header_pad` ×16 | `noop` ×24 |
| 7 | 16/40 | `http_header_pad` ×16 | `split24` ×17, `pad16` ×7 |
| 1337 | 16/40 | **`http_header_case` ×16** | `noop` ×24 |

**Trên mẫu số D4 (16 flow C2): cả 3 seed = 16/16 (100%)**, mech rẻ (cost 0.05,
0–8 byte wire). Seed 1337 tự tìm ra action mới idx 15 — chuỗi P15 hoạt động end-to-end.

### Phát hiện: replica mù frag3 gap (lệch cấu trúc, KHÔNG phải bug P15)

24 flow neris bị policy bỏ alert vì **surrogate không thưởng được split trên đó**:

- Replica (train): `split8` valid-evasion trên 24 neris = **0/24** (đo trực tiếp,
  in-process, 2026-10-13).
- Real Snort (committed `ceiling_v4_both_test.json`): `split8` = **24/24**,
  `split_slow` = **24/24**.

Nguyên nhân: Snort 2.9 frag3 không reassemble-then-detect với fragment đủ nhỏ
(quyết định #13/P13) — split8 thắng bằng chính gap đó; replica match content trên
payload đã reassemble nên không mô hình hóa được. Hệ quả: **mọi training bằng
surrogate trên corpus cũ đều không thể học split-on-neris**; policy cũ 40/40 của
thesis được train bằng `--real-snort` (README_SIC.md:245). Không sửa replica
(ngoài phạm vi P15); ghi nhận làm giới hạn đã biết của surrogate.

### Hệ quả — deviation có ghi chép

Thêm 1 seed train `--real-snort` (RS64, precedent `ppo_rs64_both_*`):
seed 42, n-flows 64, max-epochs 30, conf 21k → `models/ppo_post_p14_rs_s42.zip`,
`train_post_p14_rs_s42.json`. Lý do: chỉ real-Snort training mới phủ được 24 flow
neris; surrogate seeds giữ nguyên làm bằng chứng cho claim phi-split trên mẫu D4.

## Phase 3 — Eval Snort thật (TBD — điền sau khi chạy)

| model | scorer train | alerted | valid (raw/40) | valid (D4/16) | mech HTTP | mech neris | wire cost |
|---|---|---:|---:|---:|---|---|---:|
| ppo_post_p14_s42 | replica | TBD | TBD | TBD | TBD | TBD | TBD |
| ppo_post_p14_s7 | replica | TBD | TBD | TBD | TBD | TBD | TBD |
| ppo_post_p14_s1337 | replica | TBD | TBD | TBD | TBD | TBD | TBD |
| ppo_post_p14_rs_s42 | real_snort | TBD | TBD | TBD | TBD | TBD | TBD |

Baseline so sánh (committed, KHÔNG chạy lại): `ppo_masked_test.json` (model cũ,
15 actions, real-snort train): 40/40 raw, D4 16/16, mech `split8`×24 + `split24`×16,
wire cost split-family. Fixed mech: `http_header_case` 16/16 D5
(`ceiling_v6_case_fullrules_qbar.json`), `query_param_prepend` 0/16 C2 cũ
(`p14_v10_qpp_old_corpus.json`).

Câu hỏi headline (trả lời bằng số Phase 3, không chọn seed đẹp):
1. Policy 17-action có đạt ≥ coverage fixed mech tốt nhất trên mẫu D4, dưới Snort thật?
2. Nó có chọn mech KHÔNG-split rẻ (0–8 B) thay vì split (+10.744 B) trên flow HTTP?
3. Real-snort train có khôi phục 40/40 raw (A4: split coverage không thấp hơn model cũ)?

## Đính chính baseline (2026-10-13, trước Phase 3)

**Không được** dùng `ppo_masked_test.json` làm baseline so với policy P15. Bằng
chứng (`docs/baseline_ownership_provenance.md`): report đó sinh tại `e6fb02d`
(2026-10-04), **trước** `40fffdf` (2026-10-05) — commit đưa client-only mutation
và strict byte bar vào code. Ở `e6fb02d`, `apply_mech(pkts, mech)` không có
tham số ownership nên nhánh split fragment **mọi** packet có `Raw` (kể cả packet
server), và `semantics_intact` khi đó so **per-packet với command bar relaxed**
("packets that yield no command impose no constraint"). Vậy `40/40 raw` là
**both-ownership + relaxed bar**.

Ba con số baseline hợp lệ cho Phase 3:

| baseline | pipeline | số |
|---|---|---:|
| `oracle_split8_test.json` | real Snort, **client-only**, strict bar | **23/40** (http 16/16, neris 7/24) |
| `ppo_masked_test.json` | real Snort, **both**, relaxed bar | 40/40 *(superseded — chỉ để tham chiếu)* |
| fixed mech trên **mẫu D4** (16 flow C2) | `http_header_case` 16/16 D5 · `query_param_prepend` 0/16 | **16/16** |

Hệ quả cho câu hỏi 3 ở trên: "real-snort train có khôi phục 40/40 raw (A4)" là
câu hỏi **sai baseline**. A4 đúng là: split coverage của model mới **không thấp
hơn** `oracle_split8_test.json` per-framing (http 16/16, neris 7/24) dưới cùng
client-only + strict bar.

## Phase 2b — surrogate direction fix (P15.5/P15.6)

**Nguyên nhân (2 câu).** `RealRulesReplica.parse_ruleset` suy `to_server`/`from_server`
CHỈ từ keyword `flow:`, nên rule UDP của ET Open C2 viết
`alert udp $HOME_NET any -> $EXTERNAL_NET any` không có `flow:` (vd sid:2008581)
rơi vào nhánh payload "both" — replica bắn rule lên packet SERVER nguyên vẹn dù
phía client (bot) đã fragment, nên training surrogate không có tín hiệu evasion cho
`split8` trên 24 flow neris. Fix P15.5: parse direction từ rule HEADER
(`$HOME_NET->$EXTERNAL_NET` = to_server, ngược lại = from_server, còn lại = any) và
thêm tham số `home_ip` tường minh cho `verdict/alert_count/firing_rules/_arms/_payloads`
(`home_ip=None` giữ nguyên hành vi cũ).

**Calibration vs 2 report real-Snort đã commit (P15.6, in-process, KHÔNG chạy Snort).**
`controls/calibrate_surrogate_direction.py` → `snort_validation/reports/surrogate_calibration_p15.json`:

| thí nghiệm | đối chiếu | before (legacy) | after (home_ip) |
|---|---|---:|---:|
| (a) noop, 40 flow | `control_noop_real_snort.json` | 40/40 | **36/40** |
| (b) per-flow action, client-only | `ppo_masked_test.json` | 16/40 | **40/40** |
| (b′) per-flow action, ownership=both | `ppo_masked_test.json` | 40/40 | 40/40 |
| (c) split8, client-only | `oracle_split8_test.json` | 17/40 | **7/40** |

**Hai phát hiện phủ định tiền đề (báo cáo trung thực, không chỉnh model cho đẹp số).**
1. Mức tăng (b) 16→40/40 là **artifact**: `ppo_masked_test.json` sinh tại `e6fb02d`
   (2026-10-04), TRƯỚC client-only `apply_mech` (`40fffdf`, 2026-10-05) — `apply_mech`
   thời điểm đó mutate MỌI packet Raw, nên đây là kết quả real-Snort **both-ownership**
   (40/40 evade). Chấm theo report đó, replica đã fix đoán "không alert" cả 40 flow vì
   lý do SAI; dưới both-ownership fix không đổi gì (b′ = 40/40 cả hai).
2. Với report DUY NHẤT là real-Snort client-only đã commit (`oracle_split8_test.json`,
   `method=constant_action_oracle`) và với control noop, fix **GIẢM** đồng thuận
   (c: 17→7/40; a: 40→36/40). Lý do gốc: `snort_validation/et_open_c2/snort_et_c2.conf`
   cố ý đặt `var HOME_NET any` / `var EXTERNAL_NET any` ("everything is home so rules
   written for both directions can fire"), nên `$HOME_NET any -> $EXTERNAL_NET any`
   nở thành any->any và Snort thật match content ở CẢ HAI chiều. Bằng chứng: 10 flow test
   có pattern sid:2008581 CHỈ ở chiều peer→home, và `control_noop_real_snort.json` cho
   thấy Snort thật alert cả 10. Filter theo header direction không thể bắn ở đó.

**Hệ quả lên retrain: fix là NO-OP.** Corpus pickle (`hidden_defender_corpus.pkl`)
nhúng object `Rule` pickle TRƯỚC khi có field `direction` (getattr → default 'any');
`home_ip` không đổi verdict nào trên đường train (0/680 cell) cũng như trên 40 flow test.
Vì vậy 3 seed retrain cho **đúng số cũ** (xác nhận empirical, không suy đoán):

| seed | final pct epoch 30 (cũ = mới) | surrogate valid/40 | actions_chosen |
|---:|---:|---:|---|
| 42 | 46.9% | 16/40 | `http_header_pad`×16, `noop`×24 |
| 7 | 43.8% | 16/40 | `http_header_pad`×16, `split24`×17, `pad16`×7 |
| 1337 | 43.8% | 16/40 | `http_header_case`×16, `noop`×24 |

Số cũ trong `d01f4da` là 46.9/43.8/43.8% và 16/40 — **trùng khớp byte-for-byte**.
Đây là số **REPLICA**, không phải Snort thật; muốn fix thực sự tác động training thì
phải rebuild corpus (chạy `build_hidden_defender_corpus.py`, parse lại rule) — nằm ngoài
phạm vi P15 và cần quyết định riêng vì (c) cho thấy hướng fix có thể SAI với conf hiện tại.
Xác nhận real-Snort vẫn ở Phase 3.
