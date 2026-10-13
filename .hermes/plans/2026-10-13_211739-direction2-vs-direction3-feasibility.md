# Plan P16 — Hướng 2 (defender thích ứng) vs Hướng 3 (action space tham số hóa): cái nào khả dụng

**Ngày:** 2026-10-13 · **Branch:** `packet-level-rl` · **HEAD khi viết:** `a275c42`
**Loại plan:** feasibility study có gate đo được. **Deliverable chính là một QUYẾT ĐỊNH
có bằng chứng**, không phải code chạy được. Nếu cả hai gate fail → kết luận "cả hai
không khả dụng trên corpus/ruleset đóng băng" cũng là kết quả đạt.

## Goal

Đo, bằng bằng chứng thật (static rule geometry + Snort thật, có ngân sách chặn), xem
**Hướng 2** (defender thích ứng / non-stationary) hay **Hướng 3** (action space
parameterized-compositional) khả dụng cho luận văn — rồi ghi verdict kèm metric
pre-registered cho hướng được chọn.

## Current context / assumptions (đã recon bằng lệnh read-only, 2026-10-13)

**Trạng thái P15 đang mở (phải xử lý trước, xem Phase 0):**
- Một run train `--real-snort` seed 42 **đang chạy** (pid 2409282, epoch ~15/30,
  ~11,5 phút/epoch). Plan này **không được chạy Snort song song** với nó (máy 4 nhân,
  load đã 2.0). Mọi task Snort phải chờ `ps -p 2409282` hết.
- Commit `99356c0` (replica direction fix) **fail calibration** trên cả hai bằng chứng
  client-only: noop 40/40 → **36/40**, `oracle_split8_test.json` 17/40 → **7/40**.
  Nguyên nhân gốc đã verify: `snort_validation/et_open_c2/snort_et_c2.conf:17-18` đặt
  `var HOME_NET any` / `var EXTERNAL_NET any` → header `$HOME_NET any -> $EXTERNAL_NET any`
  nở thành any→any → Snort thật match **cả hai chiều**; 10/40 flow test có pattern
  sid:2008581 **chỉ ở chiều peer→home** và Snort thật alert cả 10.
- `ppo_masked_test.json` (headline 40/40 của thesis) sinh ở `e6fb02d` (4/10), **trước**
  khi client-only `apply_mech` vào ở `40fffdf` (5/10) → nó là kết quả **both-ownership**.
  Baseline client-only đúng là `oracle_split8_test.json`: **23/40** (http 16/16, neris 7/24).

**Bằng chứng cho Hướng 3 (parameterized) — đã đọc rule text thật:**

| SID | classtype | AND-chain clause | dự đoán param-sensitivity |
|---|---|---|---|
| 2012533 (Virut, 4 flow) | trojan-activity | `GET ` depth:4 ∧ `list.php?c=` within:32 ∧ `&v=` distance:0 ∧ `&t=` distance:0 ∧ pcre `/c\x3d[0-9A-F]{100}/i` | **equivalent**: chèn key lạ sau `?` phá clause 2 bất kể tên/độ dài/vị trí; chèn vào *giá trị* `c=` phá pcre nhưng **fail bar D5** (đổi giá trị handler đọc) |
| 2012627 (FakeAV) | trojan-activity | 4 content ∧-chain, có `fast_pattern` | **equivalent**: lowercase MỘT field name cũng phá chain; 0 byte thêm → không khác cost |
| 2014635 (Kazy TLS, 4 flow) | trojan-activity | `byte_test` trên độ dài cipher-suite list | **không có client-side slack** (đã kết luận P14.3) → split-only, mọi split unit等价 |
| 2018959 (sogou, 1 flow) | trojan-activity | `within:2` | **to_client** → bot không sở hữu byte |
| 2023753 (36 flow) | attempted-recon | `offset:5 depth:6` — **anchored, param-sensitive** | **BỊ LOẠI khỏi mẫu D4** |
| 2014169/2027863 (10 flow) | bad-unknown | `offset:2 depth:1` — anchored | **BỊ LOẠI khỏi mẫu D4** |

→ **Nghịch lý trung tâm của Hướng 3:** rule có geometry anchored (nơi tham số *thật sự*
quyết định) nằm NGOÀI mẫu số C2 đóng băng; rule nằm TRONG mẫu số đều là AND-chain mà
phá một clause là đủ, nên mọi tham số hoá đều **outcome-equivalent**. `controls/rule_geometry.py`
đã lập luận đúng điều này cho split unit trên corpus v3fixed.

- Primitive **đã parameterized sẵn**: `snort_validation/fragment_ops.py:40`
  `split_fragments(payload, split_at=8)`, `:74` `overlap_fragments(payload, split_at=8, ...)`
  → mở trục tham số KHÔNG cần viết lại primitive, chỉ cần wrapper action.
- Nhưng **bar-constrained effective action space** nhỏ hơn 17 nhiều: `prepend4/8/12`
  trên HTTP phá request line → D7 fail; `corrupt8`/`overlap8` phá ngữ nghĩa; `noop`
  không né. Phải ĐO bảng này (Task 2.1), không được đoán.

**Bằng chứng cho Hướng 2 (defender thích ứng):**

- **Surrogate KHÔNG thể phân xử vòng lặp**: `real_rules_replica.py:57` `UNSUPPORTED_RE`
  match `pcre|byte_test|byte_extract|byte_jump` nhưng chỉ set flag `uses_unsupported`;
  `Rule.fires()` (dòng 139) **không đọc flag đó** → replica **over-fire** trên rule có
  pcre. sid:2012533 có pcre. → mọi vòng adaptive **bắt buộc dùng Snort thật**.
  Quy mô: `et_open_c2.rules` có **4.304** rule pcre / 21.374; `et_open_3000.rules`
  **17.058** / 52.454.
- **Defender operator cụ thể, kiểm được bằng tay** (cần Snort xác nhận): vá sid:2012533
  bằng cách **rút ngắn literal** `content:"list.php?c="` → `content:"list.php?"`.
  Trên packet đã bị `query_param_prepend` biến đổi
  (`GET /list.php?x=0&c=<100hex>&v=2&t=0.89`): clause 2 vẫn khớp (`list.php?` có mặt),
  `&v=`/`&t=` vẫn khớp, pcre `c=[0-9A-F]{100}` **vẫn khớp** (qpp không đụng giá trị `c=`)
  → rule vá **bắt lại được** evasion đã đo. Dự đoán hệ quả (đây mới là finding):
  attacker phải **rơi về fragmentation** (split8) để sống sót → survival-time xếp hạng
  cơ chế, và "cơ chế cố định tốt nhất" không còn tồn tại đúng như user nhận định.
- **Benign pool là gap thật**: extended corpus chỉ **5/120** flow `baseline_alert=False`
  (`p13_v7_noop.json`); old corpus `rows` 40/40 alerted. Pool train 1.153 flow
  (2 capture: `20110819-bot` 722, `20110811-neris` 471) **chưa từng được đo alert** →
  phải đo mẫu bằng Snort thật (Task 3.1, ngân sách chặn).
- **Chưa có infra nào**: `grep -rln "adaptive|rotate|non_stationary" ai_agent controls
  snort_validation tests` → **rỗng**. Nhưng infra kề cận dùng lại được:
  `controls/make_naive_ruleset.py`, `controls/build_c2_only_ruleset.py`,
  `controls/ruleset_probe.py`, `controls/harvest_alerts.py`, `controls/verify_report_claims.py`.
- **Chi phí Snort đã đo**: conf 21k ≈ **20s/flow**; conf 52k ≈ **70s/flow/mech**;
  harvest 15 capture ≈ 5h. Run train real-Snort hiện tại ≈ 11,5 phút/epoch.

**Ràng buộc phương pháp luận kế thừa (bắt buộc):**
- Gate viết TRƯỚC khi có dữ liệu; không hạ bar, không tune theo kết quả (D10 precedent).
- Không sửa validator để số pass. Báo cáo cả ứng viên hỏng.
- Verify REACHABLE trước khi hứa hướng sửa (P8 vi phạm 2 lần).
- Subagent: cấm chạy Snort / full pytest; `workdir` = repo path.
- Citation phải truy nguồn; ghi ledger `~/.hermes/skills/research/grounded-citations/scripts/sources.py`.

## Architecture / proposed approach

Ba pha đo, mỗi pha có gate pass/fail viết trước: **Phase 1** freeze gate + metric vào
một file policy mới (không đo trước khi freeze); **Phase 2** test Hướng 3 bằng static
rule geometry (rẻ, không Snort) + một lưới Snort nhỏ để xác nhận; **Phase 3** test
Hướng 2 bằng cách dựng benign pool + một defender operator thật + vá ruleset thật và
xác nhận nó bắt lại evasion đã đo. **Phase 4** so sánh hai verdict trên 7 trục và ghi
`docs/p16_direction_verdict.md`; **Phase 5** (chỉ khi G2 pass) pre-register metric
survival-time và thiết kế vòng lặp, KHÔNG train trong plan này.

---

## Phase 0 — Dọn nợ P15 (điều kiện tiên quyết, ~25 phút, không Snort)

Lý do phải làm trước: Phase 3 dùng `oracle_split8_test.json` làm bằng chứng, và Phase 2
dùng replica để prune — nếu replica đang ở trạng thái đã bị chứng minh là tệ hơn và
baseline còn ghi sai ownership thì mọi so sánh phía sau đều lệch.

### T0.1 — Chờ run train real-Snort xong (không làm gì song song)

```bash
cd /root/.hermes/c2-evasion-rl
ps -p 2409282 -o pid,etime,args --no-headers | cut -c1-90
tail -3 /tmp/p15_train_rs_s42.log
```
Kỳ vọng khi xong: process biến mất, log có `[*] ppo: N queries, X%, 30 epochs, scorer=real_snort`,
và `models/ppo_post_p14_rs_s42.zip` + `snort_validation/reports/train_post_p14_rs_s42.json` tồn tại.
**Nếu chưa xong: DỪNG, không chạy task Snort nào.** Các task không-Snort (T0.2–T0.5, 1.x, 2.1) vẫn làm được.

### T0.2 — Revert HÀNH VI của direction fix, giữ bằng chứng

`99356c0` thêm `rule.direction` + `home_ip`. Giữ field/code (vô hại, `home_ip=None`
là legacy) nhưng **ngừng truyền `home_ip`** ở 3 call-site, vì calibration chứng minh
nó làm agreement tệ hơn:

- `ai_agent/hidden_defender_env.py` — trong `_detected()` (~dòng 540-547) đổi
  `flow["replica"].verdict(pkts, home_ip=client_ip_of(flow["flow_id"]))`
  → `flow["replica"].verdict(pkts)` kèm comment 2 dòng trỏ tới
  `snort_validation/reports/surrogate_calibration_p15.json`.
- `controls/surrogate_vs_real_snort.py` và `controls/surrogate_sweep_14mech.py` — bỏ
  tham số `home_ip=` tương tự.

Verify (KHÔNG dùng Snort):

```bash
.venv/bin/python controls/calibrate_surrogate_direction.py 2>&1 | tail -12
```
Kỳ vọng: `noop_agreement_after` trở lại **40**, `oracle_split8_agreement_after` trở lại **17**
(bằng cột "before"), vì after == before khi không truyền home_ip. Nếu khác → dừng, điều tra.

### T0.3 — Ghi provenance của baseline 40/40 (docs, không sửa số cũ)

Tạo `docs/baseline_ownership_provenance.md` (~40 dòng) ghi đúng 4 sự kiện đã verify:
1. `ppo_masked_test.json` sinh ở `e6fb02d` (2026-10-04); `apply_mech(pkts, mech)` lúc đó
   **không có tham số ownership** (verify: `git show e6fb02d:ai_agent/hidden_defender_env.py | grep -n "def apply_mech" -A 4`)
   và nhánh `split` lặp qua **mọi** packet có `Raw` → fragment cả packet server.
2. Client-only bar vào ở `40fffdf` (2026-10-05, "one strict client-stream bar").
3. Baseline client-only đúng: `oracle_split8_test.json` → **23/40** (http 16/16, neris 7/24),
   `pipeline: fixed_6_fixes`, `method: constant_action_oracle`, `action: split8`.
4. `ceiling_v4_both_test.json` là **ownership=both** → không được dùng làm baseline client-only.
Kèm lệnh reproduce cho từng sự kiện. **Không sửa** `ppo_masked_test.json` hay thesis trong task này.

### T0.4 — Sửa A4 baseline trong plan P15 + docs P15

- `.hermes/plans/2026-10-13_150427-post-p14-action-space-training.md`: mục A4 và bảng
  Phase 3 — thay baseline `ppo_masked_test.json 40/40` bằng `oracle_split8_test.json 23/40
  (client-only)`, giữ 40/40 như "both-ownership, superseded".
- `docs/p15_train_results.md`: thêm section `## Đính chính baseline (2026-10-13)` với 3 số
  23/40 · 40/40(both) · 16/16(D4 mẫu C2) và lý do.

### T0.5 — Commit Phase 0

```bash
git add -A ai_agent/hidden_defender_env.py controls/surrogate_vs_real_snort.py \
  controls/surrogate_sweep_14mech.py docs/baseline_ownership_provenance.md \
  docs/p15_train_results.md .hermes/plans/
git commit -F /tmp/p16_msg_0.txt   # nội dung: revert(P16.0) + provenance, dẫn calibration JSON
git log --oneline -1
```
Kỳ vọng: 1 commit mới; `git status --porcelain` không còn file đã sửa (untracked cấm
thêm vẫn nguyên: `rulesets/p13/*.rules`, `rulesets/p13/classification.config`,
`logs/p3_*.sh`, `logs/probe_rbot_privstep.py`, `models/*.zip`).

---

## Phase 1 — Freeze gate G2/G3 + metric (KHÔNG đo trước khi freeze)

### T1.1 — Viết `docs/p16_direction_gates.md`

Nội dung tối thiểu, ghi "**Frozen 2026-10-13, before any P16 measurement**":

**G3 — Hướng 3 khả dụng khi CẢ BA đúng:**
- **G3a** Tồn tại ≥1 SID trong mẫu số D4 đóng băng (`docs/p14_denominator.md`) mà
  fire/no-fire **đảo** khi đổi THAM SỐ của một cơ chế, giữ nguyên danh tính cơ chế.
- **G3b** Tồn tại ≥2 flow trong mẫu D4 có **tham số tối ưu khác nhau** (nếu cùng một
  tham số thắng mọi flow thì fixed choice vẫn gần tối ưu → headroom vs fixed ≈ 0).
- **G3c** Mỗi trục tham số mới có **≥2 giá trị sống sót qua bar D5/D7** (trục tham số
  mà mọi giá trị hợp lệ đều equivalent, hoặc mọi giá trị khác đều phá ngữ nghĩa, là trục rỗng).
- **G3-fail** nếu bất kỳ điều nào sai. Ghi rõ: mở mẫu số để nạp rule anchored
  (2023753/2014169/2027863) là **đổi threat model đã đóng băng** → không được tính là G3 pass.

**G2 — Hướng 2 khả dụng khi CẢ BỐN đúng:**
- **G2a** Benign pool ≥ **50** flow có **0 alert** dưới ruleset hiện hành, đo bằng Snort thật.
- **G2b** Tồn tại ≥1 **rule-hardening operator** (biến đổi rule text, sinh từ rule text
  thật, không viết tay tùy hứng) sao cho ruleset vá (i) vẫn fire trên traffic **chưa
  biến đổi** của flow mà nó từng bắt, (ii) **bắt lại** một evasion đã đo trong report
  đã commit, (iii) **0 alert** trên benign pool G2a.
- **G2c** Sau vòng vá đầu, attacker còn ≥1 cơ chế **khác** sống sót (nếu không, trò chơi
  kết thúc ở round 1 và survival time là hằng số → không có gì cho RL học).
- **G2d** Ngân sách: một vòng đầy đủ (attacker search + defender patch + validate) ≤ **30 phút**
  Snort trên mẫu ≤ 24 flow, để một experiment 5 vòng × 2 seed ≤ 5 giờ.

**Metric pre-registered cho Hướng 2 (chỉ định nghĩa, KHÔNG đo trong plan này):**
- `survival_rounds(mech)` = số vòng defender liên tiếp mà cơ chế `mech` vẫn né được
  (valid dưới bar D5, không chỉ evaded).
- `queries_to_re_evade` = số (flow, mech) probe attacker cần để tìm lại một valid evasion
  sau mỗi vòng vá.
- `mech_switch_count` = số lần attacker phải đổi họ cơ chế (non-split ↔ split) qua các vòng.
- Baseline bắt buộc: **reactive heuristic** (chọn cơ chế rẻ nhất còn sống sót) — nếu nó
  ngang RL thì báo cáo ngang, theo precedent P4 `docs/diversity_verdict.md`.

**Anti-gaming (kế thừa `docs/action_space_policy.md`):** không được làm defender yếu đi
để attacker thắng; operator vá phải là biến đổi **bảo toàn detection trên traffic gốc**
(điều (i) của G2b) và phải được sinh bằng code từ rule text, có log diff.

### T1.2 — Verify + commit

```bash
wc -l docs/p16_direction_gates.md          # kỳ vọng > 55
grep -c "G3a\|G3b\|G3c\|G2a\|G2b\|G2c\|G2d" docs/p16_direction_gates.md   # kỳ vọng >= 7
git add docs/p16_direction_gates.md && git commit -F /tmp/p16_msg_1.txt
```

---

## Phase 2 — Test Hướng 3 (rẻ trước, Snort sau)

### T2.1 — Bảng "live action space dưới bar D5/D7" (in-process, KHÔNG Snort)

Tạo `controls/effective_action_space.py`. Với mỗi (framing, mech) trong `ACTION_NAMES` (17),
trên 16 flow HTTP của mẫu D4 cũ + 4 flow Virut, tính bằng `mutate_client_only` +
`c2_semantics`: `bytes_ok` (bar byte), `d7_ok` (`endpoint_commands_preserved`),
`d5_ok` (`endpoint_query_preserved`), `sem_valid = d7_ok or d5_ok`. In bảng và ghi
`snort_validation/reports/effective_action_space_p16.json`.

```bash
.venv/bin/python controls/effective_action_space.py
# kỳ vọng in được bảng 17 mech × {bytes, d7, d5, sem_valid} trên 20 flow, KHÔNG gọi Snort
```
Đọc kết quả: số mech có `sem_valid > 0` trên HTTP chính là **effective action space**.
Nếu ≤ 4 → ghi thẳng vào verdict rằng không gian *hợp lệ* vốn đã nhỏ, tham số hoá chỉ
mở rộng trong vùng đã equivalent.

### T2.2 — Static parameter-sensitivity (KHÔNG Snort) — gate G3a/G3b

Tạo `controls/param_sensitivity_geometry.py`:
1. Đọc SID list của mẫu D4 từ `docs/p14_denominator.md` (hard-code list + comment trỏ dòng).
2. Dùng `real_rules_replica.parse_ruleset(path, sid_filter=...)` để lấy `Rule` thật
   (KHÔNG tự parse lại — DRY).
3. Với mỗi rule, liệt kê AND-chain clause + modifier; in ra `min_clauses_to_break = 1`
   (vì AND) và, cho từng họ cơ chế, **clause nào bị phá** và **tham số có đổi clause đó không**.
4. Trục tham số cần xét (chỉ những trục có primitive sẵn):
   - `split_at ∈ {2,4,8,16,24,32,64}` → `split_fragments(payload, split_at)`;
   - `query_param_prepend`: (vị trí chèn ∈ {sau `?` đầu, sau `&` cuối}, độ dài ∈ {4,8,16},
     tên key ∈ {`x`, `utm_source`}) — chèn vào **giá trị** của key C2 bị loại ngay vì fail D5;
   - `http_header_case`: tập field lowercase ∈ {1 field, tất cả};
   - `http_header_pad`: (vị trí ∈ {sau request line, giữa 2 header}, độ dài ∈ {8,16,32}).
5. Kết luận từng SID: `param_sensitive: true/false` + lý do một câu.

```bash
.venv/bin/python controls/param_sensitivity_geometry.py | tee /tmp/p16_param_geom.txt
# kỳ vọng: bảng per-SID; dự đoán dựa trên recon = param_sensitive false cho
# 2012533/2012627/2014635/2018959. Nếu ra true ở SID nào -> đó là ứng viên cho T2.3.
```

### T2.3 — Lưới Snort xác nhận (CHỈ khi T2.2 tìm được ≥1 ứng viên `param_sensitive`)

Ngân sách cứng: ≤ 24 run × 20s (conf 21k) ≈ **8 phút**. Chọn ≤ 3 giá trị tham số ×
≤ 8 flow. Chạy qua `controls/ownership_ceiling_sweep.py` nếu nó nhận tham số; nếu không,
viết `controls/param_grid_probe.py` gọi `mutate_client_only` + `SnortBatchService`.

```bash
# CHỈ chạy khi T0.1 xác nhận không còn process Snort nào khác
ps -eo args | grep -c "[s]nort"     # kỳ vọng 0
```
Nếu T2.2 ra **0 ứng viên**: **BỎ QUA T2.3**, ghi "G3a fail by static analysis, no Snort
spent" — đó là kết quả, không phải thiếu sót.

### T2.4 — Verdict Hướng 3 → append vào `docs/p16_direction_gates.md` (section "Verdict G3")

Bảng bắt buộc: G3a/G3b/G3c mỗi dòng PASS/FAIL + con số + đường dẫn report. Commit
`docs(P16.2): direction-3 verdict -- parameterized action space`.

---

## Phase 3 — Test Hướng 2 (benign pool + defender operator thật)

### T3.1 — Dựng benign pool (Snort, ngân sách cứng 25 phút)

Tạo `controls/build_benign_pool.py`:
1. `load_corpus("train")` từ `hidden_defender_corpus.pkl` (1.153 flow, 2 capture).
2. Lấy **mẫu ngẫu nhiên có seed cố định** 60 flow (`np.random.default_rng(42).choice`,
   KHÔNG shuffle toàn bộ — ngân sách).
3. Chạy `noop` (không biến đổi) qua `SnortBatchService` conf 21k → flow nào 0 alert là
   benign candidate.
4. Ghi `snort_validation/reports/benign_pool_p16.json` (flow_id list + n_probed + n_benign)
   và pickle `snort_validation/reports/benign_pool_p16.pkl`.

```bash
# background=true + process_manage wait; KHÔNG nohup, KHÔNG notify dạng string
.venv/bin/python controls/build_benign_pool.py --n 60
# kỳ vọng: 60 flow × ~20s ≈ 20 phút; in "benign: X/60"
```
**G2a gate:** X ≥ 50 → PASS. Nếu X < 50: probe thêm 40 flow (một lần duy nhất, +13 phút);
vẫn < 50 → **G2a FAIL**, ghi trung thực, KHÔNG nới ngưỡng.

### T3.2 — Defender operator: sinh ruleset vá từ rule text (không Snort)

Tạo `controls/defender_patch.py` với **một** operator, viết tổng quát:

```python
def shorten_literal(rule_line: str, sid: int, keep_prefix: bytes) -> str:
    """Rút ngắn content literal dài nhất của `sid` về `keep_prefix`.

    Defender đã quan sát một evasion: nó biết literal nào bị phá, nên nó vá bằng cách
    bỏ phần literal mà attacker có thể chèn byte vào, giữ prefix đặc trưng.
    Bảo toàn detection trên traffic gốc: prefix vẫn xuất hiện trong traffic chưa biến đổi.
    """
```
- Input: `snort_validation/et_open_c2/et_open_c2.rules`, sid 2012533, `keep_prefix=b"list.php?"`.
- Output: `rulesets/p16_adaptive/round1_et_c2.rules` (bản copy với đúng 1 dòng rule bị vá)
  + `rulesets/p16_adaptive/snort_round1.conf` (copy `snort_et_c2.conf`, đổi `include`
  sang rules mới) + `rulesets/p16_adaptive/MANIFEST.md` ghi **diff rule text** trước/sau.
- Verify không Snort: `diff` chỉ đúng 1 dòng thay đổi; `snort -T` **được phép** ở đây
  (chỉ validate conf, không phải chạy pcap) → kỳ vọng exit 0. Lưu ý quirk đã biết:
  `snort -T -r /dev/null` báo "not a regular file" → dùng
  `data/stratosphere/mcfp/CTU-Malware-Capture-Botnet-9/2013-08-20_captureWin5.pcap`.

### T3.3 — Validate operator vá bằng Snort thật (ngân sách ~12 phút)

Ba phép đo, tất cả trên conf `rulesets/p16_adaptive/snort_round1.conf`:
1. **(i) bảo toàn**: 4 flow Virut **chưa biến đổi** → kỳ vọng **alert 4/4**.
2. **(ii) bắt lại evasion**: 4 flow Virut đã `query_param_prepend` (byte-identical với
   `p13_v9_query_prepend.json` — dùng lại `mutate_client_only`) → kỳ vọng **alert 4/4**
   (trước vá: 0/4, đó chính là evasion đã đo).
3. **(iii) không FP**: benign pool từ T3.1 → kỳ vọng **0 alert**.

```bash
.venv/bin/python controls/validate_defender_patch.py --round 1
# kỳ vọng in 3 dòng (i)/(ii)/(iii) với số; ghi reports/defender_round1_p16.json
```
**G2b gate:** cả ba đúng kỳ vọng → PASS. Nếu (ii) ra 0/4 (vá không bắt lại được) →
thử **một** operator thứ hai (thêm clause `content:"&x="`-agnostic: bỏ hẳn `within:32`),
rồi DỪNG — không iterate vô hạn.

### T3.4 — Attacker còn đường nào sau round 1? (G2c, ~10 phút Snort)

Trên cùng 4 flow Virut với ruleset round1, probe các cơ chế **khác** qpp:
`split8`, `split_slow`, `http_header_case`, `noop`.

```bash
.venv/bin/python controls/attacker_response_probe.py --round 1
# kỳ vọng: split8 evaded (dự đoán từ frag3 structural gap, decision #13/P13),
# qpp bị bắt, noop bị bắt. Ghi reports/attacker_response_r1_p16.json
```
**G2c gate:** ≥1 cơ chế khác sống sót → PASS. Nếu 0 → trò chơi kết thúc round 1,
G2c FAIL, Hướng 2 không có non-stationarity đủ dài để cần RL.

### T3.5 — Ngân sách một vòng (G2d)

Cộng wall-time thật của T3.3 + T3.4 (đọc từ `wall_s` trong 2 report) → so với trần 30 phút.
Ghi vào verdict.

### T3.6 — Verdict Hướng 2 → append `docs/p16_direction_gates.md` (section "Verdict G2")

Commit `docs(P16.3): direction-2 verdict -- adaptive defender round 1`.

---

## Phase 4 — So sánh và quyết định

### T4.1 — Viết `docs/p16_direction_verdict.md`

Bảng so sánh 7 trục, mỗi ô phải có **số hoặc đường dẫn report**, không形容词:

| trục | Hướng 2 (adaptive) | Hướng 3 (parameterized) |
|---|---|---|
| Gate kết quả | G2a–G2d | G3a–G3c |
| Snort đã đốt để quyết | T3.1+T3.3+T3.4 phút | T2.3 phút (hoặc 0) |
| Infra viết mới | benign pool, defender_patch, validate, attacker_response, vòng lặp | wrapper tham số + **bar ngữ nghĩa mới cho mỗi trục** |
| Surrogate dùng được? | **Không** (pcre) → mọi vòng là Snort thật | Có một phần (prune lưới) |
| Metric | survival_rounds / queries_to_re_evade / mech_switch_count | headroom vs fixed (metric cũ) |
| Rủi ro claim rỗng | defender do ta thiết kế → phải có điều kiện bảo toàn + FP gate | P13 composite = 0; param equivalence |
| Thời gian tới số đầu tiên | ~1 buổi (đã có T3.3) | ~2 giờ (T2.1–T2.2) |

Kết luận **một** hướng được chọn (hoặc "cả hai fail" / "cả hai pass → chọn theo ngân sách"),
kèm câu trả lời trực tiếp cho câu hỏi của user: *cái nào khả dụng*.

### T4.2 — Commit + cập nhật memory/skill

```bash
git add docs/p16_direction_verdict.md && git commit -F /tmp/p16_msg_4.txt
```
Nếu phát hiện bẫy đo mới (ví dụ replica over-fire pcre): `skill_manage patch` vào
`c2-evasion-rl/references/scoring-pitfalls.md` mục 5.

---

## Phase 5 — CHỈ KHI G2 pass: pre-register experiment survival-time (không train trong plan này)

### T5.1 — Viết `docs/p16_survival_design.md` (thiết kế, chưa chạy)

- **Vòng lặp:** round r: (1) attacker chọn cơ chế cho từng flow trong mẫu; (2) Snort chấm;
  (3) defender quan sát các evasion thành công, sinh patch bằng `defender_patch.py`
  (operator chọn theo clause bị phá — **code sinh, không chọn tay**); (4) validate patch
  (3 điều kiện G2b); (5) tăng r.
- **Ba arm bắt buộc** (để không claim rỗng): `fixed_best_single` (cơ chế cố định tốt nhất
  round 0), `reactive_heuristic` (đổi sang cơ chế rẻ nhất còn sống), `rl_policy`
  (MaskablePPO, observation gồm round-id one-hot hoặc không — ghi rõ lựa chọn và lý do).
- **Mẫu:** ≤ 24 flow (4 Virut + 16 C2 cũ + benign làm FP guard, không tính vào điểm attacker).
- **Ngân sách:** 5 vòng × 2 seed × 30 phút = 5 giờ Snort. Vượt → giảm vòng, không giảm validate.
- **Điều kiện dừng:** round mà không operator nào thoả G2b (defender hết nước đi) →
  ghi `survival_rounds = ∞ (defender exhausted)`, đó là finding, không phải lỗi.

### T5.2 — Không train, không chạy vòng lặp trong plan này. Commit design doc.

---

## Tests / validation

- **Code mới ở Phase 2/3 là script đo, không phải thư viện** → validation = chạy và so
  với kỳ vọng đã ghi trong gate, không phải unit test phủ mọi nhánh. NGOẠI LỆ bắt buộc
  có test (TDD RED→GREEN→commit) cho:
  - `defender_patch.shorten_literal` → `tests/test_defender_patch.py`: input là **rule text
    thật** của sid:2012533 (copy từ ruleset, không gõ lại), assert (a) output chỉ khác
    đúng literal đó, (b) sid/rev/classtype/flow/pcre giữ nguyên, (c) `keep_prefix` xuất hiện,
    (d) `parse_ruleset` trên output vẫn parse ra 1 Rule với clause đã vá.
  - `param_sensitivity_geometry` → `tests/test_param_geometry.py`: với rule 2012533 thật,
    assert `param_sensitive is False` và lý do có chứa "AND-chain"; với rule anchored
    2023753 (`offset:5 depth:6`), assert `param_sensitive is True` (chứng minh analyzer
    phân biệt được, không phải luôn trả False).
- Mỗi task có lệnh + output kỳ vọng ngay trong task. Gate PASS/FAIL phải ghi số, không ghi "có vẻ ổn".
- Regression: sau Phase 0 và sau mỗi commit code, chạy **chỉ** các file named:
  ```bash
  .venv/bin/python -m pytest tests/test_defender_patch.py tests/test_param_geometry.py \
    tests/test_replica_direction.py tests/test_post_p14_actions.py \
    tests/test_reward_semantic_gate.py tests/test_semantics_bar_agreement.py -q
  ```
  Kỳ vọng: all passed. Full suite chạy nền giữa các phase (`background=true` + `process_manage wait`).
- `controls/verify_report_claims.py` phải pass (≥109) sau Phase 0 và sau Phase 4.

## Risks, tradeoffs, open questions

1. **Rủi ro lớn nhất của Hướng 2: defender là artifact do ta thiết kế.** Nếu operator
   yếu, "RL thắng adaptive defender" là claim rỗng. Giảm thiểu: G2b buộc 3 điều kiện
   (bảo toàn detection gốc · bắt lại evasion đã đo · 0 FP trên benign pool), operator sinh
   bằng code có log diff, và arm `reactive_heuristic` làm baseline. Nếu reactive ngang RL
   → báo cáo ngang (precedent P4).
2. **Benign pool có thể không đủ 50.** 5/120 flow extended không alert cho thấy capture
   malware đặc. Nếu G2a fail, Hướng 2 **chết vì thiếu FP guard**, không phải vì thiếu ý tưởng
   — phải ghi đúng như vậy.
3. **Surrogate vô dụng cho vòng adaptive** (pcre) → không có đường rẻ để sweep; mọi vòng
   là Snort thật. Đây là lý do G2d đặt trần 30 phút/vòng.
4. **Hướng 3 nhiều khả năng fail G3a** theo recon tĩnh (AND-chain + bar-constrained).
   Nếu vậy, kết luận phải nói rõ *tại sao*: không phải "tham số hoá vô dụng" mà là
   "trên mẫu số C2 đóng băng, rule có geometry anchored bị loại bởi D4, nên vùng tham số
   hợp lệ còn lại là equivalent". Đó là finding có giá trị phòng thủ.
5. **Cám dỗ mở mẫu số để cứu Hướng 3** (nạp 2023753/2014169 anchored) = **đổi threat model
   đã đóng băng** → cấm, và ghi rõ trong gate G3.
6. **Tranh CPU với run train real-Snort đang chạy** (pid 2409282). T0.1 là gate cứng;
   vi phạm sẽ làm sai cả hai phía (train chậm + probe Snort timeout).
7. **Chi phí cơ hội:** Phase 2 ~2–3 giờ, Phase 3 ~1 giờ Snort + 2 giờ code. Nếu G2 pass
   thì Phase 5 (experiment thật) là ~5 giờ Snort + 1 ngày code — phải hỏi user trước khi vào.
8. **Open question cho user (hỏi ở Phase 4, không tự quyết):** nếu **cả hai** gate pass,
   ưu tiên novelty (Hướng 2, nhiều code mới, metric mới) hay ưu tiên an toàn (Hướng 3,
   dùng lại metric headroom cũ)? Và thesis cần bao nhiêu trang cho mỗi hướng?
9. **Open question kỹ thuật:** Hướng 2 có cần **rotate ruleset** (đổi cả bộ 21k↔52k) ngoài
   patch rule không? Rotate rẻ hơn nhiều về mặt kỹ thuật (đã có 2 conf sẵn) nhưng yếu hơn
   về mặt novelty. Đề xuất: làm patch trước (T3.2), rotate chỉ như một arm phụ nếu còn ngân sách.
