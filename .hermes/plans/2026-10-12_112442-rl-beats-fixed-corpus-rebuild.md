# Plan: RL beats fixed mechanism — rebuild corpus để có headroom thật

## Goal

Làm cho policy RL đạt `valid_evasion` **cao hơn** bất kỳ fixed single mechanism nào trên cùng held-out test split, real Snort, bằng cách rebuild corpus v4 có **winner-signature phân kỳ** (mỗi flow đòi một mechanism khác nhau) thay vì đổi thuật toán RL.

## Current context / assumptions

Repo `/root/.hermes/c2-evasion-rl`, venv `.venv`, branch `packet-level-rl`, HEAD `4c02b21`. Suite 196 passed/1 skip, verifier 109/109.

**Đã đo (P5, real Snort, KHÔNG suy đoán):** trên v3fixed cả 3 regime đều `headroom = oracle − best_single = 0`:

| Regime | best_single | oracle | headroom |
|---|---|---|---|
| both + ET full | split_slow 40/40 | 40 | 0 |
| client + ET full | split8 15/40 | 15 | 0 |
| client + mixed-tier (http→httpinspect) | split8 15/40 | 15 | 0 |

Nguyên nhân gốc: 40 test flows chỉ alert qua **5 SID content-based cùng họ** (2016413×25, 2014169×8, 2012533×3, 2014635×3, 2017287×1). Cùng match geometry → mọi fragmentation byte-safe thắng/thua ĐỒNG LOẠT → winner-set lồng nhau ({split8,16,24,slow} hoặc {split8,16,slow}) → constant split8 = oracle. Không có flow nào "chỉ split_slow mới thắng, split8 thua".

**Đây là vấn đề DỮ LIỆU, không phải thuật toán.** RL đúng và đã đạt trần; chỉ là trần = constant nên không có gì để "beat". Muốn claim "RL beats fixed" phải có corpus mà oracle > best_single.

**Công cụ đã có (P5, tái dùng nguyên trạng):**
- `controls/ownership_ceiling_sweep.py --ownership {client,both} --conf X --corpus Y --mechs A,B` → 600 cells real Snort.
- `controls/rl_headroom.py <sweep.json> [corpus.pkl]` → in `best_single/oracle/headroom/unique_winner_sets/flows_only_X/separability`.
- `controls/mixed_matrix.py` → merge matrix theo framing + gate.
- `controls/build_corpus_v3.py` (SOURCES = 4 capture stratosphere/mcfp, `parse_alerts`, `extract`, `--verify` re-score real Snort, filter `sids - NAIVE`, split per-capture).
- ET ruleset 21374 rules, match geometry ĐA DẠNG: depth 13135, fast_pattern 17104, flow:established 10318, pcre 4304, http_uri 3879, http_header 4307 → nguyên liệu để tạo divergence có thật.
- Env 15-action, ownership param, `--corpus`/`--diversity-coef` flags đã wire end-to-end.

**Giả định:** divergence phải đến từ CAPTURE THẬT (không synthetic). Nếu stratosphere không có flow phân kỳ → honest NO-GO, không chế dữ liệu.

## Architecture / proposed approach

Rebuild corpus v4 bằng `build_corpus_v3.py` mở rộng: với MỖI candidate flow, chạy ceiling sweep 15-mech (client-ownership, ET full) để lấy **winner-signature** (mechanism nào thắng), rồi CHỈ giữ flows có signature phân kỳ (≥2 mechanism class khác nhau thắng các flow khác nhau, để best_single < oracle), stratified split giữ tỉ lệ signature. Đo headroom v4; chỉ train khi `headroom ≥ 4` (gate H1'). Train RL trên v4 (real Snort, ownership phù hợp), eval held-out, claim "RL beats fixed" IFF `RL_valid > best_single` với integrity + no-overfit.

## Step-by-step tasks

### Phase 0 — Baseline read-only (5 phút)
**T0.1** Xác nhận tree sạch + số P5:
```bash
cd /root/.hermes/c2-evasion-rl && git log --oneline -1 && \
.venv/bin/python controls/rl_headroom.py snort_validation/reports/ceiling_v3_client_test.json | grep -E 'best_single|oracle|headroom'
```
Kỳ vọng: HEAD `4c02b21`, headroom 0. **T0.2** Xác nhận alert sources còn đó (`ls snort_validation/pcaps/snort_logs/alert`) — nếu thiếu, chạy lại script coverage cũ (tìm trong git log `parse_alerts`/`/tmp/cov`) TRƯỚC khi build.

### Phase 1 — Winner-signature stratifier (TDD, ~30 phút code + sweep)
**T1.1** RED test `tests/test_winner_signature.py`:
```python
import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "controls"))
from winner_signature import signature_of, divergent_flows, stratified_split

def test_signature_of_collects_winning_mechs():
    cells = [{"flow_id":"f1","mech":"split8","valid_evasion":True},
             {"flow_id":"f1","mech":"split_slow","valid_evasion":False},
             {"flow_id":"f2","mech":"split8","valid_evasion":False},
             {"flow_id":"f2","mech":"split_slow","valid_evasion":True}]
    sig = signature_of(cells)
    assert sig["f1"] == {"split8"} and sig["f2"] == {"split_slow"}

def test_divergent_flows_needs_two_disjoint_signatures():
    sig = {"f1":{"split8"},"f2":{"split_slow"},"f3":{"split8","split_slow"}}
    div = divergent_flows(sig)
    assert set(div["flows"]) == {"f1","f2"}   # f3 wins bằng cả → không phân kỳ
    assert div["n_classes"] >= 2

def test_stratified_split_balances_signatures_across_train_test():
    sig = {f"a{i}":{"split8"} for i in range(10)}
    sig.update({f"b{i}":{"split_slow"} for i in range(10)})
    tr, te = stratified_split(sig, test_ratio=0.25, seed=42)
    # mỗi split phải chứa CẢ HAI signature class
    assert {"split8"} in {frozenset(sig[f]) for f in te}
    assert {"split_slow"} in {frozenset(sig[f]) for f in te}
    assert len(te) == 5
```
Chạy RED: `.venv/bin/python -m pytest tests/test_winner_signature.py -q` → kỳ vọng ModuleNotFoundError (3 failed).

**T1.2** GREEN `controls/winner_signature.py`: implement `signature_of` (dict flow→set mech thắng), `divergent_flows` (trả flows có signature disjoint với ít nhất 1 flow khác + `n_classes`), `stratified_split` (chia theo signature-class, giữ tỉ lệ, seed). Chạy → 3 passed. Commit.

### Phase 2 — Sweep candidate pool lấy signature (~1–2h Snort, nền)
**T2.1** Build candidate pool LỚN (không filter headroom trước): chạy `build_corpus_v3.py` variant `--no-stratify --per-capture 400` ra `/tmp/corpus_v4_candidates.pkl` (mọi alerting flow, đã `--verify` real Snort). Ghi rõ count.
**T2.2** Sweep 15-mech × candidates, ownership=**both** (giữ ceiling cao, nhiều winner class hơn) ET full:
```bash
.venv/bin/python -u controls/ownership_ceiling_sweep.py --split all \
  --ownership both --corpus /tmp/corpus_v4_candidates.pkl \
  --out /tmp/sweep_v4_candidates.json > logs/sweep_v4_candidates.log 2>&1 &
```
(Nền; `--split all` pool train+test candidate; ước tính ~170s/flow × N.) Integrity bắt buộc: baseline alert 100%, noop evaded 0 — nếu sai, DỪNG (bài học naive-tier).

### Phase 3 — Gate H1' trên signature (5 phút tính)
**T3.1** `.venv/bin/python -c "..."` dùng `winner_signature` đọc `/tmp/sweep_v4_candidates.json`: in `n_classes`, count divergent flows, và headroom của subset divergent (dùng `rl_headroom`). **Gate:** `divergent_flows ≥ 8` VÀ subset headroom ≥ 4 → Phase 4. Nếu < → **NO-GO honest**: stratosphere không có flow phân kỳ đủ; ghi verdict, dừng, đề xuất nguồn capture khác (không chế dữ liệu).

### Phase 4 — Build v4 stratified corpus + đo headroom (TDD build, ~15 phút)
**T4.1** RED `tests/test_build_corpus_v4.py`: build phải (a) chỉ giữ divergent flows, (b) split giữ ≥2 signature class mỗi bên, (c) baseline_sids non-empty mỗi flow (valid positive), (d) pickle load được qua `load_corpus(..., corpus=...)`. GREEN: thêm `--stratify-by-signature <sweep.json>` vào builder (gọi `winner_signature`), xuất `snort_validation/reports/hidden_defender_corpus_v4.pkl`. Commit.
**T4.2** Sweep v4 test split 15-mech (client VÀ both), chạy `rl_headroom` → **Gate H1'': `headroom ≥ 4`** trên test split thật. <4 → quay lại Phase 3 nới tiêu chí divergent (đúng 1 lần), fail nữa → NO-GO.

### Phase 5 — Train RL trên v4 (~3.5h, nproc rule: 2 song song rồi 1)
**T5.1** Chain script `logs/p5_train.sh <seed> <ownership>` (mirror `p4_probe.sh`, đổi corpus→v4, `--n-flows` = size train v4): train real Snort + eval held-out. **T5.2** Chạy 3 seeds (7,1337,42) ownership theo regime headroom≥4 (client hoặc both). Early-stop ≥90% như P3/P4.

### Phase 6 — Verdict "RL beats fixed" (TDD gate, ~10 phút)
**T6.1** RED `tests/test_rl_beats_fixed.py`: đọc 3 eval reports v4 + sweep ceiling; assert `RL_valid > best_single` cho ≥2/3 seeds, `RL_valid ≥ oracle − 4`, breaks=0, baseline=100, và RL dùng ≥2 distinct actions (nếu không chỉ là "constant khác"). GREEN = chính reports. **T6.2** `docs/rl_beats_fixed.md`: bảng best_single/oracle/RL-per-seed, ngôn từ claim chặt ("RL exceeds the best fixed mechanism by X pp, selecting per-flow"), trace report. Commit.

### Phase 7 — Full regression + skill
`pytest tests -q` (expect ≥200 passed), `verify_report_claims.py` 109/109, cập nhật skill `c2-evasion-rl` (bài học: headroom=0 do SID-family homogeneity; fix bằng winner-signature stratification, không phải thuật toán). Commit.

## Tests / validation
Mỗi phase TDD RED→GREEN→commit (P1, P4, P6 có test mới). Số chốt bằng real Snort + bar two-stream. Mọi sweep qua integrity (baseline 100%, noop 0). Headroom tính bằng script có test (`rl_headroom` + `winner_signature`), không nhẩm. Claim chỉ viết khi T6.1 GREEN.

## Risks, tradeoffs, open questions
1. **Rủi ro chính: stratosphere cạn flow phân kỳ.** 40 flow hiện tại đồng nhất vì cùng botnet behavior. Candidate pool lớn hơn có thể vẫn <8 divergent → NO-GO. Đây là kết quả chấp nhận được (honest), không phải thất bại. Giảm thiểu: sweep ownership=both (nhiều winner class hơn client), pool per-capture 400.
2. **Divergence "giả" từ bar:** một mechanism "thắng" flow chỉ vì mechanism khác phá semantics trên flow đó (như reorder phá bar 4/40) — KHÔNG phải headroom thật. `winner_signature` phải chỉ đếm `valid_evasion` (đã thế), và verdict phải loại các flow mà "best_single thua" chỉ vì bar, không vì IDS. Ghi rõ.
3. **Overfit:** train/test phải stratified CÙNG signature distribution; nếu RL chỉ thắng nhờ học thuộc train signature mà test lệch → false claim. T6 đối chiếu headroom train vs test.
4. **Chi phí:** sweep candidate pool (Phase 2) là bước đắt nhất (N×170s). Nếu pool 200 flow → ~9h. Giảm: sweep `--mechs split8,split16,split24,split_slow,http_header_pad,length_wrapper,prepend8,pad16` (8 mech đại diện các geometry class, không đủ 15) → ~5h, vẫn đủ phát hiện divergence.
5. **Open Q:** (a) claim ownership=both (ceiling cao, dễ có divergence) hay client (threat model hẹp hơn, honest hơn)? Plan mặc định both, hỏi lại nếu client cần. (b) Chấp nhận `RL ≥ oracle−4` hay phải `= oracle`? (c) Nếu chỉ 2/3 seeds beat best_single → claim "2/3" hay đòi 3/3?

**KHÔNG làm:** đổi thuật toán RL (đã đúng), hạ bar byte-equality (tạo số ảo), tắt integrity gate, chế synthetic flow để có divergence, hạ gate headroom <4.
