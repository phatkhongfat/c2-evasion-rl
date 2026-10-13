# Plan: Validate probe λ=0.6 và ra verdict học thuật (đủ đưa vào thesis chưa)

## Goal

Khi probe λ=0.6 (`proc_5300b113caac`, started 00:47) chạy xong: kiểm chứng toàn vẹn số liệu bằng script có test, so sánh định lượng với λ=0.3 và P3 (λ=0), rồi viết verdict học thuật theo pass bar đã đăng ký trước — PASS → rollout 3 seeds; FAIL → kết luận data-capped có bằng chứng; cả hai nhánh đều trả lời câu "kết quả này đủ đưa vào thesis chưa".

## Current context / assumptions

Repo `/root/.hermes/c2-evasion-rl`, venv `.venv`, branch `packet-level-rl`. HEAD: `8dacf7b` (frequency-penalty shaping, TDD 5 tests). Suite xanh 184 passed / 1 skipped (179 + 5 mới), verifier 109/109.

**Trạng thái đang chạy:** probe λ=0.6 seed 42 (`bash logs/p4_probe.sh 0.6`, log `logs/p4_probe.log`, train log `logs/train_v3div_l0.6_s42.log`, outputs `models/ppo_v3div_l0.6_s42.zip` + `snort_validation/reports/ppo_v3div_l0.6_s42_{train,test}.json`). Script đã sửa bug `.zip.zip` ở lần λ=0.3 nên eval sẽ tự chạy sau train; dòng cuối `logs/p4_probe.log` phải là `[probe] DONE` với cả `train exit=0` và `eval exit=0`.

**Kết quả đã có (đo thật, không suy đoán):**

| Run | valid | diversity | actions | breaks | baseline | train epochs/rate |
|---|---|---|---|---|---|---|
| P3 s42 λ=0 (`ppo_v3_both_test_s42.json`) | 100.0% | 1 | split8 ×40 | 0 | 40/40 | 16 ep, 95.5% |
| P4 probe λ=0.3 (`ppo_v3div_l0.3_s42_test.json`) | 100.0% | 1 | split8 ×40 | 0 | 40/40 | 16 ep, 95.5% |
| P4 probe λ=0.6 | *đang chạy* | | | | | |

λ=0.3 FAIL tiêu chí diversity (≥2) dù các tiêu chí khác đạt. Pass bar đăng ký trước (plan `2026-10-11_182054-fix-single-action-collapse.md`): **PASS ⇔ diversity ≥2 ∧ valid ≥95.0 ∧ breaks=0 ∧ baseline=100.0**; λ=0.6 là phát bắn CUỐI được phép — sau nó chỉ có verdict, không tune thêm.

**Vì sao λ=0.6 có cửa lật tie (để verdict không bị hiểu nhầm là "thử mù"):** trên dns, split8 net = 10−0.40 = 9.60, split16 = 9.50, split_slow = 10−0.65+0.15 = 9.50. λ=0.3 nhân với usage_share ≤1 → penalty ≤0.3 < khoảng cách tới action thay thế... nhưng thực tế λ=0.3 KHÔNG lật được (kết quả đo: vẫn split8 ×40). λ=0.6 cho penalty tối đa 0.6 > 0.10 (chênh split8↔split_slow) nên về lý thuyết đủ lớn — nhưng chỉ khi share tiến gần 1 trong epoch VÀ policy học được mapping per-framing thay vì constant. Kết quả λ=0.3 gợi ý constant-policy là attractor mạnh; λ=0.6 có thể vẫn fail. Verdict phải phản ánh đúng kết quả đo, không phải kỳ vọng.

**Chuẩn học thuật áp cho verdict** (từ skill `references/measurement-freshness-and-confounds.md` + precedent repo):
1. Số chốt bằng real Snort, pipeline `fixed_6_fixes`, bar two-stream byte-equality.
2. Integrity controls: baseline phải alert 40/40 (mọi flow là valid positive), noop-control đã có trong ceiling reports.
3. Không confound: cùng corpus v3fixed, cùng split test 40 flows, cùng ownership=both, cùng conf ET Open full — chỉ λ thay đổi. Model action space phải = 15.
4. Pre-registered pass bar, giới hạn số lần thử đã khai báo (λ ∈ {0.3, 0.6} đúng 2 phát).
5. Số train-report phải self-consistent: `diversity_coef` ghi trong JSON, `evaded ≤ n_flows`, `queries == epochs × n_flows`.

## Architecture / proposed approach

Một script validate thuần (`controls/validate_div_probe.py`) chạy 9 invariant checks trên cặp train/test report của một probe, có unit test (TDD) để chính validator không thể sai âm thầm; sau đó verdict document (`docs/diversity_verdict.md`) lắp số đo được vào decision tree đã đăng ký. Không sửa env/train/eval — chỉ đọc reports.

---

## Step-by-step tasks

### Phase A — Chờ probe và thu số (không poll sleep-loop dài)

**A1.** Chờ `logs/p4_probe.log` xuất hiện dòng `[probe] DONE`. Nếu process chết giữa chừng (không còn `pgrep -af train_hidden_defender` mà chưa DONE): đọc tail train/eval log, chẩn đoán, KHÔNG tự relaunch quá 1 lần; nếu relaunch thì ghi vào Execution log.

```bash
cd /root/.hermes/c2-evasion-rl && tail -3 logs/p4_probe.log
```

Kỳ vọng khi xong: `train exit=0`, `eval exit=0`, `DONE`.

**A2.** Đọc kết quả thô:

```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python -c "
import json
t=json.load(open('snort_validation/reports/ppo_v3div_l0.6_s42_train.json'))
d=json.load(open('snort_validation/reports/ppo_v3div_l0.6_s42_test.json'))
print('TRAIN', {k:t[k] for k in ('diversity_coef','epochs','evasion_pct','evaded','n_flows','semantics_breaks')})
print('EVAL ', {k:d[k] for k in ('valid_evasion_pct','mechanism_diversity','actions_chosen','semantics_breaks','baseline_alert_pct')})
print('PER-FRAMING', {k:v['valid_evasion'] for k,v in d['per_framing'].items()})
"
```

### Phase B — Validator có test (TDD, ~20 phút)

**B1 (RED).** Tạo `tests/test_validate_div_probe.py`:

```python
"""The probe validator must accept a known-good P3-style report and reject
tampered ones.  A validator that cannot fail is not a check."""
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path("/root/.hermes/c2-evasion-rl")
sys.path.insert(0, str(REPO / "controls"))
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))

from validate_div_probe import validate_pair  # noqa: E402

GOOD = REPO / "snort_validation/reports/ppo_v3_both_test_s42.json"
GOOD_TRAIN = REPO / "snort_validation/reports/ppo_v3_train_s42.json"


def test_known_good_p3_report_passes():
    problems = validate_pair(GOOD_TRAIN, GOOD)
    assert problems == [], f"good report flagged: {problems}"


def test_tampered_valid_count_is_rejected(tmp_path):
    d = json.loads(GOOD.read_text())
    d["valid_evasion"] = d["valid_evasion"] - 1      # aggregate != per-flow sum
    p = tmp_path / "bad.json"
    p.write_text(json.dumps(d))
    problems = validate_pair(GOOD_TRAIN, p)
    assert any("aggregate" in x for x in problems)


def test_missing_baseline_control_is_rejected(tmp_path):
    d = json.loads(GOOD.read_text())
    d["baseline_alert_pct"] = 97.5                   # control must be 100
    p = tmp_path / "bad.json"
    p.write_text(json.dumps(d))
    problems = validate_pair(GOOD_TRAIN, p)
    assert any("baseline" in x for x in problems)


def test_semantics_break_is_rejected(tmp_path):
    d = json.loads(GOOD.read_text())
    d["semantics_breaks"] = 1
    p = tmp_path / "bad.json"
    p.write_text(json.dumps(d))
    problems = validate_pair(GOOD_TRAIN, p)
    assert any("semantics" in x for x in problems)


def test_train_report_self_consistency_is_enforced(tmp_path):
    t = json.loads(GOOD_TRAIN.read_text())
    t["queries"] = t["epochs"] * t["n_flows"] + 1    # impossible
    p = tmp_path / "bad_train.json"
    p.write_text(json.dumps(t))
    problems = validate_pair(p, GOOD)
    assert any("queries" in x for x in problems)
```

Chạy RED:

```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python -m pytest tests/test_validate_div_probe.py -q
```

Kỳ vọng: 5 failed (ImportError `validate_div_probe`). Nếu fail khác hình dạng → sửa test trước.

**B2 (GREEN).** Tạo `controls/validate_div_probe.py`:

```python
#!/usr/bin/env python3
"""Integrity validation for a diversity-probe report pair (train JSON + eval JSON).

Nine invariant checks; returns a list of human-readable problems (empty = OK).
The eval report is the P3 pipeline output (fixed_6_fixes, real Snort, two-stream
byte bar); the checks re-derive every aggregate from the per-flow rows so a
hand-edited or truncated report cannot pass.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path


def validate_pair(train_json: Path, eval_json: Path) -> list:
    problems = []
    t = json.loads(Path(train_json).read_text())
    d = json.loads(Path(eval_json).read_text())
    rows = d.get("per_flow", [])

    # -- eval-side aggregates re-derived from per-flow rows ------------------
    n = d.get("n_flows")
    if n != len(rows):
        problems.append(f"n_flows {n} != per_flow rows {len(rows)}")
    valid = sum(bool(r["valid_evasion"]) for r in rows)
    if valid != d.get("valid_evasion"):
        problems.append(f"aggregate valid_evasion {d.get('valid_evasion')} != per-flow sum {valid}")
    for r in rows:
        recomputed = (not r["alert"]) and r["semantics_ok"]
        if bool(r["valid_evasion"]) != recomputed:
            problems.append(f"per-flow valid_evasion inconsistent with alert/semantics: {r['flow_id'][:40]}")
            break
    # control: every flow must alert at baseline (all-positive corpus)
    if d.get("baseline_alert_pct") != 100.0:
        problems.append(f"baseline control {d.get('baseline_alert_pct')}% != 100.0")
    if d.get("semantics_breaks") != 0:
        problems.append(f"semantics_breaks {d.get('semantics_breaks')} != 0")
    if d.get("scorer") != "real_snort":
        problems.append(f"scorer {d.get('scorer')!r} != 'real_snort'")
    # action mask sanity: chosen action names must exist in the 15-action space
    from hidden_defender_env import ACTION_NAMES
    bad_actions = [r["action"] for r in rows if r["action"] not in ACTION_NAMES]
    if bad_actions:
        problems.append(f"unknown actions chosen: {sorted(set(bad_actions))}")

    # -- train-side self-consistency ------------------------------------------
    if t.get("queries") != t.get("epochs") * t.get("n_flows"):
        problems.append(f"train queries {t.get('queries')} != epochs*n_flows {t.get('epochs')}*{t.get('n_flows')}")
    if t.get("evaded", 10**9) > t.get("n_flows", 0):
        problems.append(f"train evaded {t.get('evaded')} > n_flows {t.get('n_flows')}")
    if "diversity_coef" not in t:
        problems.append("train report missing diversity_coef (not a P4 run?)")
    return problems


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: validate_div_probe.py TRAIN.json EVAL.json")
        return 2
    problems = validate_pair(Path(sys.argv[1]), Path(sys.argv[2]))
    if problems:
        print("FAIL:")
        for p in problems:
            print(" -", p)
        return 1
    print("OK: all invariant checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

Chạy GREEN:

```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python -m pytest tests/test_validate_div_probe.py -q
```

Kỳ vọng: `5 passed`.

**B3.** Chạy validator trên CẢ 3 cặp report (P3 λ=0 s42 làm chứng dương, 2 probe):

```bash
cd /root/.hermes/c2-evasion-rl && \
.venv/bin/python controls/validate_div_probe.py snort_validation/reports/ppo_v3_train_s42.json snort_validation/reports/ppo_v3_both_test_s42.json; \
.venv/bin/python controls/validate_div_probe.py snort_validation/reports/ppo_v3div_l0.3_s42_train.json snort_validation/reports/ppo_v3div_l0.3_s42_test.json; \
.venv/bin/python controls/validate_div_probe.py snort_validation/reports/ppo_v3div_l0.6_s42_train.json snort_validation/reports/ppo_v3div_l0.6_s42_test.json
```

Kỳ vọng: 3 dòng `OK: all invariant checks passed`, exit 0. **Lưu ý:** train report P3 (`ppo_v3_train_s42.json`) KHÔNG có `diversity_coef` → check đó sẽ báo problem cho cặp P3. Xử lý đúng: validator chỉ yêu cầu `diversity_coef` khi eval report là P4 — sửa check thành điều kiện trên TÊN file eval (`"v3div" in str(eval_json)`) và thêm 1 test cho hành vi này (`test_p3_report_not_required_to_have_diversity_coef`) trước khi chạy B3. Kỳ vọng cuối: P3 pair OK, 2 probe pairs OK.

**B4.** Regression + verifier, rồi commit:

```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python -m pytest tests -q 2>&1 | tail -2 && .venv/bin/python controls/verify_report_claims.py 2>&1 | tail -2
```

Kỳ vọng: `190 passed, 1 skipped` (±1 theo test B3 thêm) và `109/109`.

```bash
git add controls/validate_div_probe.py tests/test_validate_div_probe.py
git commit -m "controls: diversity-probe report validator (9 invariants, TDD)"
```

### Phase C — Verdict học thuật theo decision tree (~20 phút)

**C1.** Lắp số λ=0.6 vào decision tree đã đăng ký. Viết `docs/diversity_verdict.md` theo template sau (điền số THẬT từ A2/B3 — không điền trước, không làm tròn):

```markdown
# Verdict: frequency-penalty shaping cho mechanism diversity (P4)

Ngày: <date>. Điều kiện đo: corpus v3fixed, ownership=both, ET Open full,
real Snort (fixed_6_fixes), bar two-stream byte-equality, eval split test 40 flows.
Pass bar đăng ký trước (plan 2026-10-11_182054): diversity ≥2 ∧ valid ≥95% ∧
breaks=0 ∧ baseline=100%; tối đa 2 giá trị λ (0.3, 0.6).

## Kết quả đo

| λ | seed | valid | diversity | actions | breaks | baseline | validator |
|---|---|---|---|---|---|---|---|
| 0.0 (P3) | 42 | <n>/40 | <k> | <dict> | 0 | 40/40 | OK |
| 0.3 | 42 | <n>/40 | <k> | <dict> | 0 | 40/40 | OK |
| 0.6 | 42 | <n>/40 | <k> | <dict> | <b> | <n>/40 | <OK/FAIL> |

## Verdict: <PASS — shaping tạo diversity đủ đưa vào / FAIL — data-capped>

### Nếu PASS (diversity ≥2, valid ≥95%):
- Rollout 3 seeds (s7, s1337; s42 đã có) với λ trúng, driver theo khuôn
  logs/p3_driver.sh, report *_v3div_l<λ>_s{7,1337,42}_test.json.
- Bar rollout: cả 3 seed valid ≥95 ∧ breaks=0 ∧ baseline=100; diversity ≥2 ở ≥2/3.
- Đủ đưa vào thesis: có — dưới dạng "shaping ablation": bảng λ ∈ {0, 0.3, 0.6}
  × {valid, diversity, actions}, kèm ghi chú honest: eval là deterministic
  argmax, diversity đến từ per-framing action selection chứ không phải
  stochasticity; shaping KHÔNG đổi số eval (chỉ đổi train reward).
- Câu phải viết trong limitations: λ lớn hơn có thể đổi thành phần actions
  nhưng cap 0.6 giữ shaping ≪ REWARD_EVADE=10 để không bao giờ manufacture
  evasion (test test_penalty_is_bounded_below_evasion_reward).

### Nếu FAIL (diversity =1 ở cả 0.3 và 0.6):
- Kết luận: diversity=1 trên điều kiện (v3fixed, both, ET full) là DATA-CAPPED,
  không phải tối ưu-hoá fail. Bằng chứng chain:
  1. split8/16/24 và split_slow đều valid 40/40 trên TOÀN BỘ test flows
     (ceiling_v3_splitslow_fixed.json 40/40; P3 eval split8 40/40, split16 40/40)
     → tồn tại constant policy tối ưu; không flow nào BẮT BUỘC đổi mechanism.
  2. Penalty λ≤0.6 chỉ bẻ được thứ tự ưa thích giữa các action cùng valid
     (đo được: λ=0.3 chuyển split16→split8) nhưng không tạo per-flow
     variation vì observation của 33 dns flows gần trùng nhau và mọi action
     winning đều khả dụng trên mọi flow.
  3. Headroom thật chỉ xuất hiện khi data regime đổi: ownership=client + ET
     full (split_slow unique winner 33/40 dns; fast splits 7/40) hoặc tầng
     naive (7 flows bất đồng verdict) — xem diversity_headroom_v3.json và
     caveat stale-sweep bên dưới.
- Đủ đưa vào thesis: CÓ, dưới dạng negative result có kiểm soát (chương
  discussion/limitations): "reward shaping với λ≤0.6 không tạo diversity khi
  tồn tại dominant constant policy; diversity là tính chất của regime
  (ruleset tier × ownership), không phải của thuật toán". Kèm bảng λ-ablation
  ở trên làm bằng chứng số.
- KHÔNG được viết: "policy học được đa dạng mechanism" (sai); "λ=0.6 phá
  evasion" nếu valid vẫn 100% (sai).

## Caveat bắt buộc ghi kèm (mọi nhánh)
- ceiling_v3_expert.json / ceiling_v3_naive.json chạy TRƯỚC fix
  transport-payload (commit 3393644): 33 DNS flows bị scapy dissection nuốt,
  mechanism chưa từng chạy trên chúng (split16 dns: sweep 0/33 vs P3 eval
  33/33 cùng điều kiện). Hai report đó KHÔNG được trích làm headroom; chỉ
  dùng ceiling_v3_splitslow_fixed.json và P3/P4 eval reports.
- Probe = 1 seed. Nếu PASS, số rollout 3 seeds mới là số đưa vào thesis;
  nếu FAIL, kết luận data-capped không phụ thuộc seed (constant policy tối
  ưu là tính chất của data, đã chứng minh bằng ceiling reports).
```

**C2 (chỉ khi PASS):** rollout theo Phase 3 của plan gốc (`2026-10-11_182054`): driver copy khuôn `logs/p3_driver.sh` thêm `--diversity-coef λ`, batch1 s7+s1337 song song → s42 (đã có model+eval từ probe — chỉ ghi nhận, không train lại), eval tuần tự, tên file `*_v3div_l<λ>_*`, validate từng cặp bằng `controls/validate_div_probe.py`, full pytest + verifier, commit reports (force-add models theo convention P3).

**C3 (chỉ khi FAIL):** tạo thêm `docs/diversity_datacap_note.md` NGẮN (~20 dòng) trỏ về verdict doc + headroom json; commit toàn bộ:

```bash
git add docs/diversity_verdict.md snort_validation/reports/ppo_v3div_l0.6_s42_*.json docs/diversity_datacap_note.md
git add -f models/ppo_v3div_l0.6_s42.zip
git commit -m "reports(P4): lambda ablation 0/0.3/0.6 + academic verdict"
```

(Nếu PASS: commit sau rollout, message `reports(P4): diversity rollout 3 seeds <λ> + verdict`.)

### Phase D — Báo cáo user

Một message duy nhất: bảng λ-ablation 3 dòng, verdict 1 câu, chỉ dẫn file (`docs/diversity_verdict.md`), và (nếu PASS) hỏi có chạy rollout ~2.5h không; (nếu FAIL) khẳng định số P3 100% không đổi và negative result đã đủ bằng chứng đưa vào discussion.

## Tests / validation

- TDD validator: RED 5 failed (ImportError) → GREEN 5 passed → chạy trên cặp P3 thật (chứng dương) trước khi tin nó.
- Validator re-derive mọi aggregate từ per-flow rows → report bị sửa tay không qua được.
- Full pytest + verifier 109/109 trước mỗi commit.
- Verdict chỉ dùng số đã validate; mọi claim trong verdict doc phải trỏ được tới một file JSON cụ thể.

## Risks, tradeoffs, and open questions

1. **λ=0.6 có thể vẫn div=1** (λ=0.3 đã vậy, constant policy là attractor). Đây KHÔNG phải rủi ro của plan — cả hai nhánh đều có verdict viết trước, không có nhánh nào phải bịa số.
2. **λ=0.6 có thể giảm valid <95%** (penalty đủ lớn để đôi khi chọn action kém hơn trên flow khó): khi đó FAIL theo bar, ghi đúng số, không hạ bar.
3. **Validator false-negative:** nếu B3 báo FAIL trên cặp λ=0.6, phải phân biệt "report hỏng" (train/eval crash giữa chừng — kiểm tra `exit=0` trong p4_probe.log, chạy lại eval) vs "số thật sự vi phạm invariant" (giữ nguyên, verdict FAIL). Không sửa validator để số pass.
4. **Thời gian:** probe còn ~40-60 phút (train) + ~14 phút (eval). Không relaunch khi thấy im lặng — kiểm tra `pgrep` + log trước (bài học P3: runner lạ).
5. **Open question cho user:** nếu FAIL và anh vẫn muốn một con số diversity ≥2 "đẹp" cho thesis, con đường đúng là Phase 4 optional (ownership=client đối chứng — diversity=2 tự nhiên không cần shaping, ~75 phút), KHÔNG phải tăng λ quá bar. Verdict doc sẽ ghi rõ lựa chọn này.

## Execution log (implementer điền)

- Probe λ=0.6: train epochs=____ rate=____ | eval valid=____ diversity=____ actions=____ breaks=____ baseline=____
- Validator: P3=____ λ0.3=____ λ0.6=____ (OK/FAIL + problems)
- pytest: ____ verifier: ____
- Verdict: PASS / FAIL-data-capped → file: docs/diversity_verdict.md
- Commits: ____________
