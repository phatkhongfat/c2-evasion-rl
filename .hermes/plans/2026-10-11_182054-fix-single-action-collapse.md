# Plan: Sửa collapse 1-action (diversity=1) của policy PPO trên v3fixed

## Goal

Làm policy đã retrain (P3, v3fixed, ownership=both) dùng **≥2 mechanism khác nhau** trên test split mà **không giảm valid_evasion dưới 95%** — bằng frequency-penalty shaping (count-based exploration) đặt sau một flag CLI, với pass bar đăng ký trước; nếu shaping không tạo được diversity thì kết luận trung thực là data-capped và dừng.

## Current context / assumptions

Repo: `/root/.hermes/c2-evasion-rl`, venv `.venv` (py3.11, torch+SB3+sb3-contrib MaskablePPO), branch `packet-level-rl`. Chạy mọi lệnh với workdir tuyệt đối. HEAD hiện tại: `72bbcc1` (P3 reports). Suite xanh: **179 passed / 1 skipped**, verifier **109/109**.

**Hiện trạng (đã đo, không phải suy đoán):**

- 3 model P3 (`models/ppo_v3_both_s{7,1337,42}.zip`) eval real-Snort trên 40 test flows đều **40/40 = 100%** nhưng `mechanism_diversity = 1`: s7/s1337 chọn `split16` ×40, s42 chọn `split8` ×40 (`snort_validation/reports/ppo_v3_both_test_s*.json`).
- **Vì sao collapse là "đúng" của reward hiện tại:** trong điều kiện eval (ownership=both + ET Open full), `split16` clear **cả 40/40** flows (`ceiling_v3_expert.json` per-flow analysis: split8/16/24 thắng trên CÙNG một tập flows, 0/40 flow có bất đồng giữa 3 fast splits) và rẻ hơn split_slow (cost 0.50 vs 0.65). Một action dominant toàn cục → argmax của policy deterministic là hằng số. **Đây là data cap, không phải lỗi tối ưu.** (Nhất quán với kết luận cũ trong memory: "Diversity=2 is data-capped, not a bug".)
- **Số học reward hiện tại giải thích vì sao chỉ cần shaping nhỏ:** `REWARD_EVADE=10`; trên framing dns: `split_slow = 10 − 0.65 + 0.15(bonus dns) = 9.50`, `split16 = 10 − 0.50 = 9.50` → **tie hoàn hảo**; split8 = 9.40. Tie được phá bằng nhiễu trọng số mạng → seed-dependent constant. Một frequency penalty λ ≈ 0.3–0.6 (≪ 10) đủ lật argmax theo từng framing mà không thể biến action fail thành "evasion".
- Nơi heterogeneity per-flow THẬT SỰ tồn tại (để đối chứng, không phải điều kiện chính): (a) ownership=**client** + ET full → split_slow là unique winner trên 33 flows (fast splits chỉ 7/40 — `ceiling_v3_expert.json` + `ceiling_v3_splitslow_fixed.json`); (b) ruleset tầng **naive** → prepend*/length_wrapper/http_header_pad fail trên 7/40 flows nhưng thắng 33 flows khác (`ceiling_v3_naive.json`).

**Research đã đọc, ánh xạ vào lựa chọn:**

| Hướng | Nguồn | Vì sao chọn/không |
|---|---|---|
| Count-based / frequency penalty (bandit analog của pseudo-count) | Bellemare et al. 2016, *Unifying Count-Based Exploration* | **CHỌN** — 5 dòng shaping, test được bằng unit test thuần, chỉ đổi reward lúc train, eval giữ nguyên 100% honest |
| MaxEnt RL / entropy | Haarnoja et al. 2018 (SAC) | Không đủ: eval của ta là `deterministic=True` → entropy chỉ đa dạng hoá policy stochastic, greedy vẫn collapse |
| Quality-Diversity (MAP-Elites / Novelty Search) | Mouret & Clune 2015; Lehman & Stanley 2011 | Quá khổ (YAGNI): đổi deliverable từ 1 policy thành archive elites; để dành làm future work trong thesis |
| ε-greedy / action-mask dropout | kinh điển | Tương đương frequency penalty nhưng thêm hyperparameter lịch trình; penalty đơn giản hơn |
| Data-side fix (đổi điều kiện để mechanisms bất đồng) | chính các ceiling reports ở trên | Là **đối chứng** (Phase 4 optional), không phải fix chính vì task P3 chốt ownership=both |

**Ràng buộc bất biến (từ skill + plan collapse cũ 2026-10-05):**

1. Không xoá entry khỏi `ACTION_NAMES`; không làm yếu `_compute_action_mask()`.
2. `valid_evasion` = `evaded ∧ semantics_ok` — không đổi.
3. Shaping **không bao giờ được manufacture evasion**: chỉ áp lên step đã là valid evasion thật; alert/semantics-break giữ nguyên reward.
4. Mọi con số chốt bằng **real Snort** + baseline control (40/40 alert) + noop control.
5. Report điều kiện mới đặt tên riêng `*_v3div_*` — **không ghi đè** bất kỳ file P3 nào.
6. `--n-flows 22` (= đúng kích thước train split v3fixed; `--n-flows 64` làm rate chia sai mẫu → early-stop ≥90% không bao giờ nổ — bài học P3).
7. **Single-runner discipline**: trước khi launch, kiểm tra không còn runner lạ (`pgrep -af "chain\|train_hidden_defender"`); chỉ MỘT driver; log unbuffered (`PYTHONUNBUFFERED=1` + `python -u`).
8. Parallelism nproc=4: tối đa 2 train song song, seed thứ 3 chạy sau.
9. `--diversity-coef` mặc định **0.0** → hành vi hiện tại bất biến, verifier/reports cũ tái lập được.

**Pass bar đăng ký TRƯỚC (không câu cá):**

- **PASS:** probe seed 42 với λ ∈ {0.3} (nếu fail, thử lại ĐÚNG MỘT lần với λ=0.6): `mechanism_diversity ≥ 2` VÀ `valid_evasion_pct ≥ 95.0` VÀ `semantics_breaks = 0` VÀ `baseline_alert_pct = 100.0` trên eval real-Snort test split v3fixed.
- Pass probe → retrain s7 + s1337 cùng λ, yêu cầu như trên cho cả 3 seed (valid ≥95% mỗi seed; diversity ≥2 ít nhất 2/3 seed).
- **FAIL (sau đúng 2 lần λ):** kết luận bằng văn bản "diversity=1 trên điều kiện này là data-capped: split16 dominant 40/40 với cost thấp hơn mọi alternative; shaping λ≤0.6 không lật được argmax" — giữ flag (default 0), KHÔNG tune thêm, KHÔNG đổi corpus. Chạy Phase 4 optional làm bằng chứng regime có diversity.

## Architecture / proposed approach

Thêm **frequency-penalty shaping** vào `BatchEnv` trong `ai_agent/train_hidden_defender_ppo.py`, sau flag mới `--diversity-coef λ` (default 0.0): mỗi step là valid evasion, trừ thêm `λ · usage_share(action)` vào reward, với `usage_share = count[action]/total_valid` tính TRƯỚC khi tăng count (lần dùng đầu tiên không bị phạt). Counter reset theo episode (= epoch, vì n_steps=22 = đúng 1 lượt corpus). Shaping chỉ tồn tại lúc train — eval pipeline, env scoring, mask, bar **không đổi một dòng nào**, nên số eval vẫn honest tuyệt đối. Toán shaping tách thành hàm thuần `frequency_penalty()` để unit-test không cần Snort.

---

## Step-by-step tasks

### Phase 0 — Đóng băng bằng chứng data-cap (read-only, ~10 phút)

**T0.1** Viết script phân tích `controls/diversity_headroom.py` (mới) đọc 3 ceiling reports và xuất `snort_validation/reports/diversity_headroom_v3.json`: với mỗi (tầng ruleset × ownership) có trong reports, đếm số flow mà ≥2 mechanism có verdict valid KHÁC NHAU ("disagreement flows") — đó là headroom thật cho diversity.

```python
#!/usr/bin/env python3
"""Diversity headroom: flows where mechanisms disagree, per ceiling report.

Reads existing ceiling sweep reports (real Snort) and counts, for each report,
how many test flows have >=2 mechanisms with DIFFERENT valid_evasion verdicts.
Zero disagreement => a constant policy is optimal => diversity=1 is data-capped.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "snort_validation" / "reports"

SOURCES = [
    ("expert_full_both", "ceiling_v3_expert.json"),
    ("naive_both", "ceiling_v3_naive.json"),
    ("splitslow_full_both", "ceiling_v3_splitslow_fixed.json"),
]


def headroom(path: Path) -> dict:
    d = json.loads(path.read_text())
    per_flow = {}
    for c in d["cells"]:
        per_flow.setdefault(c["flow_id"], {})[c["mech"]] = bool(c["valid_evasion"])
    disagree = 0
    for mechs in per_flow.values():
        if len(set(mechs.values())) > 1:
            disagree += 1
    return {
        "report": path.name,
        "ownership": d.get("ownership"),
        "conf": d.get("conf"),
        "n_flows": len(per_flow),
        "disagreement_flows": disagree,
    }


def main() -> int:
    out = [headroom(REPORTS / name) for _tag, name in SOURCES
           if (REPORTS / name).exists()]
    dst = REPORTS / "diversity_headroom_v3.json"
    dst.write_text(json.dumps(out, indent=2))
    print(json.dumps(out, indent=2))
    print(f"[+] {dst}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

Chạy:

```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python controls/diversity_headroom.py
```

Kỳ vọng (đã đo trước bằng tay, script phải khớp): `expert_full_both` → `disagreement_flows: 0` (chứng minh data cap ở điều kiện P3); `naive_both` → `disagreement_flows: 7`; `splitslow_full_both` → `disagreement_flows: 40`. **Nếu expert_full_both ≠ 0 → DỪNG, báo lại** (giả định data-cap sai, kế hoạch này không còn đúng trọng tâm).

**T0.2** Commit:

```bash
git add controls/diversity_headroom.py snort_validation/reports/diversity_headroom_v3.json
git commit -m "controls: diversity headroom analysis (expert-both tier has 0 disagreement flows)"
```

### Phase 1 — TDD frequency-penalty shaping (~30 phút)

**T1.1 (RED)** Tạo `tests/test_diversity_shaping.py`:

```python
"""TDD: --diversity-coef frequency-penalty shaping (P4, 2026-10-11).

The penalty is a count-based exploration term applied ONLY to steps that are
already a valid evasion (invariant: shaping can never manufacture an evasion),
computed from the action-usage share within the current episode (= epoch).
Default coefficient 0.0 must leave the existing reward EXACTLY unchanged.
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path("/root/.hermes/c2-evasion-rl")
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))


def test_frequency_penalty_math():
    from train_hidden_defender_ppo import frequency_penalty
    # first use of an action: count=0 -> no penalty
    assert frequency_penalty(counts={}, total=0, mech="split16", lam=0.5) == 0.0
    # after 3 valid evasions all split16, a 4th split16 is penalised by lam*1.0
    assert abs(frequency_penalty({"split16": 3}, 3, "split16", 0.5) - 0.5) < 1e-9
    # an unused action is never penalised
    assert frequency_penalty({"split16": 3}, 3, "split_slow", 0.5) == 0.0
    # lam=0 disables shaping entirely
    assert frequency_penalty({"split16": 9}, 9, "split16", 0.0) == 0.0


def test_penalty_is_bounded_below_evasion_reward():
    """Shaping must never outweigh a valid evasion (+10) or flip its sign."""
    from train_hidden_defender_ppo import frequency_penalty
    p = frequency_penalty({"split16": 999}, 999, "split16", 0.6)
    assert p <= 0.6 < 10.0


def test_train_cli_exposes_diversity_coef_defaulting_to_zero():
    main_src = (REPO / "ai_agent" / "train_hidden_defender_ppo.py").read_text()
    assert '"--diversity-coef"' in main_src
    # default must be 0.0 so existing reproductions are bit-identical
    assert 'default=0.0' in main_src.split('--diversity-coef')[1][:200]


def test_batch_env_applies_penalty_only_on_valid_evasion():
    """Integration: a stubbed inner env proves (a) valid-evasion reward is
    lowered by the share penalty, (b) alerted/broken steps are untouched."""
    from train_hidden_defender_ppo import BatchEnv
    import numpy as np

    env = BatchEnv.__new__(BatchEnv)          # bypass corpus + Snort
    env.diversity_coef = 0.5
    env._valid_counts = {}
    env._valid_total = 0
    env.n = 2
    env._i = 0

    calls = []

    class _Inner:
        action_space = None
        observation_space = None
        _flows = [{"flow_id": "f0"}, {"flow_id": "f1"}]

        def step(self, action):
            calls.append(action)
            info = dict(flow_id="f0", action="split16")
            if len(calls) == 1:               # first step: valid evasion
                info.update(evaded=True, semantics_ok=True, alert=False)
                return np.zeros(11, np.float32), 10.0, False, False, info
            info.update(evaded=False, semantics_ok=True, alert=True)
            return np.zeros(11, np.float32), -1.0, False, False, info

        def action_masks(self):
            return np.ones(15, dtype=np.int8)

    env.inner = _Inner()
    _o, r1, _t, _tr, _i = env.step(1)
    assert r1 == 10.0, "first use of an action carries no penalty"
    _o, r2, _t, _tr, _i = env.step(1)
    assert r2 == -1.0, "an alerted step must NOT be shaped"
    # third step: valid evasion again, now split16 share = 1/1 -> -0.5
    class _Inner2(_Inner):
        def step(self, action):
            calls.append(action)
            info = dict(flow_id="f1", action="split16",
                        evaded=True, semantics_ok=True, alert=False)
            return np.zeros(11, np.float32), 10.0, False, False, info
    env.inner = _Inner2()
    _o, r3, _t, _tr, _i = env.step(1)
    assert abs(r3 - 9.5) < 1e-9, f"share penalty missing: got {r3}"
```

Chạy RED:

```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python -m pytest tests/test_diversity_shaping.py -q
```

Kỳ vọng: **4 failed** (`ImportError: cannot import name 'frequency_penalty'` cho 2 test đầu; chuỗi `--diversity-coef` không tồn tại; `BatchEnv` chưa có `diversity_coef`). Nếu fail KHÁC hình dạng này (vd syntax error) → sửa test trước khi tiếp tục.

**T1.2 (GREEN)** Sửa `ai_agent/train_hidden_defender_ppo.py`:

1. Thêm hàm thuần ngay sau `QueryCounter` (trước `def main`):

```python
def frequency_penalty(counts: dict, total: int, mech: str, lam: float) -> float:
    """Count-based exploration penalty (Bellemare et al. 2016, bandit analog).

    Returns lam * usage_share(mech), where usage_share is the fraction of this
    episode's VALID EVASIONS that already used `mech`.  The first use of an
    action is free (count=0).  Applied ONLY to valid-evasion steps by
    BatchEnv.step, so it can never manufacture an evasion; lam must stay
    << REWARD_EVADE (10.0) -- the pass bar caps it at 0.6.
    """
    if lam <= 0.0 or total <= 0:
        return 0.0
    return lam * (counts.get(mech, 0) / total)
```

2. Trong `BatchEnv.__init__`, nhận và lưu hệ số (thêm kwarg `diversity_coef: float = 0.0` vào chữ ký, đặt `self.diversity_coef = diversity_coef`, `self._valid_counts = {}`, `self._valid_total = 0`).

3. Trong `BatchEnv.reset()`, thêm ngay sau `self._i = 0`:

```python
        self._valid_counts = {}
        self._valid_total = 0
```

4. Trong `BatchEnv.step()`, thay `return obs, reward, done, False, info` bằng:

```python
        # Frequency-penalty shaping (P4): penalise REPEATED use of the same
        # winning mechanism within the episode so ties (e.g. split16 vs
        # split_slow both net 9.50 on dns) break toward under-used actions.
        # Gated on a REAL valid evasion: alerted / semantics-broken steps keep
        # their exact reward, so shaping can never fake an evasion.
        if self.diversity_coef > 0.0 and info.get("evaded") and info.get("semantics_ok"):
            reward -= frequency_penalty(self._valid_counts, self._valid_total,
                                        info["action"], self.diversity_coef)
            self._valid_counts[info["action"]] = \
                self._valid_counts.get(info["action"], 0) + 1
            self._valid_total += 1
        return obs, reward, done, False, info
```

5. Trong `main()`: thêm argument (cạnh `--corpus`):

```python
    ap.add_argument("--diversity-coef", type=float, default=0.0,
                    help="frequency-penalty coefficient lambda (0.0 = off, "
                         "bit-identical to P3; recommended probe values 0.3/0.6)")
```

và truyền vào BatchEnv: `diversity_coef=args.diversity_coef` trong lời gọi `BatchEnv(...)`; đồng thời ghi `"diversity_coef": args.diversity_coef` vào dict `result` (để report tự khai điều kiện).

6. Cập nhật `tests/test_train_report_schema.py` NẾU nó enumerate khoá của result (kiểm tra bằng `grep -n "diversity\|keys" tests/test_train_report_schema.py`); nếu schema test liệt kê exact keys thì thêm `"diversity_coef"` vào danh sách kỳ vọng — không nới lỏng kiểu kiểm tra.

Chạy GREEN:

```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python -m pytest tests/test_diversity_shaping.py -q
```

Kỳ vọng: `4 passed`. Sau đó chạy regression không-Snort:

```bash
.venv/bin/python -m pytest tests/test_train_cli.py tests/test_train_report_schema.py tests/test_training_coverage.py tests/test_split_slow_action.py -q
```

Kỳ vọng: tất cả pass.

**T1.3** Kiểm tra bất biến default-off bằng smoke replica (2 phút):

```bash
.venv/bin/python ai_agent/train_hidden_defender_ppo.py \
  --corpus snort_validation/reports/hidden_defender_corpus_v3fixed.pkl \
  --n-flows 22 --max-epochs 1 --seed 42 --model-out /tmp/div_off.zip \
  --out /tmp/div_off.json 2>&1 | tail -2
```

Kỳ vọng: `epoch  1: 22 queries, ...` và `/tmp/div_off.json` chứa `"diversity_coef": 0.0`. Kết quả epoch phải TRÙNG với hành vi P3 (cùng seed/split/1 epoch). Commit:

```bash
git add ai_agent/train_hidden_defender_ppo.py tests/test_diversity_shaping.py tests/test_train_report_schema.py
git commit -m "feat(train): --diversity-coef frequency-penalty shaping (default 0.0, TDD)"
```

### Phase 2 — Probe 1 seed với λ=0.3 (real Snort, ~60–75 phút)

**T2.0** Vệ sinh single-runner (bài học P3 — một runner lạ `/tmp/p3_chain.sh` đã spawn trùng tiến trình):

```bash
pgrep -af "chain|train_hidden_defender_ppo|eval_fixed_pipeline" || echo "clean"
```

Kỳ vọng: `clean` (hoặc chỉ các lệnh grep của chính bạn). Nếu có tiến trình lạ → điều tra NGUỒN GỐC trước khi launch, không kill mù.

**T2.1** Viết driver probe `/root/.hermes/c2-evasion-rl/logs/p4_probe.sh`:

```bash
#!/bin/bash
# P4 probe: ONE seed (42) with frequency shaping, then real-Snort eval.
# Reports go to *_v3div_* names; P3 artifacts are NEVER touched.
set -u
cd /root/.hermes/c2-evasion-rl || exit 1
export PYTHONUNBUFFERED=1
CORPUS=snort_validation/reports/hidden_defender_corpus_v3fixed.pkl
LAM="${1:?usage: p4_probe.sh LAM}"
TAG="v3div_l${LAM}_s42"
L=logs/p4_probe.log
echo "[probe] start lam=$LAM $(date -Is)" > $L
.venv/bin/python -u ai_agent/train_hidden_defender_ppo.py \
  --real-snort --ownership both --corpus $CORPUS \
  --n-flows 22 --max-epochs 40 --seed 42 --diversity-coef "$LAM" \
  --model-out "models/ppo_${TAG}.zip" \
  --out "snort_validation/reports/ppo_${TAG}_train.json" \
  > "logs/train_${TAG}.log" 2>&1
echo "[probe] train exit=$? $(date -Is)" >> $L
.venv/bin/python -u ai_agent/eval_fixed_pipeline.py \
  --model "models/ppo_${TAG}.zip" --split test \
  --ownership both --corpus $CORPUS \
  --out "snort_validation/reports/ppo_${TAG}_test.json" \
  --progress "snort_validation/reports/.eval_${TAG}_progress.jsonl" \
  > "logs/eval_${TAG}.log" 2>&1
echo "[probe] eval exit=$? $(date -Is)" >> $L
echo "[probe] DONE $(date -Is)" >> $L
```

**T2.2** Launch background (MỘT process duy nhất, notify):

```bash
cd /root/.hermes/c2-evasion-rl && bash logs/p4_probe.sh 0.3
```

(chạy qua terminal tool với `background=true, notify=true`.)

Poll mỗi ~55s bằng lệnh foreground ngắn (không sleep-loop trong background):

```bash
cd /root/.hermes/c2-evasion-rl && tail -1 logs/p4_probe.log; grep -o "epoch.*" logs/train_v3div_l0.3_s42.log | tail -1
```

Kỳ vọng tiến độ: ~2–4 phút/epoch (real Snort, 22 flows × 15 actions/epoch), early-stop khi ≥90% — tham chiếu P3: s42 không shaping dừng ở epoch 16.

**T2.3** Đọc kết quả probe (chỉ khi `DONE` xuất hiện trong `logs/p4_probe.log`):

```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python -c "
import json
d=json.load(open('snort_validation/reports/ppo_v3div_l0.3_s42_test.json'))
print('valid', d['valid_evasion_pct'], 'diversity', d['mechanism_diversity'],
      'actions', d['actions_chosen'], 'breaks', d['semantics_breaks'],
      'baseline', d['baseline_alert_pct'])
"
```

**Quyết định theo pass bar (đăng ký ở trên):**
- `diversity ≥ 2` VÀ `valid ≥ 95.0` VÀ `breaks = 0` VÀ `baseline = 100.0` → sang Phase 3 với λ=0.3.
- `diversity = 1` → chạy lại probe ĐÚNG MỘT lần với `bash logs/p4_probe.sh 0.6` (file/tag tự đổi theo λ). Nếu λ=0.6 vẫn diversity=1 hoặc valid <95 → **FAIL có kỷ luật**: viết kết luận data-capped vào `docs/` (Task F1 dưới), không probe thêm λ khác.
- `valid < 95` ở λ=0.3 → không tăng λ (λ cao chỉ càng hại valid); thử λ=0.6 chỉ khi diversity=1 VÀ valid ≥95.

**Task F1 (chỉ khi FAIL):** tạo `docs/diversity_datacap_note.md` (~20 dòng) nêu: điều kiện đo (v3fixed, ownership=both, ET full, real Snort), số liệu (`disagreement_flows=0` từ `diversity_headroom_v3.json`; valid_evasion của split16 = 40/40; kết quả probe λ=0.3/0.6), kết luận "diversity=1 là tối ưu của reward trên dữ liệu này; muốn diversity phải đổi regime (client ownership hoặc naive tier — xem headroom report)", và commit cùng 2 report probe. Kết thúc plan tại đây (báo user, KHÔNG tự chạy Phase 4).

### Phase 3 — Rollout 3 seeds (chỉ khi probe PASS, ~2.5–3 giờ)

**T3.1** Viết `logs/p4_driver.sh` theo đúng khuôn `logs/p3_driver.sh` (file có sẵn trong repo — copy cấu trúc), khác 3 điểm:
1. Train command thêm `--diversity-coef "$LAM"` và tag `v3div_l${LAM}_s${s}`.
2. Batch1 = s7+s1337 song song, batch2 = s42 (nproc=4 rule); probe s42 ở Phase 2 ĐÃ train với λ trúng → driver BỎ QUA train s42 nếu `models/ppo_v3div_l${LAM}_s42.zip` tồn tại và `logs/p4_probe.log` có `eval exit=0`, chỉ eval lại nếu chưa có report.
3. Eval tuần tự 3 seed, report `ppo_v3div_l${LAM}_s{7,1337,42}_test.json`.

Trước khi launch, lặp lại vệ sinh T2.0. Launch background + notify, poll như T2.2.

**T3.2** Sau `ALL_DONE`: bảng tổng hợp

```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python -c "
import json
for s in (7,1337,42):
    for lam in ('0.3','0.6'):
        try:
            d=json.load(open(f'snort_validation/reports/ppo_v3div_l{lam}_s{s}_test.json'))
            print(f's{s} lam={lam}: valid={d[\"valid_evasion_pct\"]} div={d[\"mechanism_diversity\"]} actions={d[\"actions_chosen\"]} breaks={d[\"semantics_breaks\"]} baseline={d[\"baseline_alert_pct\"]}')
        except FileNotFoundError: pass
"
```

Pass bar rollout: **cả 3** seed valid ≥95.0, breaks=0, baseline=100.0; diversity ≥2 ở **≥2/3** seed. Nếu seed nào dưới bar → báo số liệu đúng như đo, không thay seed/làm tròn.

**T3.3** Full regression + verifier:

```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python -m pytest tests -q 2>&1 | tail -2
.venv/bin/python controls/verify_report_claims.py 2>&1 | tail -2
```

Kỳ vọng: `179+ passed, 1 skipped` (số pass tăng theo test mới) và `109/109 checks passed, 0 failed`.

**T3.4** Commit:

```bash
git add snort_validation/reports/ppo_v3div_* logs/p4_*.sh
git add -f models/ppo_v3div_*.zip
git commit -m "reports(P4): diversity shaping probe+rollout, 3 seeds, real-Snort eval"
```

(Ghi chú deviation nếu được hỏi: `models/*.zip` bị gitignore theo convention repo; P3 đã force-add theo yêu cầu task — làm giống hệt để nhất quán.)

### Phase 4 — Optional (chỉ chạy khi user gật đầu, KHÔNG tự chạy)

Đối chứng regime có headroom thật: retrain 1 seed với **ownership=client** (λ=0, không shaping) trên v3fixed — dự đoán từ ceiling: policy bắt buộc dùng split_slow cho 33 DNS flows và fast split cho 7 HTTP flows → diversity=2 tự nhiên. Đây là bằng chứng "shaping không phải thứ duy nhất tạo diversity — data regime mới là gốc", phục vụ chương discussion của thesis. Chi phí ~75 phút (1 train + 1 eval).

## Tests / validation

- TDD cycle ở Phase 1: RED (`4 failed` đúng hình dạng ImportError/assert) → GREEN (`4 passed`) → regression targeted → commit.
- Bất biến default-off: `--diversity-coef` vắng mặt ⇒ reward bit-identical P3 (test `test_batch_env_applies_penalty_only_on_valid_evasion` + smoke T1.3 so kết quả epoch trùng).
- Mọi số diversity/evasion chốt bằng eval real-Snort (`eval_fixed_pipeline.py`, fixed_6_fixes, two-stream byte bar) + baseline control 40/40 + pass bar đăng ký trước ở đầu plan.
- Full suite + verifier 109/109 trước mỗi commit reports.

## Risks, tradeoffs, and open questions

1. **Rủi ro chính — shaping vẫn không lật được argmax:** λ·share ≤ 0.6 trong khi các action "thua" kém ≥0.10 net; nếu policy tìm được một action strictly-dominant (không tie), penalty chỉ đổi action khi share·λ > khoảng cách net. Mitigation: pass bar + giới hạn đúng 2 giá trị λ; FAIL thì kết luận data-capped (Phase 0 đã chứng minh headroom=0 — kết luận này có bằng chứng, không phải đoán).
2. **Đánh đổi valid_evasion:** penalty có thể đẩy policy sang action kém hơn trên vài flow (95% bar chấp nhận mất ≤2 flow). Không hạ bar; không báo cáo chọn lọc.
3. **Deterministic eval che diversity stochastic:** ngay cả khi training policy đa dạng, `model.predict(deterministic=True)` là argmax per-obs; diversity chỉ hiện khi obs khác framing dẫn tới argmax khác. Đây là chủ đích (số honest = số deploy được), nhưng phải nói rõ trong báo cáo.
4. **Chi phí:** mỗi seed ~45–60 phút train + ~14 phút eval (real Snort). Probe-then-rollout giới hạn lãng phí ở 1 seed nếu fail.
5. **Runner collision (đã xảy ra ở P3):** luôn làm T2.0 trước khi launch; chỉ một driver duy nhất; không launch lại khi thấy log im lặng — kiểm tra `pgrep snort` trước.
6. **Open question cho user:** (a) chấp nhận điều kiện λ=0.3/0.6 hay muốn probe thêm λ khác ngoài pass bar? (b) có chạy Phase 4 (ownership=client đối chứng) không? (c) P3 models force-add vào git — giữ convention đó cho P4 models?

## Execution log (implementer điền)

- HEAD trước khi bắt đầu: `____________`
- Phase 0 headroom đo được: expert_full_both=____ naive_both=____ splitslow=____
- Probe λ=0.3: epochs=____ valid=____ diversity=____ actions=____
- Probe λ=0.6 (nếu chạy): ____
- Rollout: s7=____ s1337=____ s42=____
- pytest: ____ verifier: ____
- Kết luận: PASS / FAIL-data-capped
