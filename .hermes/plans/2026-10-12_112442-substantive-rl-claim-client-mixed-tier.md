# Plan: Nhánh ownership=client / mixed-tier để có claim RL thực chất

## Goal

Tạo điều kiện đo mà ở đó policy RL học được **vượt mọi fixed-mechanism baseline** (best single action) trên cùng pipeline honest (real Snort, two-stream byte bar) — trước hết bằng nhánh `ownership=client` (không sửa eval), fallback bằng nhánh mixed-tier (per-flow ruleset theo framing) — với headroom gate và RL gate đăng ký trước; nếu cả hai nhánh không có headroom thì kết luận trung thực "không có claim RL thực chất trên corpus này" thay vì nới bar.

## Current context / assumptions

Repo `/root/.hermes/c2-evasion-rl`, venv `.venv` (py3.11, torch+SB3+sb3-contrib), branch `packet-level-rl`, HEAD `2580698`. Suite xanh 190 passed / 1 skipped, verifier 109/109. Corpus: `snort_validation/reports/hidden_defender_corpus_v3fixed.pkl` (train 22 = 20 dns + 2 http; test 40 = 33 dns + 6 http + 1 irc). Chạy mọi lệnh với workdir tuyệt đối `/root/.hermes/c2-evasion-rl`.

**Vấn đề với claim hiện tại (đã đo, P3/P4):** ở điều kiện P3 (ownership=both, ET Open full, v3fixed), split8/16/24 VÀ split_slow đều valid 40/40 → tồn tại constant policy tối ưu → RL đạt 100% nhưng `diversity=1`, không chứng minh được RL *học* gì beyond "chọn đúng 1 action". Verdict P4 (`docs/diversity_verdict.md`): data-capped; diversity/claim thực chất đòi hỏi regime mà **cơ chế tối ưu khác nhau theo flow VÀ dự đoán được từ observation**.

**Vì sao ownership=client là ứng viên số 1 (bằng chứng có sẵn, chưa đo đủ):**
- Tiền lệ v1 corpus: dưới client-only, 17/40 neris flows có packet ĐẦU do peer gửi mang signature (HOME_NET=any) → fast-split phía client KHÔNG diệt được alert, trong khi split_slow (P3, action 14) diệt 40/40 dưới both. Dưới client, split_slow chỉ sửa packet client → số flow thắng chưa biết, **chắc chắn khác split8** → khả năng cao tạo ra per-flow structure: flow này fast-split đủ, flow kia phải split_slow.
- Framing + 8 shallow features (obs 11-dim) là tín hiệu dự đoán; separability thật phải đo (Task T2.3).
- Không cần sửa eval: `eval_fixed_pipeline.py` và train CLI đều đã có `--ownership client` (default). CHỈ sweep đang hardcode `ownership="both"` → phải thêm flag (T1).

**Vì sao mixed-tier là fallback chứ không phải nhánh chính:** cần sửa cả env (2 SnortBatchService route theo framing) lẫn eval (conf per-flow) — invasive hơn; và train split chỉ có 2 http flows nên học tier-http từ 2 mẫu là yếu. Chỉ kích hoạt nếu gate H1 của nhánh client FAIL.

**Con số nền đã đo (không đo lại):**
- Test split baseline alert (ET full, cả client lẫn both): 40/40. baseline_sids test: 2016413 ×25 (DNS .su query), 2014169 ×8 (DNS sinkhole reply), 2012533 ×3 (HTTP Virut), 2014635 ×3, 2017287 ×1.
- split_slow dưới **both**: 40/40 (`ceiling_v3_splitslow_fixed.json`). reorder/ttl: 0/40 (`ceiling_v3_reorder_ttl_fixed.json`).
- Naive tier (4 SID) trên v3fixed: baseline 0/40 → cấu trúc invalid, đã loại (`docs/diversity_verdict.md` addendum). KHÔNG dùng naive conf trong plan này.
- Chi phí Snort thật: sweep 600 cells ≈ 20-25 phút; train 1 seed (22 flows × 15 actions × ~16-20 epochs) ≈ 50-60 phút; eval 40 flows ≈ 14 phút.

**Định nghĩa dùng thống nhất trong plan:**
- `best_single` = max theo mechanism của số flow valid_evasion (fixed policy "luôn dùng M").
- `oracle` = số flow có ≥1 mechanism valid (per-flow best; chính là `ceiling_valid_evasion` của sweep).
- `headroom` = oracle − best_single. RL có đất diễn khi headroom > 0 VÀ cơ chế tối ưu per-flow suy ra được từ obs.

**Pass bar đăng ký TRƯỚC (không câu cá, không nới):**
- **H1 (headroom gate, nhánh client):** trên test-split matrix client+ET-full: `headroom ≥ 4 flows` (≥10 điểm %). Dưới 4 → sang nhánh mixed-tier (Phase 5); mixed cũng < 4 → kết luận NO-CLAIM (Phase 6).
- **H2 (RL gate):** retrain 3 seeds dưới client: **≥2/3 seeds** có `valid_evasion > best_single` (strict) VÀ `valid_evasion ≥ oracle − 4` VÀ `semantics_breaks = 0` VÀ `baseline_alert_pct = 100`.
- **H3 (claim language gate):** nếu policy thắng H2 với ≥2 distinct actions → claim "per-flow mechanism selection". Nếu policy là constant (vd split_slow = oracle) → claim YẾU hơn, ghi đúng: "RL discovered the dominant mechanism that every cheaper fixed heuristic misses" — không được viết "per-flow selection".
- Mọi số chốt bằng real Snort, pipeline fixed_6_fixes, bar two-stream, report tên riêng `*_client_*` / `*_mixed_*`, KHÔNG ghi đè artifact P3/P4.

---

## Phase 0 — Baseline read-only (~5 phút)

**T0.1** Xác nhận trạng thái sạch + số nền:

```bash
cd /root/.hermes/c2-evasion-rl && git log --oneline -1 && pgrep -af "train_hidden_defender|eval_fixed|ceiling_sweep" | grep -v pgrep || echo clean
.venv/bin/python controls/verify_report_claims.py 2>&1 | tail -2
```

Kỳ vọng: HEAD `2580698`, `clean`, `109/109 checks passed, 0 failed`. Nếu có runner lạ → điều tra nguồn gốc trước (bài học P3), không kill mù.

## Phase 1 — Sweep hỗ trợ ownership + đo matrix client (TDD, ~40 phút)

**T1.1 (RED)** Tạo `tests/test_sweep_ownership_flag.py`:

```python
"""TDD: --ownership flag on the ceiling sweep.

The sweep hardcoded ownership='both'; the client-only ceiling (the conservative
threat model) is a different measurement and must be selectable.  Default stays
'both' so existing reports reproduce bit-identically.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "controls"))


def test_parser_defaults_to_both():
    from ownership_ceiling_sweep import build_parser
    assert build_parser().parse_args([]).ownership == "both"


def test_parser_accepts_client():
    from ownership_ceiling_sweep import build_parser
    args = build_parser().parse_args(["--ownership", "client"])
    assert args.ownership == "client"


def test_parser_rejects_unknown_ownership():
    from ownership_ceiling_sweep import build_parser
    import pytest
    with pytest.raises(SystemExit):
        build_parser().parse_args(["--ownership", "server"])
```

```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python -m pytest tests/test_sweep_ownership_flag.py -q
```

Kỳ vọng RED: 2 failed (AttributeError `ownership`), 1 passed (SystemExit chưa có nhưng `--ownership` unknown arg cũng SystemExit — nếu pass cả 3 thì kiểm tra lại test 1/2 thật sự fail vì thiếu attribute).

**T1.2 (GREEN)** Sửa `controls/ownership_ceiling_sweep.py`:

1. Trong `build_parser()` thêm (sau `--corpus`):

```python
    ap.add_argument("--ownership", default="both", choices=("client", "both"),
                    help="packet-ownership model for mechanisms (default both)")
```

2. Trong `main()`: thay HAI chỗ `ownership="both"` (dòng ~64 baseline và ~72 mech) bằng `ownership=args.ownership`; thay `"ownership": "both"` trong dict `out` (dòng ~93) bằng `"ownership": args.ownership`.

```bash
.venv/bin/python -m pytest tests/test_sweep_ownership_flag.py tests/test_sweep_corpus_flag.py tests/test_sweep_mechs_flag.py tests/test_sweep_conf_flag.py -q
```

Kỳ vọng: `9 passed` (3 mới + 6 cũ). Commit:

```bash
git add controls/ownership_ceiling_sweep.py tests/test_sweep_ownership_flag.py
git commit -m "feat(sweep): --ownership flag (default both, backward compatible; TDD)"
```

**T1.3** Chạy sweep CLIENT + ET full trên **test** (15 mechs × 40 flows = 600 cells + 40 baseline; ~25 phút) — chạy nền 1 process duy nhất, poll bằng lệnh foreground ngắn:

```bash
cd /root/.hermes/c2-evasion-rl && PYTHONUNBUFFERED=1 .venv/bin/python -u controls/ownership_ceiling_sweep.py \
  --split test --ownership client \
  --corpus snort_validation/reports/hidden_defender_corpus_v3fixed.pkl \
  --out snort_validation/reports/ceiling_v3_client_test.json \
  > logs/sweep_client_test.log 2>&1
```

**T1.4** Chạy sweep CLIENT trên **train** (15 × 22 = 330 cells; ~14 phút) — cấu trúc train phải cùng dạng (có flow cần split_slow, có flow fast-split đủ) thì việc học mới transfer được:

```bash
cd /root/.hermes/c2-evasion-rl && PYTHONUNBUFFERED=1 .venv/bin/python -u controls/ownership_ceiling_sweep.py \
  --split train --ownership client \
  --corpus snort_validation/reports/hidden_defender_corpus_v3fixed.pkl \
  --out snort_validation/reports/ceiling_v3_client_train.json \
  > logs/sweep_client_train.log 2>&1
```

Kiểm tra integrity cả hai (bắt buộc trước khi dùng):

```bash
.venv/bin/python -c "
import json
for n in ('ceiling_v3_client_test.json','ceiling_v3_client_train.json'):
    d=json.load(open('snort_validation/reports/'+n))
    cells=d['cells']; base={}
    for c in cells: base.setdefault(c['flow_id'], c['baseline_alert'])
    print(n, '| ownership', d['ownership'], '| cells', len(cells),
          '| baseline alerted', sum(base.values()), '/', len(base),
          '| noop evaded', sum(c['evaded'] for c in cells if c['mech']=='noop'))
"
```

Kỳ vọng: ownership=client; baseline alerted = n_flows (40/40, 22/22 — nếu 0 → STOP, corpus/conf mismatch như vụ naive); noop evaded = 0. Commit 2 reports:

```bash
git add snort_validation/reports/ceiling_v3_client_test.json snort_validation/reports/ceiling_v3_client_train.json
git commit -m "measure: client-ownership 15-mech ceiling on v3fixed train+test (real Snort)"
```

## Phase 2 — Headroom analysis + separability (TDD, ~30 phút)

**T2.1 (RED)** Tạo `tests/test_rl_headroom.py`:

```python
"""TDD: controls/rl_headroom.py — best_single / oracle / headroom + obs
separability diagnostic from a ceiling sweep report."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "controls"))


def _fixture(tmp_path):
    # 3 flows: f1 only split8 wins; f2 only split_slow wins; f3 both win.
    cells = []
    def add(fid, framing, mech, valid):
        cells.append({"flow_id": fid, "framing": framing, "mech": mech,
                      "evaded": valid, "semantics_ok": True,
                      "valid_evasion": valid, "baseline_alert": True})
    add("f1", "dns", "split8", True);  add("f1", "dns", "split_slow", False)
    add("f2", "dns", "split8", False); add("f2", "dns", "split_slow", True)
    add("f3", "http", "split8", True); add("f3", "http", "split_slow", True)
    p = tmp_path / "sweep.json"
    p.write_text(json.dumps({"ownership": "client", "cells": cells,
                             "n_flows": 3}))
    return p


def test_best_single_oracle_headroom(tmp_path):
    from rl_headroom import summarize
    s = summarize(_fixture(tmp_path))
    assert s["best_single"] == {"mech": "split8", "valid": 2}
    assert s["oracle"] == 3
    assert s["headroom"] == 1


def test_per_flow_required_mechs(tmp_path):
    from rl_headroom import summarize
    s = summarize(_fixture(tmp_path))
    # flows where ONLY the slow mechanism wins vs only the fast one
    assert s["flows_only_split_slow"] == ["f2"]
    assert s["flows_only_split8"] == ["f1"]
```

Kỳ vọng RED: `2 failed` (ModuleNotFoundError `rl_headroom`).

**T2.2 (GREEN)** Tạo `controls/rl_headroom.py`:

```python
#!/usr/bin/env python3
"""RL headroom from a ceiling sweep: best_single vs oracle, and which flows
require which mechanism.  headroom = oracle - best_single is the maximum a
per-flow-selecting policy can gain over the best fixed mechanism.
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path


def summarize(sweep_path: Path) -> dict:
    d = json.loads(Path(sweep_path).read_text())
    per_mech = Counter()
    winners = {}
    for c in d["cells"]:
        per_mech[c["mech"]] += bool(c["valid_evasion"])
        if c["valid_evasion"]:
            winners.setdefault(c["flow_id"], set()).add(c["mech"])
    n_flows = d.get("n_flows") or len({c["flow_id"] for c in d["cells"]})
    best_mech, best_n = max(per_mech.items(), key=lambda kv: kv[1])
    oracle = len(winners)
    only = {}
    for fid, ms in winners.items():
        for m in ms:
            if ms == {m}:
                only.setdefault(m, []).append(fid)
    return {
        "sweep": Path(sweep_path).name,
        "ownership": d.get("ownership"),
        "n_flows": n_flows,
        "per_mech_valid": dict(per_mech.most_common()),
        "best_single": {"mech": best_mech, "valid": best_n},
        "oracle": oracle,
        "headroom": oracle - best_n,
        "flows_only_split8": sorted(only.get("split8", [])),
        "flows_only_split_slow": sorted(only.get("split_slow", [])),
        "unique_winner_sets": len({frozenset(ms) for ms in winners.values()}),
    }


def separability(matrix_path: Path, corpus_path: Path) -> dict:
    """Diagnostic: can (obs, framing) separate flows by their required winner
    set?  Reports per-feature mean gap between the two largest winner groups.
    Not a gate — informs whether an obs-conditioned policy CAN beat a constant.
    """
    import pickle
    d = json.loads(Path(matrix_path).read_text())
    winners = {}
    for c in d["cells"]:
        if c["valid_evasion"]:
            winners.setdefault(c["flow_id"], set()).add(c["mech"])
    flows = {f["flow_id"]: f for f in
             pickle.load(open(corpus_path, "rb"))["test"] +
             pickle.load(open(corpus_path, "rb"))["train"]}
    groups = {}
    for fid, ms in winners.items():
        groups.setdefault(frozenset(ms), []).append(fid)
    top2 = sorted(groups.values(), key=len, reverse=True)[:2]
    if len(top2) < 2:
        return {"separable_signal": None, "note": "fewer than 2 winner groups"}
    import numpy as np
    a = np.array([flows[f]["obs"] for f in top2[0] if f in flows])
    b = np.array([flows[f]["obs"] for f in top2[1] if f in flows])
    gap = np.abs(a.mean(0) - b.mean(0)) if len(a) and len(b) else None
    return {"group_sizes": [len(top2[0]), len(top2[1])],
            "obs_feature_mean_gap": [round(float(x), 3) for x in gap] if gap is not None else None}


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: rl_headroom.py SWEEP.json [CORPUS.pkl]")
        return 2
    s = summarize(Path(sys.argv[1]))
    print(json.dumps(s, indent=1))
    if len(sys.argv) > 2:
        print(json.dumps(separability(Path(sys.argv[1]), Path(sys.argv[2])), indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

```bash
.venv/bin/python -m pytest tests/test_rl_headroom.py -q
```

Kỳ vọng: `2 passed`. Commit:

```bash
git add controls/rl_headroom.py tests/test_rl_headroom.py
git commit -m "controls: rl_headroom (best_single/oracle/headroom + separability, TDD)"
```

**T2.3 — GATE H1.** Đo headroom thật:

```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python controls/rl_headroom.py \
  snort_validation/reports/ceiling_v3_client_test.json \
  snort_validation/reports/hidden_defender_corpus_v3fixed.pkl | tee logs/headroom_client_test.txt
.venv/bin/python controls/rl_headroom.py snort_validation/reports/ceiling_v3_client_train.json
```

**Decision (ghi vào Execution log):**
- `headroom ≥ 4` trên test → **Phase 3** (train client).
- `headroom < 4` trên test → **Phase 5** (mixed-tier).
- both < 4 → **Phase 6** (NO-CLAIM verdict).
- Ghi luôn `unique_winner_sets` và separability gap — nếu headroom ≥ 4 nhưng `obs_feature_mean_gap` toàn ~0 thì cảnh báo trong report rằng policy nhiều khả năng không học được per-flow mapping (H2 sẽ kiểm chứng bằng số thật, không loại trước).

## Phase 3 — Retrain 3 seeds dưới ownership=client (~3.5 giờ, chỉ khi H1 PASS)

**T3.1** Viết `logs/p5_driver.sh` (copy khuôn `logs/p3_driver.sh`, diff tối thiểu):

```bash
#!/bin/bash
# P5 driver: train 3 seeds on v3fixed with real-Snort teacher under
# ownership=CLIENT, then eval all 3 (same condition). Single runner only.
set -u
cd /root/.hermes/c2-evasion-rl || exit 1
export PYTHONUNBUFFERED=1
CORPUS=snort_validation/reports/hidden_defender_corpus_v3fixed.pkl
L=logs/p5_driver.log
echo "[driver] batch1 (s7,s1337) client start $(date -Is)" >> $L

train_seed() {
  local s=$1
  .venv/bin/python -u ai_agent/train_hidden_defender_ppo.py \
    --real-snort --ownership client --corpus $CORPUS \
    --n-flows 22 --max-epochs 40 --seed $s \
    --model-out "models/ppo_v3_client_s${s}" \
    --out "snort_validation/reports/ppo_v3_client_train_s${s}.json" \
    > "logs/train_v3_client_s${s}.log" 2>&1
  echo "[driver] train s$s exit=$? $(date -Is)" >> $L
}

eval_seed() {
  local s=$1
  .venv/bin/python -u ai_agent/eval_fixed_pipeline.py \
    --model "models/ppo_v3_client_s${s}.zip" --split test \
    --ownership client --corpus $CORPUS \
    --out "snort_validation/reports/ppo_v3_client_test_s${s}.json" \
    --progress "snort_validation/reports/.eval_v3_client_s${s}_progress.jsonl" \
    > "logs/eval_v3_client_s${s}.log" 2>&1
  echo "[driver] eval s$s exit=$? $(date -Is)" >> $L
}

train_seed 7 &
P1=$!
train_seed 1337 &
P2=$!
wait $P1 $P2
echo "[driver] batch1 done $(date -Is)" >> $L
echo "[driver] batch2 (s42) start $(date -Is)" >> $L
train_seed 42
echo "[driver] batch2 done $(date -Is)" >> $L
for s in 7 1337 42; do eval_seed $s; done
echo "[driver] ALL_DONE $(date -Is)" >> $L
```

Lưu ý đã học: `--model-out` KHÔNG đuôi `.zip` (trainer tự thêm); `python -u`; nproc=4 → 2 song song rồi 1; T0 vệ sinh runner trước khi launch (`pgrep -af "train_hidden_defender|ceiling_sweep" | grep -v pgrep || echo clean`).

Launch nền 1 process:

```bash
cd /root/.hermes/c2-evasion-rl && bash logs/p5_driver.sh
```

(terminal tool: background=true; poll bằng lệnh ngắn mỗi ~55s: `tail -1 logs/p5_driver.log; grep -o 'epoch.*' logs/train_v3_client_s7.log | tail -1`.)

**T3.2** Khi `ALL_DONE`: validate + so bar.

```bash
cd /root/.hermes/c2-evasion-rl && for s in 7 1337 42; do
  .venv/bin/python controls/validate_div_probe.py \
    snort_validation/reports/ppo_v3_client_train_s${s}.json \
    snort_validation/reports/ppo_v3_client_test_s${s}.json
done
.venv/bin/python -c "
import json
bs=json.load(open('logs/headroom_client_test.txt'))
best=bs['best_single']['valid']; orc=bs['oracle']
for s in (7,1337,42):
    d=json.load(open(f'snort_validation/reports/ppo_v3_client_test_s{s}.json'))
    print(f's{s}: valid={d[\"valid_evasion\"]}/40 div={d[\"mechanism_diversity\"]} actions={d[\"actions_chosen\"]} breaks={d[\"semantics_breaks\"]} baseline={d[\"baseline_alert_pct\"]}')
print('best_single', best, 'oracle', orc)
"
```

Kỳ vọng validator: `OK` ×3 (lưu ý: `validate_div_probe` chỉ đòi `diversity_coef` khi tên file chứa `v3div` — các report `v3_client` không bị đòi; nếu validator báo problem khác → dừng, điều tra, không sửa số).

**GATE H2/H3:** ≥2/3 seeds `valid > best_single` ∧ `valid ≥ oracle − 4` ∧ breaks=0 ∧ baseline=100 → PASS. Ghi H3 theo actions_chosen (≥2 distinct actions → claim per-flow selection; constant → claim weak, đúng ngôn từ trong pass bar).

**T3.3** Viết `docs/rl_substantive_claim.md`:

```markdown
# RL substantive claim (P5) — ownership=client, ET Open full, v3fixed

Điều kiện: real Snort, fixed_6_fixes, two-stream byte bar, ownership=client
(attacker chỉ sở hữu packet phía bot — threat model bảo thủ), 40 test flows.

| Đại lượng | Giá trị |
|---|---|
| best_single (fixed policy tốt nhất) | <mech> <n>/40 = <pct>% |
| oracle (per-flow best) | <n>/40 = <pct>% |
| headroom | <n> flows |
| RL s7 / s1337 / s42 (valid/40) | <> / <> / <> |
| RL actions per seed | <> |
| semantics_breaks / baseline | 0 / 40-40 mọi seed |

## Claim (chọn đúng 1 theo H3)
[A — per-flow selection:] Policy RL, chỉ quan sát 11 feature defender-blind,
học được per-flow mechanism selection đạt <X>/40, vượt fixed mechanism tốt
nhất (<best_single>/40) +Δ flows, cách oracle ≤4 flows. Không fixed policy
nào đạt được mức này (đo bằng ceiling sweep 600 cells).
[B — dominant mechanism:] Policy RL hội tụ về <mech> đạt <X>/40 trong khi mọi
fixed heuristic rẻ hơn đứng ở ≤<best_single>/40: RL discovered the dominant
mechanism. (KHÔNG viết "per-flow selection".)

## So với P3 (ownership=both)
P3 đạt 100% nhưng constant policy cũng đạt 100% → không phân biệt được RL
với fixed heuristic. P5 bịt lỗ hổng claim đó: cùng pipeline, cùng corpus, chỉ
đổi ownership; mọi số ở bảng trên trace về file JSON trong reports/.
```

**T3.4** Regression + verifier + commit:

```bash
.venv/bin/python -m pytest tests -q 2>&1 | tail -2      # kỳ vọng 195 passed, 1 skipped (190 + 5 test mới P5)
.venv/bin/python controls/verify_report_claims.py 2>&1 | tail -2   # kỳ vọng 109/109
git add docs/rl_substantive_claim.md snort_validation/reports/ppo_v3_client_*.json logs/p5_driver.sh
git add -f models/ppo_v3_client_s7.zip models/ppo_v3_client_s1337.zip models/ppo_v3_client_s42.zip
git commit -m "reports(P5): client-ownership retrain, RL beats best fixed mechanism <X>/40 vs <Y>/40"
```

(Force-add models theo convention P3/P4 đã được user duyệt.)

## Phase 4 — (nằm trong T3.3) Không có task riêng; placeholder để đánh số phase khớp decision tree.

## Phase 5 — Nhánh mixed-tier (CHỈ khi H1 FAIL; ~2 giờ code+sweep, +3 giờ train nếu H1' PASS)

Mô hình: defender chạy protocol-appropriate inspection — HTTP flows đi qua conf `snort_et_c2_httpinspect.conf`, dns/irc qua `snort_et_c2.conf` (ET full). Tier là hàm của framing → observable qua affordance bit, hợp threat model (sensor cấu hình khác nhau theo segment).

**T5.1 (RED)** Tạo `tests/test_mixed_tier.py`: parser flags + routing logic thuần:

```python
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ai_agent"))
sys.path.insert(0, str(ROOT / "snort_validation"))


def test_env_mixed_tier_routes_by_framing():
    from hidden_defender_env import conf_for_flow, HTTPINSPECT_CONF, DEFAULT_CONF
    assert conf_for_flow({"framing": "http"}) == HTTPINSPECT_CONF
    assert conf_for_flow({"framing": "dns"}) == DEFAULT_CONF
    assert conf_for_flow({"framing": "irc"}) == DEFAULT_CONF


def test_train_cli_exposes_mixed_tier():
    src = (ROOT / "ai_agent" / "train_hidden_defender_ppo.py").read_text()
    assert '"--mixed-tier"' in src


def test_eval_cli_exposes_mixed_tier():
    src = (ROOT / "ai_agent" / "eval_fixed_pipeline.py").read_text()
    assert '"--mixed-tier"' in src
```

**T5.2 (GREEN)** Sửa `ai_agent/hidden_defender_env.py`:

```python
DEFAULT_CONF = REPO / "snort_validation/et_open_c2/snort_et_c2.conf"
HTTPINSPECT_CONF = REPO / "snort_validation/et_open_c2/snort_et_c2_httpinspect.conf"


def conf_for_flow(flow) -> Path:
    """Mixed-tier threat model: HTTP-aware sensor on http flows, full ET otherwise."""
    return HTTPINSPECT_CONF if flow.get("framing") == "http" else DEFAULT_CONF
```

Trong `HiddenDefenderEnv.__init__` thêm kwarg `mixed_tier: bool = False`; khi True tạo `self._svc_http = SnortBatchService(conf=HTTPINSPECT_CONF)` cạnh `self._svc` (conf mặc định). Trong `_detected()`:

```python
        if self.real_snort:
            svc = self._svc
            if self.mixed_tier and flow.get("framing") == "http":
                svc = self._svc_http
            res = svc.verdicts_chunked([(pkts, 0)])
            return bool(res.get(0, True))
```

Sửa `eval_fixed_pipeline.py`: thêm `--mixed-tier` (store_true); khi bật, mỗi flow truyền `conf=conf_for_flow(f)` vào CẢ baseline lẫn act `score_flow_real`; ghi `"mixed_tier": true` vào result. Sửa `train_hidden_defender_ppo.py`: thêm `--mixed-tier`, truyền qua `BatchEnv(..., mixed_tier=...)` → inner env; ghi khoá vào report.

Kỳ vọng GREEN: `3 passed` + regression targeted (`tests/test_hidden_defender_env.py tests/test_train_cli.py tests/test_eval_cli.py`).

**T5.3** Đo mixed ceiling CHỈ phần thiếu (http flows × 15 mechs × httpinspect conf = 90 cells, ~5 phút; dns/irc lấy lại từ matrix client Phase 1):

```bash
.venv/bin/python controls/ownership_ceiling_sweep.py --split test --ownership client \
  --corpus snort_validation/reports/hidden_defender_corpus_v3fixed.pkl \
  --conf snort_validation/et_open_c2/snort_et_c2_httpinspect.conf \
  --out snort_validation/reports/ceiling_v3_client_httpinspect.json
```

Viết `controls/mixed_matrix.py` (script ghép, ~30 dòng, không cần TDD riêng — output được gate bằng H1'): với mỗi flow chọn cells theo framing (http → httpinspect report, dns/irc → client report), tính best_single/oracle/headroom y hệt `rl_headroom.summarize`. **Gate H1'**: headroom ≥ 4 → train 3 seeds với `--mixed-tier --ownership client` (khuôn T3.1 thêm flag); nếu train split chỉ có 2 http flows mà H1' pass nhờ http test flows → ghi rõ caveat "tier-http learned from 2 train flows" vào claim doc. H1' < 4 → Phase 6.

**T5.4** Commit code+sweep:

```bash
git add ai_agent/hidden_defender_env.py ai_agent/train_hidden_defender_ppo.py ai_agent/eval_fixed_pipeline.py tests/test_mixed_tier.py controls/mixed_matrix.py snort_validation/reports/ceiling_v3_client_httpinspect.json
git commit -m "feat(env): mixed-tier (per-framing conf) behind flags, default off (TDD)"
```

## Phase 6 — NO-CLAIM verdict (chỉ khi cả H1 và H1' FAIL)

Viết `docs/rl_substantive_claim.md` với verdict: trên v3fixed, cả client-ownership lẫn mixed-tier đều có headroom < 4 flows (số đo kèm file trace); constant policy vẫn tối ưu trong mọi regime đo được → không có claim "RL beats fixed heuristic" trung thực nào trên corpus này; đề xuất honest cho thesis: (a) giữ claim P3 dạng "RL matches the measured ceiling under both-ownership", (b) muốn claim mạnh phải đổi corpus (nhiều SID family hơn để per-flow optimum đa dạng — build_corpus_v3 với `--per-capture` lớn hơn và nhiều capture hơn), KHÔNG phải đổi thuật toán. Commit verdict + headroom logs. Không train gì thêm.

## Tests / validation

- TDD mọi code task: RED (fail đúng hình dạng đã ghi) → GREEN → regression targeted → commit ngay.
- Integrity trước khi dùng số sweep: baseline alerted = n_flows, noop evaded = 0 (bài học naive-tier 0/40); validator `validate_div_probe.py` chạy trên mọi cặp report train/test mới.
- Full pytest + verifier 109/109 trước mỗi commit reports; kỳ vọng cuối: `195 passed, 1 skipped` (nếu chỉ Phase 1-3) hoặc `198+` (thêm mixed-tier).
- Mọi con số trong claim doc trace được về 1 file JSON trong `snort_validation/reports/`.
- Pass bar H1/H2/H3 đăng ký ở đầu plan; cấm nới sau khi thấy số; mỗi gate chỉ đo 1 lần.

## Risks, tradeoffs, and open questions

1. **headroom client có thể < 4** (split_slow dưới client vẫn thắng gần hết 40 flows — chưa đo): khi đó Phase 5/6 kích hoạt theo gate, không improvisation. Đây là lý do sweep chạy TRƯỚC train.
2. **Obs không separable dù headroom ≥ 4**: 17-hard/23-easy (pattern v1) từng không tách được bằng framing; nếu shallow features cũng không tách, policy constant chọn split_slow vẫn có thể = oracle → H3-B (claim yếu). Chấp nhận và ghi đúng ngôn từ.
3. **Train split lệch phân bố** (20 dns + 2 http, SID 2014169 dominant vs test 2016413 dominant): policy có thể học constant đúng cho train nhưng sai cho test → H2 fail. Nếu fail kiểu này (train rate ≥90% nhưng test valid thấp), Execution log phải ghi rõ "generalization failure", không đổ cho under-training và không tăng epochs quá 40 (bar).
4. **Chi phí**: Phase 1+2 ≈ 1 giờ Snort; Phase 3 ≈ 3.5 giờ; Phase 5 (nếu cần) +2 giờ code/sweep +3 giờ train. Tổng worst-case ~8 giờ — mỗi checkpoint (H1, H2) báo user trước khi đốt tiếp.
5. **Mixed-tier honesty**: tier theo framing là giả định threat model (sensor protocol-aware), phải ghi rõ trong claim doc; KHÔNG được trình bày như "ET Open full" thuần.
6. **Single-runner discipline**: mọi launch qua 1 driver, kiểm tra `pgrep` trước; không relaunch khi log im lặng — kiểm tra `pgrep snort` (bài học P3 runner lạ + P4 bug `.zip.zip`).
7. **Open question cho user**: nếu H1 pass nhưng H2 fail cả 3 seeds (RL không với tới oracle), có chấp nhận claim dạng "RL ≥ best_single nhưng < oracle" (yếu hơn bar) hay ghi NO-CLAIM? Plan hiện tại: NO-CLAIM theo bar, không nới.

## Execution log (implementer điền)

- T0: HEAD=____ verifier=____
- T1: sweep test baseline=__/40, train baseline=__/22
- T2.3 GATE H1: best_single=____ oracle=____ headroom=____ winner_sets=____ separability=____ → nhánh: Phase 3 / Phase 5 / Phase 6
- T3.2 GATE H2: s7=__/40 s1337=__/40 s42=__/40 (actions: ____) → PASS/FAIL; H3=A/B
- Phase 5 (nếu chạy): H1' headroom=____ → train s7=__ s1337=__ s42=__
- pytest=____ verifier=____
- Claim doc: docs/rl_substantive_claim.md — verdict: ____
- Commits: ____
