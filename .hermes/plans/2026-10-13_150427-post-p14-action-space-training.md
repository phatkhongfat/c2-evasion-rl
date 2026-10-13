# Plan P15 — Train với action space hậu-P14

**Ngày:** 2026-10-13 · **Branch:** `packet-level-rl` · **HEAD khi viết:** `292ae06`
**Yêu cầu của user:** "làm train action space hậu p14 trước" — đóng vòng RL: hai cơ chế
P14 phải vào `ACTION_NAMES`, policy phải được train thật và validate bằng Snort thật,
thay vì chỉ có oracle bound.

## Goal

Mở rộng action space của `HiddenDefenderEnv` thêm `http_header_case` (idx 15) và
`query_param_prepend` (idx 16), căn reward-gate theo đúng bar ngữ nghĩa đã đóng băng
(D7∧D5), train MaskablePPO 3 seed trên corpus cũ (surrogate), eval Snort thật trên
40 flow test, và so chi phí wire của policy với fixed mech trên mẫu số C2 (D4).

## Current context / assumptions (đã recon bằng lệnh thật, không đoán)

- `ai_agent/hidden_defender_env.py`:
  - `ACTION_NAMES` (dòng ~87) có **15** phần tử, idx 0–14; `N_ACTIONS = len(ACTION_NAMES)`
    (dòng 95) → `Discrete(N_ACTIONS)` (dòng 512) tự mở rộng. **Append cuối list để
    không đổi idx cũ.**
  - `apply_mech` **đã implement cả hai mech mới** (P14.2 mirror): `http_header_case`
    dòng ~334, `query_param_prepend` dòng ~356. Chỉ thiếu exposure làm action.
  - `ACTION_COSTS` (dòng ~107): dict idx 0–14. `PROTOCOL_APPROPRIATE` (dòng ~143):
    `"http": ("http_header_pad", "length_wrapper", "split8", "split16", "split24")`.
  - `mech_applicable` (dòng ~183): `http_header_case` đã nằm chung nhánh
    `("http_header_pad", "http_header_case") → framing == "http"`.
    `query_param_prepend` **chưa có nhánh** → đang return True cho mọi framing (sai).
  - Mask trong `action_masks`/hàm mask (dòng ~583–605): hard-code `mask[12]=0; mask[13]=0`
    khi `framing != "http"`; `mask[14]=0` khi không có owned payload > 8 byte.
  - **Reward gate (dòng ~640–655):** `score()` gọi `semantics_intact()` =
    `bytes_equal_semantics` (bar BYTE). `step()`: `evaded and sem → +10`;
    `evaded and not sem → −10`; trừ `ACTION_COSTS`; `+0.15` nếu mech ∈
    `PROTOCOL_APPROPRIATE[framing]` và evasion hợp lệ.
    → **Blocker cấu trúc:** cả hai mech P14 đổi byte wire có chủ đích → gate hiện tại
    phạt −10 → policy không bao giờ học được chúng.
- `snort_validation/c2_semantics.py`: `bytes_equal_semantics` (437),
  `endpoint_commands_preserved` (516, D7), `endpoint_query_preserved` (560, D5).
  Cả hai bar D7/D5 fail-closed với payload không phải HTTP.
- `docs/action_space_policy.md` (frozen): admission A1–A4; **A2 yêu cầu
  `endpoint_ok` ≥ 90%** — hiểu theo chữ là bar v1 → `query_param_prepend` fail v1
  theo thiết kế → bị chặn vĩnh viễn. Cần quyết định D9 (bar-group) freeze TRƯỚC khi code.
- `docs/action_space_policy_p14.md` (frozen, D4–D7): D6 nói rõ "cơ chế P14 chỉ vào
  `mutate_client_only` + mirror `apply_mech`; **`Discrete(14)` untouched until a full
  sweep passes the admission rules**". Sweep admission (P14.3 + v10) đã có → P15 là
  bước tiếp theo đúng trình tự policy, không phải xé rào.
- Corpus cũ `snort_validation/reports/hidden_defender_corpus.pkl`: 40 test flows,
  `replica` = `RealRulesReplica` armed (conf 21k `et_open_c2`), train được ngay không
  cần Snort. Corpus mở rộng `corpus_p13_extended.pkl`: 120 test, **`replica=None`**,
  obs len 8 (tương thích: env nối `base(8) + framing_features(3)` = OBS_DIM 11),
  framing lưu toàn `'http'` **sai** (detect_framing default; UDP/53 phải là `'dns'`
  theo `controls/merge_corpora.py::corrected_framing`).
- Baseline sự thật đã đo (không đo lại): corpus cũ C2 = 16 flow; `http_header_case`
  16/16 (D5), `query_param_prepend` 0/16 (báo cáo `p14_v10_qpp_old_corpus.json`);
  corpus mở rộng: qpp 4/4 Virut, cost headroom −48% (chỉ dưới bar D5).
- Train CLI: `ai_agent/train_hidden_defender_ppo.py` (SEED=42, N_FLOWS=256,
  MAX_EPOCHS=200 mặc định; các lần train trước dùng 64 flow/epoch, ~23 epoch theo
  `learning_curves_v2.csv`). Eval: `ai_agent/eval_masked_ppo_test.py --model --split
  test --real-snort --out`. `models/` đã tồn tại (5 zip cũ — **model cũ Discrete(15)
  KHÔNG load được vào env Discrete(17)**, phải train mới, không phải bug).
- Quirks môi trường: background thay cho `nohup` (exit −1); KHÔNG truyền `notify`
  dạng string; `process_manage wait` từng session một; pytest full ~8 phút → chạy nền;
  commit message có backtick → dùng `git commit -F file`.

## Architecture / proposed approach

Thêm 2 action append-cuối (idx 15/16) + mask HTTP-only + `ACTION_COSTS` lấy từ wire
cost đã đo (D10). Thay gate reward byte-only bằng hàm **đồng nhất cho mọi mech**:
`sem_ok = bytes_equal ∨ (D7 ∧ D5)` — đúng hai bar đã freeze/citation-gate trước P14,
đặt trong `c2_semantics.py` để train và eval dùng chung một nguồn. Mọi quyết định đổi
luật (D8 reward-gate, D9 admission bar-group, D10 costs) freeze trong file policy mới
`docs/action_space_policy_p15.md` **trước khi sửa code**. Train surrogate trên corpus
cũ (nhanh), số liệu headline lấy từ eval Snort thật — đúng mô hình "hai bộ chấm điểm"
của thesis. Phase 4 (corpus mở rộng) là stretch, chỉ chạy khi Phase 3 xanh.

---

## Phase 0 — Pre-register D8/D9/D10 (chỉ docs, không code)

### T0.1 — Viết `docs/action_space_policy_p15.md`

Nội dung tối thiểu (freeze, ghi ngày 2026-10-13, ghi rõ "frozen before any P15 code
change"; mọi con số dẫn nguồn report đã commit):

- **D8 (reward-bar alignment).** Gate semantics của reward training =
  `bytes_equal_semantics ∨ (endpoint_commands_preserved ∧ endpoint_query_preserved)`.
  Lý do: reward không được nghiêm ngặt hơn metric headline hợp lệ (D7∧D5) — nếu không,
  policy không thể biểu diễn cơ chế thắng đã đo; D7/D5 freeze trước probe P14
  (`action_space_policy_p14.md`), citation-gated (RFC 3986, PHP parse_str), fail-closed
  trên payload không-HTTP nên không rò sang neris/dns. Quy tắc áp **đồng nhất mọi
  mech** — `corrupt8`/`overlap8` vẫn fail vì không qua được D7∧D5. Kết quả bar byte
  vẫn được báo cáo nguyên trạng ở mọi bảng; nới gate chỉ ảnh hưởng reward + A2.
- **D9 (admission bar-group).** A2 của policy frozen được đọc là
  "endpoint_ok ≥ 90% dưới **bất kỳ bar frozen nào** (v1 ∨ D7∧D5)". Ghi rõ trade-off:
  đọc chữ-nghĩa-v1 sẽ loại vĩnh viễn `query_param_prepend` (fail v1 theo thiết kế)
  và làm bất khả thi việc train cơ chế đã đo thắng 4/4 Virut; D9 là diễn giải *nhóm
  quy tắc*, không phải ngoại lệ theo tên cơ chế. Dẫn bằng chứng A1–A4:
  A1: `http_header_case` evaded 16/16 C2 cũ (báo cáo qbar v6), qpp 4/4 Virut
  (`p13_v9_query_prepend.json`); A2: qpp pass D5 4/4 trên flow nó evade,
  `http_header_case` pass D5 16/16; A3: control noop alert 100% (`p13_v7_noop.json`,
  `control_noop_real_snort.json`); A4: không giảm `split8`/`split_slow` — mech mới
  chỉ append, không sửa nhánh split nào (sẽ có test ở T1.5).
- **D10 (costs).** `ACTION_COSTS[15] = 0.05` (`http_header_case`, Δwire = 0 B),
  `ACTION_COSTS[16] = 0.05` (`query_param_prepend`, +4–8 B/flow). Neo theo wire cost
  ĐÃ ĐO trong `docs/p14_results.md` / `docs/p14_cost_headroom.md`; cùng bậc với
  `http_header_pad` (0.05), dưới mọi split (0.40–0.65). **Cam kết anti-reward-hacking:
  không chỉnh lại cost sau khi thấy kết quả train**; nếu policy vẫn collapse lên
  split thì đó là finding, báo cáo trung thực.
- `PROTOCOL_APPROPRIATE["http"] += ("http_header_case", "query_param_prepend")` —
  bonus chống collapse có sẵn, gated trên valid-evasion, không tạo evasion mới.

### T0.2 — Verify + commit

```bash
cd /root/.hermes/c2-evasion-rl
wc -l docs/action_space_policy_p15.md      # kỳ vọng: file tồn tại, > 40 dòng
git add docs/action_space_policy_p15.md
git commit -m "docs(P15.0): freeze D8-D10 (reward gate, bar-group admission, costs)"
git log --oneline -1                        # kỳ vọng: hash mới, message trên
```

---

## Phase 1 — Env action space (TDD)

### T1.1 — RED: `tests/test_post_p14_actions.py`

Fixture flow copy pattern từ `tests/test_query_param_prepend.py:26` (`_flow(load=REQ)`,
REQ là GET `/list.php?c=...&v=...` thật của Virut). Flow dict cho env cần đủ khóa
`flow_id, packets, framing, obs (list 8 số 0.0), key, replica` — xem thêm cách
`tests/test_policy_diversity.py` dựng flow cho env (nếu có) và bắt chước đúng khóa
mà `load_corpus` trả ra (đã recon: `['capture','dataset','extra_sids','flow_id',
'framing','key','obs','packets','replica']`).

```python
"""P15.1: post-P14 action space -- http_header_case (15) + query_param_prepend (16)."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "snort_validation"), str(ROOT / "ai_agent")]

from scapy.all import Ether, IP, TCP, Raw  # noqa: E402
import hidden_defender_env as hde  # noqa: E402

CIP = "147.32.84.165"
REQ = (b"GET /list.php?c=" + b"A1" * 50 + b"&v=2&t=0.89 HTTP/1.0\r\n"
       b"User-Agent: Mozilla/4.0\r\nHost: mewgost.com\r\n\r\n")


def _pkts(load=REQ, src=CIP):
    return [Ether() / IP(src=src, dst="8.8.8.8")
            / TCP(sport=1024, dport=80, flags="PA") / Raw(load=load)]


def test_action_names_extended():
    assert hde.ACTION_NAMES[15] == "http_header_case"
    assert hde.ACTION_NAMES[16] == "query_param_prepend"
    assert hde.N_ACTIONS == 17
    # idx cũ bất biến (model cũ không load được là chấp nhận, idx không được xê dịch)
    assert hde.ACTION_NAMES[:15] == [
        "split8", "split16", "split24", "prepend4", "prepend8", "prepend12",
        "pad16", "reorder", "ttl", "corrupt8", "overlap8", "noop",
        "http_header_pad", "length_wrapper", "split_slow"]


def test_costs_per_d10():
    assert hde.ACTION_COSTS[15] == 0.05
    assert hde.ACTION_COSTS[16] == 0.05


def test_mech_applicable_qpp_needs_http_and_query():
    assert hde.mech_applicable([REQ], "query_param_prepend") is True
    assert hde.mech_applicable([b"GET /plain HTTP/1.0\r\n\r\n"],
                               "query_param_prepend") is False
    assert hde.mech_applicable([b"\x01J\x01\x00dns"], "query_param_prepend") is False
    assert hde.mech_applicable([REQ], "http_header_case") is True
    assert hde.mech_applicable([b"\x01J\x01\x00dns"], "http_header_case") is False


def test_protocol_appropriate_http_includes_new_mechs():
    assert "http_header_case" in hde.PROTOCOL_APPROPRIATE["http"]
    assert "query_param_prepend" in hde.PROTOCOL_APPROPRIATE["http"]
```

Thêm 1 test mask: dựng env tối thiểu (constructor `HiddenDefenderEnv(split=...,
corpus=...)` cần pickle đúng format — cách rẻ nhất: tạo dict `{"train": [...],
"test": [...]}` với flow giả đầy đủ 9 khóa, dump ra `/tmp/p15_corpus.pkl`, khởi động
env với `corpus="/tmp/p15_corpus.pkl", split="test"`, `real_snort=False`, rồi gọi
hàm mask). Kỳ vọng: flow http có `?` → `mask[15]==mask[16]==1`; flow framing
`"neris"` → cả hai == 0; flow http KHÔNG có `?` → `mask[16]==0`, `mask[15]==1`.

Chạy RED:

```bash
.venv/bin/python -m pytest tests/test_post_p14_actions.py -q
# kỳ vọng: FAIL — IndexError/assert N_ACTIONS==15 != 17
```

### T1.2 — GREEN: sửa `ai_agent/hidden_defender_env.py`

1. `ACTION_NAMES` (dòng ~87): append `"http_header_case", "query_param_prepend"`
   vào CUỐI (giữ comment giải thích P15/D9).
2. `ACTION_COSTS`: thêm
   ```python
   15: 0.05,    # http_header_case (0 wire bytes; D10)
   16: 0.05,    # query_param_prepend (+4..8 bytes, no fragments; D10)
   ```
3. `PROTOCOL_APPROPRIATE["http"]`: thêm `"http_header_case", "query_param_prepend"`.
4. `mech_applicable` (~dòng 183): thêm nhánh TRƯỚC `return True`:
   ```python
   if mech == "query_param_prepend":
       return framing == "http" and any(b"?" in p for p in original_payloads)
   ```
5. Mask (~dòng 583–605): trong khối `if framing != "http":` thêm
   `mask[15] = 0; mask[16] = 0`; sau đó thêm khối mới:
   ```python
   # query_param_prepend needs a '?' in an owned payload (mirrors mech_applicable)
   if not any(b"?" in p for p in self._owned_payloads(flow)):
       mask[16] = 0
   ```
6. Cập nhật docstring mask (liệt kê rule 15/16) — không đổi logic cũ.

Chạy GREEN:

```bash
.venv/bin/python -m pytest tests/test_post_p14_actions.py -q   # kỳ vọng: all passed
```

Commit: `feat(P15.1): action space 17 -- http_header_case + query_param_prepend (D9/D10)`
(dùng `-F /tmp/msg.txt` nếu message có backtick).

### T1.3 — RED: `tests/test_reward_semantic_gate.py`

Ba nhóm assert:

1. **Relaxed đúng chỗ:** flow `_pkts(REQ)`; `mut = hde.apply_mech(pkts,
   "query_param_prepend", CIP)`; gọi hàm mới
   `c2_semantics.semantics_ok_reward(pkts, mut, CIP)` → `True` (D7∧D5 pass dù byte
   khác); `bytes_equal_semantics(pkts, mut, CIP)` → `False` (chứng minh nhánh OR hoạt
   động, không phải byte bar trùng lặp).
2. **Không rò cho mech phá ngữ nghĩa:** `mut2 = hde.apply_mech(pkts, "corrupt8", CIP)`
   → `semantics_ok_reward(...) is False`.
3. **Fail-closed ngoài HTTP:** payload DNS giả (`b"\x01J\x01\x00..."`), mech
   `query_param_prepend` là no-op trên payload không HTTP → nếu byte không đổi thì
   `bytes_equal` True (không sao); nhưng với mutation giả đổi byte payload DNS thì
   `semantics_ok_reward is False` (D7/D5 fail-closed). Dựng mutation bằng
   `apply_mech(pkts_dns, "pad16", CIP)`.
4. **Env-level:** dựng env với corpus `/tmp` như T1.1 (replica giả: object có
   `.verdict(pkts) -> False` để mô phỏng "đã evade"), `env.step(16)` →
   `reward == pytest.approx(10.0 - 0.05 + 0.15)` và `info["semantics_ok"] is True`,
   `info["semantics_bytes"] is False`.

Chạy RED:

```bash
.venv/bin/python -m pytest tests/test_reward_semantic_gate.py -q
# kỳ vọng: FAIL — AttributeError: no semantics_ok_reward; env step reward ≈ -10+...
```

### T1.4 — GREEN: `semantics_ok_reward` + nối vào env

Thêm vào `snort_validation/c2_semantics.py` (cuối file, cạnh các hàm bar):

```python
def semantics_ok_reward(original_packets: Sequence, mutated_packets: Sequence,
                        client_ip: Optional[str] = None) -> bool:
    """D8 (docs/action_space_policy_p15.md): training-reward semantics gate.

    byte-bar OR (D7 AND D5).  Uniform across mechanisms -- no per-mech
    special-casing.  D7/D5 are HTTP-only and fail-closed, so non-HTTP flows
    fall back to the byte bar exactly as before.
    """
    if bytes_equal_semantics(original_packets, mutated_packets, client_ip):
        return True
    return (endpoint_commands_preserved(original_packets, mutated_packets, client_ip)
            and endpoint_query_preserved(original_packets, mutated_packets, client_ip))
```

**Trước khi viết, verify chữ ký thật của 3 hàm** (đã recon vị trí dòng, chưa recon
tham số):

```bash
sed -n '437,440p;516,520p;560,564p' snort_validation/c2_semantics.py
# kỳ vọng: cả ba nhận (original_packets, mutated_packets, client_ip=...) — nếu khác,
# adapt lời gọi, KHÔNG đổi chữ ký hàm cũ.
```

Sửa `hidden_defender_env.py`:

- Import: `from c2_semantics import semantics_ok_reward` (cạnh import
  `bytes_equal_semantics` hiện có — grep `from c2_semantics` để thấy chỗ).
- `score()` (~dòng 528–541): thay `sem = semantics_intact(pkts, mut, cip)` bằng
  ```python
  sem_bytes = semantics_intact(pkts, mut, cip)
  sem = semantics_ok_reward(pkts, mut, cip)          # D8
  ```
  và trả `(not alert), sem, alert, sem_bytes` — **đổi tuple 3→4**: sửa mọi call-site
  của `score()` (`grep -n "\.score(" ai_agent/ tests/` — có `step()` và có thể test
  cũ; sửa hết trong commit này).
- `step()`: `info` thêm `"semantics_bytes": sem_bytes`; `info["semantics_ok"]` giữ
  nghĩa mới (D8). Các nhánh reward giữ nguyên cấu trúc (giờ `sem` là gate D8).
- Hàm `semantics_intact` GIỮ NGUYÊN (vẫn là byte bar, eval cũ dùng).

Test cũ có thể encode gate byte (ví dụ test reward của `http_header_pad`): chạy

```bash
.venv/bin/python -m pytest tests/test_post_p14_actions.py tests/test_reward_semantic_gate.py \
  tests/test_policy_diversity.py tests/test_overlap_policy_gap.py -q
# kỳ vọng GREEN; nếu test cũ fail vì semantics_ok đổi nghĩa: đọc kỹ test đó — chỉ sửa
# test khi nó assert gate byte cho mech P14, và ghi lý do (D8) vào commit; KHÔNG sửa
# test để che regression thật.
```

Commit: `feat(P15.2): reward gate = byte OR (D7 AND D5) per frozen D8`.

### T1.5 — Byte-identity env↔eval + A4 regression (test)

Thêm vào `tests/test_post_p14_actions.py`:

```python
def test_env_apply_mech_byte_identical_to_eval_pipeline():
    from eval_pipeline import mutate_client_only, client_ip_of
    pkts = _pkts()
    fid = f"cap|{CIP}:1024->8.8.8.8:80|tcp"
    for mech in ("http_header_case", "query_param_prepend"):
        a = hde.apply_mech(pkts, mech, client_ip_of(fid))
        b = mutate_client_only(pkts, mech, client_ip_of(fid))
        ba = b"".join(bytes(p[Raw].load) for p in a if Raw in p)
        bb = b"".join(bytes(p[Raw].load) for p in b if Raw in p)
        assert ba == bb, mech


def test_split_paths_untouched_a4():
    # A4: mech mới không đổi hành vi split8 trên flow HTTP mẫu
    pkts = _pkts()
    m = hde.apply_mech(pkts, "split8", CIP)
    assert len(m) > len(pkts)          # split8 vẫn phân mảnh
    # bytes reassembled bất biến so với hành vi trước P15 (snapshot trong test)
```

```bash
.venv/bin/python -m pytest tests/test_post_p14_actions.py tests/test_reward_semantic_gate.py -q
# kỳ vọng: all passed
git add -A && git commit -m "test(P15.3): byte-identity env<->eval + A4 split regression"
```

### T1.6 — Regression full (chạy nền)

```bash
# background=true, KHÔNG notify-string; chờ bằng process_manage wait
.venv/bin/python -m pytest tests/ -q --ignore=tests/archive
# kỳ vọng: >= 331 passed (+ test mới), 1 skipped; 3 archive-fail cũ không tính
```

Nếu fail: sửa trong Phase 1, không sang Phase 2 khi chưa xanh.

---

## Phase 2 — Train 3 seed (corpus cũ, surrogate replica)

### T2.1 — Xác nhận CLI train lần cuối (không đoán tham số)

```bash
grep -n "n_flows\|max_epochs\|total_timesteps\|learning_rate" ai_agent/train_hidden_defender_ppo.py | head
head -3 snort_validation/reports/learning_curves_v2.csv
# kỳ vọng thấy 64 queries/epoch; chọn --n-flows 64 --max-epochs 30 theo precedent v2
# (23 epoch đã hội tụ 90.6%). Nếu script không có cờ --n-flows ảnh hưởng queries/epoch
# thì dùng default và ghi wall-time thực vào docs/p15_train_results.md.
```

### T2.2 — Train (tuần tự, foreground timeout 600 hoặc background + wait)

```bash
for S in 42 7 1337; do
  .venv/bin/python ai_agent/train_hidden_defender_ppo.py \
    --split train --seed $S --n-flows 64 --max-epochs 30 \
    --model-out models/ppo_post_p14_s$S.zip \
    --out snort_validation/reports/train_post_p14_s$S.json
done
```

Verify mỗi seed: `echo $?` == 0; `ls -la models/ppo_post_p14_s*.zip` đủ 3 file;
`jq .snort_validation/reports/train_post_p14_s42.json` đọc được (scorer == "replica").

### T2.3 — Sanity phân bố mech (KHÔNG gate, chỉ quan sát)

```bash
.venv/bin/python - <<'EOF'
import json
for s in (42, 7, 1337):
    d = json.load(open(f"snort_validation/reports/train_post_p14_s{s}.json"))
    print(s, {k: d.get(k) for k in ("actions_used", "mechs", "final_valid") if k in d})
EOF
```

Kỳ vọng *mong muốn*: idx 15/16 xuất hiện trên flow http. Nếu policy vẫn collapse lên
split → **ghi nhận là finding** (D10 cấm chỉnh cost hậu nghiệm); không tune reward.

Commit: `chore(P15.4): train 3 seeds post-P14 action space (surrogate)` (models/*.zip —
kiểm tra `.gitignore` trước: `git check-ignore models/ppo_post_p14_s42.zip`; nếu bị
ignore thì chỉ commit reports JSON).

---

## Phase 3 — Eval Snort thật + so chi phí (số liệu headline)

### T3.1 — Eval từng seed (background + process_manage wait; ~15–20 phút/seed, conf 21k)

```bash
.venv/bin/python ai_agent/eval_masked_ppo_test.py \
  --model models/ppo_post_p14_s42.zip --split test --real-snort \
  --out snort_validation/reports/ppo_post_p14_s42_test.json
# lặp cho s7, s1337 — TUẦN TỰ (Snort không chạy song song trên máy 4 nhân)
```

Verify: JSON có `scorer: "real_snort"`, `n_flows: 40`.

### T3.2 — Backfill bar ngữ nghĩa (in-memory, không cần Snort)

```bash
for S in 42 7 1337; do
  .venv/bin/python controls/backfill_endpoint_bar.py \
    snort_validation/reports/ppo_post_p14_s${S}_test.json \
    --corpus snort_validation/reports/hidden_defender_corpus.pkl --split test \
    --out snort_validation/reports/ppo_post_p14_s${S}_test_qbar.json
done
```

### T3.3 — Verdict table → `docs/p15_train_results.md`

Mỗi seed một dòng, TRÊN MẪU SỐ D4 (16 flow C2 — danh sách flow-id lấy từ
`docs/p14_denominator.md`, không tự lọc lại):

- alerted / valid_evasion (byte) / endpoint v1 / D7 / D5;
- phân bố mech đã dùng (đếm từ cells);
- **tổng wire cost** của policy (Σ bytes thêm) so với fixed `http_header_case` và
  fixed `split8`/`split24` trên cùng 16 flow (số fixed lấy từ report đã commit:
  `ceiling_v6_case_fullrules_qbar.json`, `p14_v10_qpp_old_corpus.json` — KHÔNG chạy
  lại Snort cho baseline);
- A4 check: `split8`/`split_slow` coverage không thấp hơn `ppo_masked_test.json` cũ.
  → **ĐÍNH CHÍNH 2026-10-13 (T0.4, P16b.0):** baseline đó là **both-ownership +
  relaxed bar** (sinh tại `e6fb02d`, trước `40fffdf` — xem
  `docs/baseline_ownership_provenance.md`). A4 đúng phải so với
  `oracle_split8_test.json` = **23/40 client-only** (http 16/16, neris 7/24),
  cùng pipeline client-only + strict bar với policy P15.

Câu hỏi RL mà bảng này trả lời (viết nguyên văn vào doc): *policy học được có đạt
≥ coverage của fixed mech tốt nhất với ≤ wire cost, bằng action không-split, trên
Snort thật?* Trả lời CÓ/KHÔNG kèm số, cả 3 seed, không chọn seed đẹp nhất.

### T3.4 — Verifier + commit

```bash
.venv/bin/python controls/verify_report_claims.py   # kỳ vọng: pass all (>=109)
git add docs/p15_train_results.md snort_validation/reports/ppo_post_p14_*
git commit -m "docs(P15.5): real-Snort eval of post-P14 trained policies (3 seeds)"
```

---

## Phase 4 (STRETCH — chỉ chạy khi Phase 3 xanh và user đồng ý) — corpus mở rộng

### T4.1 — `controls/attach_replica_extended.py` (script mới, pattern `merge_corpora.py`)

- Load `corpus_p13_extended.pkl`; join `flow_id → baseline_sids` từ
  `snort_validation/reports/p13_v7_noop.json` (cells đã có sẵn `baseline_sids`).
- `flow["replica"] = RealRulesReplica.for_sids(set(sids),
  path=ROOT/"rulesets/p13/et_open_3000.rules")` — **verify `for_sids` nhận `path`**
  (đã recon: `real_rules_replica.py:298 for_sids(cls, sids, path=RULES)` → OK).
- Sửa framing bằng logic y hệt `merge_corpora.corrected_framing` (udp/53 → `"dns"`);
  **import hàm đó thay vì chép** (DRY): `from merge_corpora import corrected_framing`
  (thêm `sys.path` — hoặc nếu import vòng thì chép 4 dòng kèm comment trỏ nguồn).
- Loại khỏi tập train: flow không `baseline_alert` (5 flow) và flow SID-only ngoài
  mẫu D4 (scan `2001219`/`2003068`, sinkhole `2016413`, policy-violation) — đọc
  classtype từ `docs/p14_denominator.md`, hard-code danh sách SID loại kèm citation
  dòng trong script.
- Ghi `snort_validation/reports/corpus_p13_extended_rl.pkl` (KHÔNG ghi đè input).
- Verify: script in số flow train/test, số replica attached, số flow bị loại theo
  từng lý do; `replica is None` chỉ còn ở flow đã loại.
- **Caveat ghi vào docstring:** replica chỉ mô hình content-match; `2012533` có pcre
  trên giá trị `c=` → surrogate có thể lệch Snort thật; train bằng surrogate,
  kết luận bằng Snort thật (hai bộ chấm điểm). Nếu `parse_ruleset` raise với SID
  nào: ghi log SID đó, loại flow tương ứng khỏi train, báo cáo số lượng.

### T4.2 — Train 1 seed trên corpus mở rộng

```bash
.venv/bin/python ai_agent/train_hidden_defender_ppo.py \
  --split train --seed 42 --corpus snort_validation/reports/corpus_p13_extended_rl.pkl \
  --n-flows 64 --max-epochs 30 \
  --model-out models/ppo_post_p14_ext_s42.zip \
  --out snort_validation/reports/train_post_p14_ext_s42.json
```

### T4.3 — Eval Snort thật conf 52k trên mẫu D4 (cần plumb `--conf`)

- Env hard-code `SnortBatchService(batch_size=1)` (dòng ~508) với conf default 21k
  (`snort_batch_service.py:75`). TDD nhỏ: test `HiddenDefenderEnv(..., conf=Path(...))`
  truyền vào service; sửa ctor env + `eval_masked_ppo_test.py` thêm cờ `--conf`.
- **Chi phí:** conf 52k ~70s/flow → chỉ eval trên flow mẫu D4 của corpus mở rộng
  (4 Virut + sogou + các flow C2 classtype, đếm trước bằng script; nếu > 20 flow thì
  hỏi user trước khi đốt ~25 phút Snort).
- Chạy background + `process_manage wait`.

### T4.4 — Kết quả: policy có chọn `query_param_prepend` trên Virut?

Bảng: per-flow mech đã chọn, D5 pass, wire bytes — so với fixed `split8` (+1224 B
toàn cục). Đây là hiện thực hóa RL của claim transfer P14.6. Ghi vào
`docs/p15_train_results.md` (mục Phase 4), commit.

---

## Phase 5 — Đóng sổ

- T5.1 Append verdict mới vào `docs/rl_substantive_claim.md` (append-only, giữ
  verdict cũ).
- T5.2 Nếu phát hiện bẫy đo mới → `skill_manage patch` vào
  `c2-evasion-rl/references/scoring-pitfalls.md` (mục 5+).
- T5.3 Regression full lần cuối (background) + `verify_report_claims.py`; commit
  `docs(P15.6): closeout`.
- Ngoài phạm vi plan này (follow-up riêng): cập nhật chương thesis P13/P14/P15,
  paper draft.

## Tests / validation (tóm tắt chu kỳ)

Mỗi task code = RED (chạy pytest, thấy fail đúng chỗ) → implement tối thiểu → GREEN
→ commit ngay. Không batch nhiều task mới commit. Lệnh verify + output kỳ vọng nằm
trong từng task. Full-suite chỉ chạy nền giữa các phase.

## Risks, tradeoffs, open questions

1. **D8/D9 là điểm nhạy cảm khoa học** (nới gate reward + diễn giải A2). Giảm thiểu:
   freeze trong file dated mới TRƯỚC code; gate mới = đúng D7∧D5 đã citation-gate;
   áp đồng nhất mọi mech (test T1.3.2 chứng minh không rò); bar byte vẫn báo cáo mọi
   nơi. Luận điểm phòng vệ: "reward không được chặt hơn định nghĩa hợp lệ headline".
2. **Model cũ incompat:** Discrete(15)→(17), 5 zip trong `models/` không eval được
   nữa trên env mới. Chấp nhận (train mới là mục tiêu); KHÔNG thêm version-switch.
3. **Collapse vẫn có thể xảy ra** (P4 cũ: data-capped). Nếu 3 seed không dùng idx
   15/16 → finding trung thực "cost gradient không đủ phá collapse trên corpus cũ",
   không tune lại D10.
4. **Surrogate lệch Snort thật** (pcre của 2012533) → mọi kết luận lấy từ Phase 3/4.3
   (Snort thật); surrogate chỉ để train.
5. **Wall-time:** Phase 3 ~45–60 phút Snort (3 seed × 40 flow × 21k); Phase 4.3 có
   thể ~25 phút (52k). Nền tảng: background=true + process_manage wait; không nohup;
   không notify-string.
6. **Open question cho user (hỏi trước Phase 4):** corpus mở rộng có vào scope lần
   train này không, hay dừng ở Phase 3 rồi quyết? (Phase 4 cần script mới + plumb
   `--conf` + ~25 phút Snort 52k.)
7. **`framing_features` one-hot chỉ có ("http","neris")** — flow `'dns'` sau T4.1 sẽ
   có one-hot [0,0]: chấp nhận được (mask chặn mech HTTP), ghi chú vào T4.1, không
   mở rộng OBS_DIM (YAGNI — corpus mở rộng sau lọc D4 gần như toàn http).
