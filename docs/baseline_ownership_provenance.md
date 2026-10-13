# Provenance of the headline baselines: ownership + semantics bar (P16b.0)

Mọi so sánh "policy mới có tốt hơn baseline không" phải đọc file này trước.
Hai baseline headline **không cùng pipeline với code hiện tại**; chênh lệch là
do pipeline, không do model. Số liệu ở đây trích nguyên văn từ report đã commit
và từ `git show <commit>:<file>` — không có con số nào ước lượng.

## Bảng đối chiếu

| report | commit sinh | ngày | mutation ownership | bar semantics | headline |
|---|---|---|---|---|---:|
| `ppo_masked_test.json` | `e6fb02d` | 2026-10-04 | **both** (mọi packet có `Raw`) | **relaxed, per-packet** | **40/40** |
| `oracle_split8_test.json` | `a980cb4` (pipeline `fixed_6_fixes`) | 2026-10-06 | **client-only** | **strict**, byte-equality của client stream đã reassemble | **23/40** (http 16/16, neris 7/24) |
| code hiện tại | `40fffdf` → HEAD | 2026-10-05 → | client-only (default `ownership="client"`) | strict + gate D8 cho reward | — |

## Bằng chứng

**① `apply_mech` ở `e6fb02d` không có tham số ownership.**

```
$ git show e6fb02d:ai_agent/hidden_defender_env.py | grep -n "def apply_mech" -A 1
164:def apply_mech(pkts, mech: str):
```

Nhánh split lặp qua **mọi** packet có `Raw`, không lọc theo IP client:

```python
for p in out:
    if Raw in p:
        payload = bytes(p[Raw].load)
        ...fragment...
```

Client-only vào từ `40fffdf` (2026-10-05, *"fix(semantics): one strict
client-stream bar for training AND evaluation"*), **sau** ngày sinh
`ppo_masked_test.json` (2026-10-04).

**② Bar semantics ở `e6fb02d` cũng relaxed.** Docstring gốc của hàm:

> "Byte equality of the joined stream is the right bar for a protocol whose
> grammar we cannot model ... **But it is the WRONG bar for HTTP**, where a real
> server skips unknown headers ... So the bar is: for every packet whose
> ORIGINAL payload yields a command under the flow's framing, the mutated packet
> must yield the same command. **Packets that yield no command (responses,
> binary segments) impose no constraint.**"

Hai điểm nới lỏng so với bar hiện tại: (a) so **từng packet rời rạc**, không so
stream đã reassemble; (b) packet không parse được command thì **miễn trừ hoàn
toàn**.

**③ Client-only split8 thật = 23/40**, đọc trực tiếp:

```json
{"valid_evasion": 23, "n_flows": 40,
 "per_framing": {"http": {"n": 16, "valid_evasion": 16},
                 "neris": {"n": 24, "valid_evasion": 7}}}
```

## Hệ quả bắt buộc khi viết thesis

1. **Không được** so sánh policy client-only (P15/P16) với `40/40` của
   `ppo_masked_test.json`. Đó là so hai mô hình threat khác nhau.
2. **Baseline đúng cho mọi so sánh client-only là `oracle_split8_test.json` =
   23/40**, và per-framing: `http 16/16`, `neris 7/24`.
3. Khi **thay bar** (relaxed → strict) cũng phải đổi **baseline**: baseline của
   bar cũ không so được với policy đo bằng bar mới.
4. Chương Kết quả / Kết luận của thesis hiện trích `40/40` mà **không ghi
   ownership** → phải sửa thành có kèm provenance, hoặc thay bằng số client-only
   23/40 nếu muốn giữ pipeline hiện tại. **Việc này là blocker trước khi nộp**,
   không phải việc tùy chọn.
5. Report không có field `ownership` → với report cũ, ownership phải suy từ
   commit sinh ra nó. `e6fb02d` (4/10) = **both**, `40fffdf`+ (5/10+) = **client**.

## Việc nên làm (chưa làm — plan ghi ở Phase 0 T0.4/T0.6 của P16b)

- `eval_pipeline.py` **đã** ghi `ownership` vào report; bổ sung tương tự cho
  `ai_agent/eval_masked_ppo_test.py` (đang ghi `scorer` nhưng thiếu `ownership`)
  để lỗi này không tái diễn.
- `tests/test_eval_report_ownership_provenance.py`: test **fail-closed** — mọi
  report sinh sau commit `40fffdf` phải có field `ownership` nếu không thì fail,
  kèm allowlist các report cũ đã biết.

## Ghi chú: vì sao calibration `home_ip` (99356c0) bị revert

Cùng một kiểu lỗi: suy luận cơ chế **trước khi** đo. Commit `99356c0` cho replica
biết hướng rule (`$HOME_NET -> $EXTERNAL_NET`) để split-on-neris có tín hiệu.
Đo trên 2 client-only references (`reports/surrogate_calibration_p15.json`):

| phép so | trước | sau |
|---|---:|---:|
| noop vs `control_noop_real_snort.json` (thật alert 40/40) | 40/40 | **36/40** ❌ |
| split8 vs `oracle_split8_test.json` | 17/40 | **7/40** ❌ |

Nguyên nhân: `snort_validation/et_open_c2/snort_et_c2.conf:17-18` đặt
`var HOME_NET any` **và** `var EXTERNAL_NET any`, nên header
`$HOME_NET any -> $EXTERNAL_NET any` nở thành **any→any** — Snort thật match
content ở **cả hai chiều**. Lọc theo direction của rule text vì vậy sai với conf
này. Hành vi gọi replica đã revert về legacy (`home_ip=None`); tham số giữ lại
để làm bằng chứng.

Và `home_ip` vốn là **no-op trên đường train**: corpus pickle nhúng object `Rule`
tạo trước khi field `direction` tồn tại → `getattr` default `any` → 0/680 cell
đổi, retrain ra report byte-identical (`git diff d01f4da a275c42` rỗng).


## Cross-engine (Suricata)

`controls/cross_engine_check.py` (P4) tham chiếu hai file **KHÔNG tồn tại**
(`snort_validation/suricata.yaml`, `snort_validation/et_open_c2/suricata.rules` —
kiểm tra `ls`: No such file or directory, 2026-10-13), và
`snort_validation/reports/cross_engine_v2.json` có **5/5 cell = -1** (exception
bị `try/except` nuốt). Cách đếm alert của nó là `stdout.count("[**]")` — chưa
từng được kiểm chứng; Suricata ghi alert vào `fast.log`/`eve.json`.

**Kết luận: CHƯA từng có một verdict Suricata thật nào trong project. Không được
trích `cross_engine_v2.json` làm bằng chứng cross-engine.** Mọi tuyên bố Hướng 1
(reassembling engine) phải bắt đầu từ harness mới + test cách đếm alert (plan
P16b Phase 1, gate G1a).
