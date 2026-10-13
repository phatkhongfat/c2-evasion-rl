# Plan: Nâng trần đánh giá — mô hình sở hữu hai phía (two-sided ownership)

## Goal

Nâng trần evasion hợp lệ (`valid_evasion`) trên eval trung thực (`eval_fixed_pipeline.py`, Snort thật, byte-equality bar) bằng cách mở rộng threat model: cho phép cơ chế sửa packet của **CẢ HAI đầu C2** (client implant + server C2), đo trần mới bằng sweep, rồi (nếu trần mới > 57,5%) train policy đạt tới nó — mọi con số gắn nhãn mô hình sở hữu.

## Current context / assumptions

Repo: `/root/.hermes/c2-evasion-rl`, python `.venv/bin/python`, test suite `tests/` (baseline 101 test, chưa tính test mới).

Sự thật đã kiểm chứng (không cần làm lại):

- **Trần mô hình hiện tại (ownership=`client`, mặc định) = 57,5% (23/40 test flows).** Cứng theo cấu trúc: 17/24 flow neris có packet ĐẦU TIÊN do peer gửi mang signature ET P2P BitTorrent DHT (sid 2008581/83/85, `HOME_NET=any`); alert bắn trên packet của peer mà attacker không sở hữu → không cơ chế phía client nào diệt được. Sweep 170 ô split-offset bất biến (commit `26eb4e3`).
- **Trần này ĐÃ ĐẠT ĐƯỢC bằng model train:** `models/ppo_rs64_s42.zip` (seed 42, 40 epoch, real-Snort teacher) eval = **57,5%, `actions={split8: 40}`, sem_breaks=0** → `snort_validation/reports/ppo_masked_test_RS64_s42.json`. Hai seed kia (s7, s1337 @ 20 epoch) dừng ở 40,0% → bài học: 20 epoch chưa đủ (under-trained), 40 epoch mới hội tụ.
- Pre-fix code (`git show 2dce9c2~1:ai_agent/hidden_defender_env.py`) áp cơ chế cho TOÀN BỘ packet hai chiều → cùng split8 từng cho 100% (40/40). Tức là side-channel còn lại để nâng trần = **mở quyền sở hữu packet phía server**.
- Bar hiện tại `c2_semantics.bytes_equal_semantics` chỉ so **client stream**. Khi mutation được mở sang phía server, bar PHẢI phủ cả hai stream, nếu không server bị sửa lung tung mà bar vẫn "ok" (chính lỗi bar lỏng cũ đã tạo số 9x%).

Giả định: trần 57,5% là đúng bản chất mô hình 1-chiều; mọi con số mới phải ghi rõ `ownership=client` hay `ownership=both`, không bao giờ thay thế số cũ.

## Architecture / proposed approach

Thêm tham số `ownership ∈ {"client","both"}` (mặc định `"client"`, không đổi hành vi hiện tại) đi xuyên: `apply_mech` (env, train) → `mutate_client_only` (eval) → `HiddenDefenderEnv` → CLI train/eval. Đồng thời siết bar thành **hai-stream byte-equality** (so cả client lẫn server stream — với ownership=client thì vế server luôn nguyên vẹn nên bar cũ và mới cho kết quả giống hệt nhau: backward-compatible). Sau đó sweep trần dưới `ownership=both`, báo cáo song song hai mô hình; chỉ train tiếp khi trần mới > 57,5%.

## Step-by-step tasks

### Phase 0 — Baseline (2 phút, read-only)

**T0.1** Chạy test suite, ghi lại baseline thật:

```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python -m pytest tests -q
```

Kỳ vọng tail: `101 passed in ...` (đúng = tổng `grep -c 'def test_' tests/*.py`). Nếu có fail từ đầu → DỪNG, báo lại, đừng tự sửa.

### Phase 1 — Bar hai-stream (TDD, ~10 phút)

**T1.1** Tạo file mới `tests/test_ownership_model.py`, viết 2 test FAIL đầu tiên:

```python
#!/usr/bin/env python3
"""Two-sided ownership model (attacker owns the C2 server too).

ownership="client" (default) = the conservative model, unchanged.
ownership="both" = a mechanism may rewrite BOTH endpoints' packets, and the
Fix-3 byte-equality bar then guards BOTH recovered streams.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path("/root/.hermes/c2-evasion-rl")
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))

from scapy.all import IP, Raw, TCP  # noqa: E402

from c2_semantics import bytes_equal_semantics  # noqa: E402
from eval_pipeline import mutate_client_only  # noqa: E402
from hidden_defender_env import apply_mech  # noqa: E402


def _bidirectional_flow():
    """client 10.0.0.1 <-> server 10.0.0.2, both sides carry payloads."""
    pkts = [
        IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=4444, flags="S"),
        IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=4444, dport=1234, flags="SA"),
        IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=4444, flags="A"),
        IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=4444, flags="PA")
        / Raw(load=b"C" * 200),
        IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=4444, dport=1234, flags="PA")
        / Raw(load=b"S" * 200),
    ]
    return pkts, "10.0.0.1", "10.0.0.2"


def test_bar_rejects_server_side_byte_change():
    """A 1-byte change on the SERVER stream must fail the bar even though the
    client stream is untouched (fails before Phase 1: bar is client-only)."""
    pkts, cip, sip = _bidirectional_flow()
    mut = [p.copy() for p in pkts]
    for p in mut:
        if IP in p and p[IP].src == sip and Raw in p:
            p[Raw].load = b"X" + bytes(p[Raw].load)[1:]
    assert bytes_equal_semantics(pkts, mut, cip) is False


def test_bar_accepts_fragmentation_of_server_stream():
    """Fragmentation preserves every byte, so fragmenting the server reply
    must still pass the bar (fails before Phase 1 for the same reason)."""
    from fragment_ops import fragment_plan_to_packets, split_fragments

    pkts, cip, sip = _bidirectional_flow()
    mut = []
    for idx, p in enumerate(pkts):
        if IP in p and p[IP].src == sip and Raw in p:
            frags = split_fragments(bytes(p[Raw].load), 8)
            mut.extend(fragment_plan_to_packets(pkts, frags, idx))
        else:
            mut.append(p)
    assert bytes_equal_semantics(pkts, mut, cip) is True
```

Chạy xác nhận FAIL (TDD đỏ):

```bash
.venv/bin/python -m pytest tests/test_ownership_model.py -q
```

Kỳ vọng (RED): `1 failed, 1 passed` — test 1 đỏ (bar cũ chỉ so client stream → trả `True`); test 2 lúc này pass "vô nghĩa" (cũng vì bar chưa so server) và chỉ có ý nghĩa kiểm tra sau Phase 1. Nếu lệch khỏi kỳ vọng này → ghi lại, vẫn tiếp Phase 1.

**T1.2** Sửa `snort_validation/c2_semantics.py` (3 chấm = code có sẵn, giữ nguyên):

1. Thêm hàm `server_ip_of` (chuyển nguyên văn từ `snort_validation/eval_pipeline.py` dòng 71–80):

```python
def server_ip_of(packets: Sequence, client_ip: str) -> Optional[str]:
    """The responder address: the other endpoint of the session."""
    from scapy.all import IP

    for p in packets:
        if IP in p and p[IP].src != client_ip:
            return p[IP].src
        if IP in p and p[IP].dst != client_ip:
            return p[IP].dst
    return None
```

2. Mở rộng `bytes_equal_semantics` (dòng 223–232 hiện tại) thành hai stream:

```python
def bytes_equal_semantics(original_packets: Sequence, mutated_packets: Sequence,
                          client_ip: str) -> bool:
    """True iff BOTH recovered streams are byte-for-byte identical (Fix 3).

    Client stream first, then the responder (server) stream.  Under the
    default ownership="client" model the server side is never mutated, so
    the second comparison is vacuous -- behavior for model A is unchanged.
    Under ownership="both" it is what stops a mechanism from silently
    rewriting the C2 server's bytes while the bar still says "ok".
    """
    if (reassembled_client_bytes(original_packets, client_ip)
            != reassembled_client_bytes(mutated_packets, client_ip)):
        return False
    sip = server_ip_of(original_packets, client_ip)
    if sip is None:
        return True
    return (reassembled_client_bytes(original_packets, sip)
            == reassembled_client_bytes(mutated_packets, sip))
```

3. `snort_validation/eval_pipeline.py`: xóa nguyên hàm `server_ip_of` (dòng 71–80), thay bằng import trong khối `from c2_semantics import (...)` (dòng 63–68): thêm `server_ip_of as server_ip_of,` (giữ tên public ở eval_pipeline vì test cũ import từ đó).

Chạy xác nhận PASS:

```bash
.venv/bin/python -m pytest tests/test_ownership_model.py tests/test_c2_semantics.py tests/test_evaluation_fixes.py -q
```

Kỳ vọng: `18 passed` không fail (11 + 5 + 2).

**T1.3** Commit:

```bash
git add snort_validation/c2_semantics.py snort_validation/eval_pipeline.py tests/test_ownership_model.py
git commit -m "fix(semantics): byte-equality bar guards BOTH streams (pre-req for two-sided ownership)"
```

### Phase 2 — Tham số `ownership` trong mutation (TDD, ~15 phút)

**T2.1** Thêm 4 test vào `tests/test_ownership_model.py` (FAIL trước khi implement — `TypeError`/`ValueError` vì chưa có kwarg):

```python
def test_apply_mech_client_default_leaves_server_intact():
    pkts, cip, sip = _bidirectional_flow()
    mut = apply_mech(pkts, "split8", cip)          # default ownership="client"
    for p in mut:
        if IP in p and p[IP].src == sip and Raw in p:
            assert bytes(p[Raw].load) == b"S" * 200


def test_apply_mech_both_mutates_server_but_bar_holds():
    pkts, cip, sip = _bidirectional_flow()
    mut = apply_mech(pkts, "split8", cip, ownership="both")
    srv_raw = [p for p in mut if IP in p and p[IP].src == sip and Raw in p]
    assert len(srv_raw) >= 2                       # 200-byte reply fragmented
    assert bytes_equal_semantics(pkts, mut, cip) is True


def test_mutate_client_only_both_mutates_server():
    pkts, cip, sip = _bidirectional_flow()
    mut = mutate_client_only(pkts, "split8", cip, ownership="both")
    srv_raw = [p for p in mut if IP in p and p[IP].src == sip and Raw in p]
    assert len(srv_raw) >= 2


def test_invalid_ownership_rejected():
    pkts, cip, _sip = _bidirectional_flow()
    with pytest.raises(ValueError):
        apply_mech(pkts, "split8", cip, ownership="peer")
    with pytest.raises(ValueError):
        mutate_client_only(pkts, "split8", cip, ownership="peer")
```

Chạy xác nhận FAIL:

```bash
.venv/bin/python -m pytest tests/test_ownership_model.py -q
```

Kỳ vọng: `4 failed, 2 passed` (hai test Phase 1 xanh, 4 mới đỏ).

**T2.2** Sửa `ai_agent/hidden_defender_env.py::apply_mech` (dòng 163+). Thay dấu 2 dòng đầu + khối `client_idx` hiện tại (dòng 179–185) thành:

```python
def apply_mech(pkts, mech: str, client_ip=None, ownership: str = "client"):
    """...giữ nguyên docstring hiện tại...plus:

    ``ownership="both"`` extends the mutation scope to BOTH endpoints'
    packets (two-sided model: the attacker also owns the C2 server).
    """
    if ownership not in ("client", "both"):
        raise ValueError(f"ownership must be 'client' or 'both', got {ownership!r}")
    out = [p.copy() for p in pkts]
    if client_ip is None:
        client_ip = client_ip_of_packets(out)
    if ownership == "both":
        client_idx = [i for i, p in enumerate(out) if IP in p]
    else:
        client_idx = [i for i, p in enumerate(out)
                      if IP in p and p[IP].src == client_ip]
    pay_idx = [i for i in client_idx
               if Raw in out[i] and len(bytes(out[i][Raw].load)) > 0]
```

Phần thân hàm (split/overlap/pad/.../reorder/ttl/noop, dùng `pay_idx` và `client_idx`) giữ NGUYÊN — chỉ ý nghĩa "owned set" thay đổi.

**T2.3** Sửa `snort_validation/eval_pipeline.py::mutate_client_only` (dòng 104+) theo đúng mẫu trên: thêm tham số `ownership: str = "client"`, validate ValueError, và thay khối dòng 119–127 thành:

```python
    out = [p.copy() for p in packets]
    if ownership not in ("client", "both"):
        raise ValueError(f"ownership must be 'client' or 'both', got {ownership!r}")
    if client_ip is None:
        ip_pkts = [p for p in out if IP in p]
        client_ip = ip_pkts[0][IP].src if ip_pkts else None
    if ownership == "both":
        client_idx = [i for i, p in enumerate(out) if IP in p]
    else:
        client_idx = [i for i, p in enumerate(out)
                      if IP in p and p[IP].src == client_ip]
    payload_idx = [i for i in client_idx
                   if Raw in out[i] and len(bytes(out[i][Raw].load)) > 0]
```

Cập nhật docstring hàm: dòng "The attacker owns the client side only..." → ghi rõ model A vs model B (ownership param). KHÔNG đổi tên hàm (test cũ import `mutate_client_only`).

Chạy PASS + toàn suite:

```bash
.venv/bin/python -m pytest tests/test_ownership_model.py -q          # 6 passed
.venv/bin/python -m pytest tests -q                                   # 107 passed (101 baseline + 6)
```

**T2.4** Commit:

```bash
git add ai_agent/hidden_defender_env.py snort_validation/eval_pipeline.py tests/test_ownership_model.py
git commit -m "feat(ownership): ownership param scopes mutation to client or both endpoints"
```

### Phase 3 — Nối `ownership` qua env + CLI (TDD, ~15 phút)

**T3.1** Thêm 2 test subprocess (kiểm flag có tồn tại) vào `tests/test_ownership_model.py`:

```python
def test_eval_cli_exposes_ownership_flag():
    r = subprocess.run(
        [sys.executable, str(REPO / "ai_agent" / "eval_fixed_pipeline.py"), "--help"],
        capture_output=True, text=True, timeout=180)
    assert "--ownership" in r.stdout


def test_train_cli_exposes_ownership_flag():
    r = subprocess.run(
        [sys.executable, str(REPO / "ai_agent" / "train_hidden_defender_ppo.py"), "--help"],
        capture_output=True, text=True, timeout=180)
    assert "--ownership" in r.stdout
```

Chạy → `2 failed` (flag chưa có).

**T3.2** Sửa 4 chỗ:

1. `ai_agent/hidden_defender_env.py::HiddenDefenderEnv.__init__` (dòng 342–344): thêm `ownership: str = "client"` vào signature; sau dòng `self.capture = capture` thêm:

```python
        if ownership not in ("client", "both"):
            raise ValueError(f"ownership must be 'client' or 'both', got {ownership!r}")
        self.ownership = ownership
```

2. `HiddenDefenderEnv.score` (dòng 380): `mut = apply_mech(pkts, mech, cip, ownership=self.ownership)`.

3. `ai_agent/eval_fixed_pipeline.py`:
   - sau `ap.add_argument("--limit", ...)` (dòng 53) thêm:
     ```python
     ap.add_argument("--ownership", choices=("client", "both"), default="client",
                     help="whose packets a mechanism may rewrite (threat model)")
     ```
   - dòng 61: `env = HiddenDefenderEnv(split=args.split, seed=42, real_snort=False, capture=args.capture, ownership=args.ownership)`
   - dòng 81 và 82: thêm `ownership=args.ownership` vào hai lệnh `score_flow_real(...)`.

4. `ai_agent/train_hidden_defender_ppo.py`:
   - `BatchEnv.__init__` (dòng 44–47): thêm tham số `ownership="client"` và truyền `ownership=ownership` vào `HiddenDefenderEnv(...)`; trong `main()` tìm lệnh gọi `BatchEnv(` và thêm `ownership=args.ownership`.
   - sau `ap.add_argument("--seed", ...)` (dòng 129) thêm:
     ```python
     ap.add_argument("--ownership", choices=("client", "both"), default="client")
     ```

5. `snort_validation/eval_pipeline.py::score_flow_real` (dòng 328): thêm `ownership: str = "client"` vào signature; dòng 347: `mut = mutate_client_only(orig, mech, client_ip, ownership=ownership)`.

Chạy PASS + toàn suite:

```bash
.venv/bin/python -m pytest tests/test_ownership_model.py -q          # 8 passed
.venv/bin/python -m pytest tests -q                                   # 109 passed
```

Smoke (không model, chỉ flag, ~2 phút, 1 flow):

```bash
.venv/bin/python ai_agent/eval_fixed_pipeline.py --model models/ppo_rs64_s42.zip \
  --split test --limit 1 --ownership both \
  --out /tmp/smoke_both.json --progress /tmp/smoke_both_progress.jsonl
```

Kỳ vọng: chạy hết (exit 0), JSON ghi ra, `baseline_alert=true` (baseline không phụ thuộc ownership).

**T3.3** Commit:

```bash
git add ai_agent/hidden_defender_env.py ai_agent/eval_fixed_pipeline.py \
        ai_agent/train_hidden_defender_ppo.py snort_validation/eval_pipeline.py \
        tests/test_ownership_model.py
git commit -m "feat(cli): ownership=client|both wired through env, train and eval CLIs"
```

### Phase 4 — Sweep trần dưới `ownership=both` (cổng ra quyết định, ~2 giờ chạy nền)

**T4.1** Tạo `controls/ownership_ceiling_sweep.py` (file mới, toàn bộ nội dung):

```python
#!/usr/bin/env python3
"""Ceiling sweep under the TWO-SIDED ownership model (ownership="both").

Scores every (action, test-flow) pair with real Snort where a mechanism may
rewrite BOTH endpoints' packets, under the two-stream byte-equality bar.
Writes per-cell rows + the per-framing best to a report JSON and prints the
ceiling.  Baseline (mech=None) is scored once per flow as a control.

Usage: .venv/bin/python controls/ownership_ceiling_sweep.py --split test
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ai_agent"))
sys.path.insert(0, str(ROOT / "snort_validation"))

from hidden_defender_env import ACTION_NAMES, HiddenDefenderEnv  # noqa: E402
from eval_pipeline import client_ip_of, score_flow_real  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", default="test")
    ap.add_argument("--out", default=str(
        ROOT / "snort_validation" / "reports" / "ceiling_ownership_both.json"))
    args = ap.parse_args()

    env = HiddenDefenderEnv(split=args.split, seed=42, real_snort=False)
    flows = env._flows
    rows, t0 = [], time.time()
    for fi, f in enumerate(flows):
        fid = f["flow_id"]
        cip = client_ip_of(fid)
        base = score_flow_real(f["packets"], cip, attempt_id=fi, mech=None)
        for mi, mech in enumerate(ACTION_NAMES):
            r = score_flow_real(f["packets"], cip,
                                attempt_id=1000 + fi * 100 + mi,
                                mech=mech, ownership="both")
            rows.append({"flow_id": fid, "framing": f.get("framing", "?"),
                         "mech": mech, "baseline_alert": base["alert"],
                         "evaded": r["evaded"], "semantics_ok": r["semantics_ok"],
                         "valid_evasion": r["valid_evasion"]})
        print(f"[{fi + 1}/{len(flows)}] {fid} done @ {time.time() - t0:.0f}s",
              flush=True)

    best: dict = {}
    for r in rows:
        k = (r["framing"], r["mech"])
        best[k] = best.get(k, 0) + (1 if r["valid_evasion"] else 0)
    per_framing: dict = {}
    for (fr, mech), n in best.items():
        if fr not in per_framing or n > per_framing[fr][1]:
            per_framing[fr] = (mech, n)
    ceiling = sum(n for _m, n in per_framing.values())
    n_by_framing = {fr: sum(1 for f in flows if f.get("framing") == fr)
                    for fr in per_framing}
    out = {"ownership": "both", "split": args.split, "scorer": "real_snort",
           "bar": "two_stream_byte_equality",
           "cells": rows,
           "best_per_framing": {fr: {"mech": m, "evaded": n,
                                     "flows": n_by_framing.get(fr, 0)}
                                for fr, (m, n) in per_framing.items()},
           "ceiling_valid_evasion": ceiling, "n_flows": len(flows),
           "wall_s": round(time.time() - t0, 1)}
    Path(args.out).write_text(json.dumps(out, indent=1))
    print(json.dumps({k: out[k] for k in
                      ("ceiling_valid_evasion", "n_flows", "best_per_framing")},
                     indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

**T4.2** Chạy nền (600 lượt Snort ≈ 1,5–2 giờ):

```bash
nohup .venv/bin/python controls/ownership_ceiling_sweep.py --split test \
  > /tmp/ceiling_both.log 2>&1 &
```

Theo dõi: `tail -f /tmp/ceiling_both.log` — mỗi dòng `[i/40] <flow_id> done @ <n>s`.

**T4.3** Khi xong, đọc kết quả:

```bash
.venv/bin/python -c "import json;d=json.load(open('snort_validation/reports/ceiling_ownership_both.json'));print(d['ceiling_valid_evasion'],'/',d['n_flows']);print(json.dumps(d['best_per_framing'],indent=1))"
```

**Cổng ra quyết định:**

- `ceiling_valid_evasion` **> 23** → mô hình `both` thật sự nâng trần → Phase 5. Kỳ vọng (bằng chứng pre-fix): `split8` cả hai phía → ~40/40.
- **≤ 23** → KHÔNG train. Ghi báo cáo "ownership=both không nâng trần" kèm bảng per-framing, commit JSON, dừng.
- Bất kỳ ô nào `baseline_alert=false` (baseline vốn 40/40) → pipeline hỏng, dừng, điều tra.

**T4.4** Commit số liệu:

```bash
git add snort_validation/reports/ceiling_ownership_both.json controls/ownership_ceiling_sweep.py
git commit -m "controls: two-sided ownership ceiling sweep (real Snort, two-stream bar)"
```

### Phase 5 — Đo + train dưới mô hình mới (gate từ T4.3)

**T5.1** Eval model trần hiện tại dưới mô hình `both` (tham chiếu, ~30–45 phút):

```bash
.venv/bin/python ai_agent/eval_fixed_pipeline.py \
  --model models/ppo_rs64_s42.zip --split test --ownership both \
  --out snort_validation/reports/ppo_masked_test_RS64_s42_BOTH.json \
  --progress snort_validation/reports/.eval_s42_both_progress.jsonl
```

Kỳ vọng: báo `valid_evasion_pct` (policy học theo mô hình `client` — có thể ≠ trần `both`; đây chỉ là tham chiếu, KHÔNG thay thế số 57,5%).

**T5.2** Train dưới `both` — 3 seed song song, 40 epoch (bài học từ Phase-0: 20 epoch under-trained):

```bash
cd /root/.hermes/c2-evasion-rl
nohup bash -c '.venv/bin/python ai_agent/train_hidden_defender_ppo.py --real-snort \
  --split train --n-flows 64 --max-epochs 40 --seed 7 --ownership both \
  --model-out models/ppo_rs64_s7_both.zip > /tmp/train_s7_both.log 2>&1' &
nohup bash -c '.venv/bin/python ai_agent/train_hidden_defender_ppo.py --real-snort \
  --split train --n-flows 64 --max-epochs 40 --seed 1337 --ownership both \
  --model-out models/ppo_rs64_s1337_both.zip > /tmp/train_s1337_both.log 2>&1' &
nohup bash -c '.venv/bin/python ai_agent/train_hidden_defender_ppo.py --real-snort \
  --split train --n-flows 64 --max-epochs 40 --seed 42 --ownership both \
  --model-out models/ppo_rs64_s42_both.zip > /tmp/train_s42_both.log 2>&1' &
```

(~7–8 giờ/run, 3 run song song trên 4 core; eval mỗi model sau khi train xong, y hệt lệnh T5.1 với `--model models/ppo_rs64_<seed>_both.zip`.)

**T5.3** Báo cáo cuối — tạo `docs/THREAT_MODEL.md`:

```markdown
# Threat models (ownership) — mọi con số phải gắn nhãn
- ownership=client (mặc định): attacker sở hữu endpoint client; peer packet bất khả xâm phạm.
  Trần chứng minh = 57,5% (23/40); model train đạt: ppo_rs64_s42 = 57,5%.
- ownership=both: attacker sở hữu cả C2 server (đúng với C2 thật — server nằm dưới quyền attacker).
  Trần sweep = <T4.3>; model train = <T5.2>.
- Cấm so sánh hai con số khác mô hình; bar byte-equality hai-stream áp dụng cho CẢ HAI.
```

Điền số từ T4.3/T5.2 vào, commit:

```bash
git add docs/THREAT_MODEL.md
git commit -m "docs: threat-model labels for client vs both ownership numbers"
```

## Tests / validation

- TDD từng phase: viết test đỏ → chạy xác nhận fail → sửa tối thiểu → chạy xanh → toàn suite → commit. Bộ kỳ vọng: Phase0 `101 passed`, sau Phase1 `103`, sau Phase2 `107`, sau Phase3 `109`.
- Toàn suite mỗi phase: `.venv/bin/python -m pytest tests -q`.
- Không phá vỡ mô hình cũ: `tests/test_evaluation_fixes.py::test_server_packets_are_never_mutated` phải xanh ở mọi lúc (default `client`).
- Số liệu: mọi eval/sweep chạy Snort THẬT, ghi JSON vào `snort_validation/reports/`, không đọc từ số cũ.

## Risks, tradeoffs, and open questions

- **Đổi threat model ≠ nâng kỹ thuật:** `ownership=both` hợp lý với C2 thật (attacker owns server), nhưng con số của nó KHÔNG so sánh được với 57,5%. Số cũ luôn giữ nguyên, số mới gắn nhãn (T5.3) — thiếu nhãn là đúng thứ từng tạo ra scam "9x%".
- **Bar hai-stream siết thêm:** dưới mô hình `client` không đổi kết quả (server không bị sửa → vế so sánh luôn true). Dưới `both`, cơ chế sửa thô bạo — corrupt/pad/prepend ở byte phía server — sẽ fail bar đúng bản chất.
- **`ttl`/`reorder` dưới `both`:** đổi IP TTL của cả peer → có thể làm Snort "không thấy" packet (evasion kiểu Ptacek-Newsham) nhưng packet cũng khó tới host thật; sweep sẽ đo, đừng mặc định tính là thắng.
- **Giữ tên `mutate_client_only`** dù param `both` — đổi tên phá test cũ; rename để sau (YAGNI).
- **Chi phí:** sweep ~2h, train 3×40epoch ~8h (4 core, đã dùng ~30% CPU). Chạy nền, không chặn.
- **Open question (hỏi user trước khi chạy T5.2):** có train tiếp dưới `both` không, hay dừng ở trần sweep + policy `client` 57,5%? Và số nào làm headline trong báo cáo/luận văn (khuyến nghị: headline = `client` 57,5%, `both` là scenario study).
