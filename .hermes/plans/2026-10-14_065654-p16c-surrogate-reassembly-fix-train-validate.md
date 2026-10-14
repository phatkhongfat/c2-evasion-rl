# P16c — Sửa surrogate (thêm stream reassembly), train thử, validate trên Suricata thật

**Ngày:** 2026-10-14
**Repo:** `/root/.hermes/c2-evasion-rl` · branch `packet-level-rl` · HEAD `ee7a87f`
**Interpreter:** luôn `.venv/bin/python` (py3.11). Đặt `workdir` = repo path cho mọi lệnh.

---

## Goal

Trong 3 giờ: chứng minh rằng `RealRulesReplica` có thể được sửa để khớp **100%** với
Suricata 7.0.3 trên 100 cell đã đo, dùng nó để train PPO, và validate policy đã train
bằng **engine Suricata thật** (không phải surrogate).

---

## Vì sao làm được trong 3 giờ — bằng chứng đã đo sẵn trong plan mode

Tôi đã chạy probe read-only (không sửa file repo, script tạm ở `/tmp/probe_*.py`).
Kết quả, **không phải suy luận**:

| phép đo | kết quả |
|---|---|
| Replica vs Suricata, 20 flow đóng băng × 5 mech | **76/100 (76%)** |
| Lệch tập trung ở đâu | `split24` 0/20 và `split8` 16/20 — **chỉ họ fragmentation** |
| 3 mech không phải fragmentation | `noop` 20/20, `http_header_case` 20/20, `query_param_prepend` 20/20 — **đã đúng** |
| **Root cause** | `Rule.fires()` (`snort_validation/real_rules_replica.py:152-170`) lặp `for payload in payloads:` — khớp content **trong một packet**. Suricata reassemble stream TCP trước. |
| **Fix thử nghiệm** | nối arm thành một buffer liên tục → **100/100, 0 cell vỡ** |
| Fix có chạy ở legacy mode (`home_ip=None`, đúng cách env gọi)? | **Có** — 100/100 ở cả hai mode |
| Fix có tổng quát ra ngoài mẫu 20 flow? | 5 Virut-like held-out: verdict `split8` đổi 5/5; `noop` vẫn detect 40/40 FakeAV + 5/5 Virut → **không tạo né giả** |
| Engine cost | **25,66 s/cell** (đo lại khi đã dừng daemon, `suricata_g1c_recheck_no_daemon.json`) |
| Validate 20 flow × **1 mech** (action policy chọn) | 20 cell = **8,6 phút** |
| Validate 20 flow × 5 mech (bảng oracle đầy đủ) | 100 cell = **42,8 phút** |
| Obs phân biệt được 2 nhóm? | FakeAV 16 vector distinct / Virut 3 / **overlap 0** → per-flow selection biểu diễn được |

**Kết luận khả thi: có.** Fix là ~15 dòng. Phần tốn thời gian là train + validate.

---

## Ràng buộc (không được phá)

1. **Không sửa nội dung rule.** `snort_validation/et_open_c2/suricata.rules` giữ nguyên 21288 rule + 86 comment-out.
2. **Không hạ bar, không thêm action chỉ để mở headroom.**
3. **Chỉ sửa surrogate, không sửa engine, không sửa corpus, không đổi threat model.**
4. Mọi số báo cáo **phải in đúng nhãn**: `verdict()` trả `True = DETECTED`.
   `evaded = NOT verdict(...)`. Đảo nhãn này đã làm tôi ra số 5% thay vì 76% trong lúc plan mode.
5. Suricata daemon của hệ thống **đang dừng** (`systemctl stop suricata` đã chạy). Không được bật lại.
   Nếu nó tự bật (reboot), probe của ta tự chạy vẫn OK vì logdir riêng, nhưng ghi vào doc.
6. **Fail-closed**: mọi script so sánh engine phải `raise` khi engine lỗi, không ghi `-1`.
7. Surrogate dùng cho train; **Suricata thật dùng cho validate**. Không dùng Suricata trong vòng lặp train
   (25,66 s/cell × 1920 query = 13,7 h/seed — vượt ngân sách).

---

## Step-by-step

### Task 0 — Đóng băng ground truth trước khi sửa code

Ground truth Suricata **đã có sẵn trong git** (`suricata_g1b_fakeav.json`,
`suricata_g1b_virut.json`). Viết một loader + một script so sánh **fail-closed** để dùng lại
ở Task 1, Task 5.

**Tạo `controls/suricate_groundtruth.py`** — đúng tên: `controls/suricata_groundtruth.py`:

```python
"""Frozen Suricata 7.0.3 ground truth for the 20 frozen HTTP-D4 flows.

READ-ONLY loader. The verdicts come from committed engine runs; this module must
never run an engine. Fail-closed: an unknown flow/mech raises instead of
defaulting, so a typo cannot silently produce a "0 disagreements" table.
"""
from __future__ import annotations

import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "snort_validation/reports/p16b_http_d4_sample.json"
REPORTS = ("suricata_g1b_fakeav.json", "suricata_g1b_virut.json")

_LABELS = {
    "noop": ("noop", 0),  # documented below; filled in by load_ground_truth
}


def frozen_flow_ids() -> list[str]:
    """The 20 flow ids, in the order they were frozen (16 FakeAV then 4 Virut)."""
    smp = json.loads(SAMPLE.read_text())
    fids = list(smp["fakeav_flows"]) + list(smp["virut_flows"])
    assert len(fids) == smp["n"] == 20, "frozen sample changed -- re-freeze first"
    return fids


def load_ground_truth() -> dict[tuple[str, str], dict]:
    """(mech, flow_id) -> {"evaded": bool, "alerts": int, "sids": list}.

    ``evaded`` is copied verbatim from the committed report cell, where
    ``evaded = (n_alerts == 0)`` (decision 58). Do NOT recompute it from
    ``alerts``: the two fields are stored separately and a mismatch means the
    report is corrupt.
    """
    out: dict[tuple[str, str], dict] = {}
    for name in REPORTS:
        d = json.loads((ROOT / "snort_validation/reports" / name).read_text())
        assert d["engine"].startswith("suricata"), f"{name} is not a Suricata run"
        for c in d["cells"]:
            key = (c["mech"], c["flow_id"])
            if key in out:
                raise AssertionError(f"duplicate cell {key} in {name}")
            out[key] = {"evaded": c["evaded"], "alerts": c["alerts"],
                        "sids": c["sids"], "pkts": c["pkts"]}
    return out


def assert_complete(mechs: tuple[str, ...]) -> dict:
    """Ground truth for exactly `mechs` x 20 flows. Raises on any gap."""
    gt = load_ground_truth()
    fids = frozen_flow_ids()
    missing = [(m, f) for m in mechs for f in fids if (m, f) not in gt]
    if missing:
        raise AssertionError(
            f"ground truth incomplete: {len(missing)} cells missing, "
            f"first={missing[0]}")
    return gt


if __name__ == "__main__":
    gt = assert_complete(("noop", "split8", "split24",
                          "http_header_case", "query_param_prepend"))
    print(f"ground truth OK: {len(gt)} cells, "
          f"{len(frozen_flow_ids())} flows, engine=suricata 7.0.3")
```

Sửa dòng `_LABELS` cho đúng (tôi để placeholder ở trên; **bản cuối phải không có
`_LABELS`** — nó thừa):

```bash
cd /root/.hermes/c2-evasion-rl
# Bỏ dict thừa _LABELS
python - <<'PY'
import re, pathlib
p = pathlib.Path("controls/suricata_groundtruth.py")
s = p.read_text()
s = re.sub(r'\n_LABELS = \{[^}]*\}\n', '\n', s)
p.write_text(s)
print("removed placeholder _LABELS")
PY
.venv/bin/python controls/suricata_groundtruth.py
```
**Kỳ vọng:** `ground truth OK: 100 cells, 20 flows, engine=suricata 7.0.3`

```bash
git add controls/suricata_groundtruth.py
git commit -m "feat(P16c.0): frozen Suricata ground-truth loader (fail-closed, read-only)"
```

---

### Task 1 — RED: test chứng minh replica hiện tại SAI (76%)

**Viết test trước.** `tests/test_replica_matches_suricata.py`:

```python
"""The replica must agree with the committed Suricata verdicts on the 20 frozen flows.

This is the P16c regression gate. Before the reassembly fix it scores 76/100;
after it must be 100/100. If a future change breaks the surrogate's agreement,
this test fails -- the surrogate is what trains the policy, and a surrogate that
disagrees with the real engine teaches the policy the wrong thing.
"""
from __future__ import annotations

import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "ai_agent"), str(ROOT / "snort_validation")]

from c2_semantics import client_ip_of, ensure_chain  # noqa: E402
from hidden_defender_env import apply_mech, load_corpus  # noqa: E402
from snort_validation.real_rules_replica import RealRulesReplica  # noqa: E402

sys.path.insert(0, str(ROOT / "controls"))
from suricata_groundtruth import assert_complete, frozen_flow_ids  # noqa: E402

MECHS = ("noop", "split8", "split24", "http_header_case", "query_param_prepend")
SIDS = (2012627, 2012533)  # FakeAV + Virut, the SIDs the frozen sample was built on


@pytest.fixture(scope="module")
def replica():
    return RealRulesReplica.for_sids(set(SIDS))


@pytest.fixture(scope="module")
def pool():
    """flow_id -> flow. The 16 FakeAV live in the ORIGINAL corpus; the 4 Virut
    only exist in the P13 extended corpus. v3/v3fixed do NOT contain them."""
    out = {}
    for name in ("hidden_defender_corpus.pkl", "corpus_p13_extended.pkl"):
        for split in ("test", "train"):
            for f in load_corpus(split=split,
                                corpus=str(ROOT / "snort_validation/reports" / name)):
                out[f["flow_id"]] = f
    return out


@pytest.fixture(scope="module")
def cases(pool):
    """[(mech, flow_id, packets, ground_truth_evaded)] for every cell."""
    gt = assert_complete(MECHS)
    fids = frozen_flow_ids()
    missing = [f for f in fids if f not in pool]
    assert not missing, f"{len(missing)} frozen flows absent from corpora"
    out = []
    for mech in MECHS:
        for fid in fids:
            cip = client_ip_of(fid)
            pkts = [ensure_chain(p) for p in apply_mech(
                list(pool[fid]["packets"]), mech, cip, ownership="client")]
            out.append((mech, fid, pkts, gt[(mech, fid)]["evaded"]))
    return out


def test_replica_agrees_with_suricata_on_every_cell(replica, cases):
    """verdict() is True = DETECTED, so evaded = NOT verdict()."""
    wrong = []
    for mech, fid, pkts, gt_evaded in cases:
        evaded = not replica.verdict(pkts)  # legacy mode: no home_ip, as the env calls it
        if evaded != gt_evaded:
            wrong.append(f"{mech}/{fid[-28:]}: replica_evaded={evaded} suricata_evaded={gt_evaded}")
    assert not wrong, (
        f"{len(wrong)}/{len(cases)} cells disagree with real Suricata:\n  "
        + "\n  ".join(wrong[:8]))


def test_fragmentation_does_not_evade_under_the_replica(replica, cases):
    """G1b(i): an engine with stream reassembly defeats the split family.

    This is the specific behaviour the fix introduces. Asserted separately so a
    failure names the cause instead of just lowering an agreement number.
    """
    for mech in ("noop", "split8", "split24"):
        evaded = [fid for m, fid, pk, _ in cases if m == mech and not replica.verdict(pk)]
        assert not evaded, f"{mech} evades {len(evaded)} flows in the replica: {evaded[:3]}"


def test_non_fragmentation_mechanisms_keep_their_suricata_verdicts(replica, cases):
    """The fix must not disturb the mechanisms that were already correct."""
    gt = assert_complete(("http_header_case", "query_param_prepend"))
    for mech in ("http_header_case", "query_param_prepend"):
        got = {fid for m, fid, pk, _ in cases if m == mech and not replica.verdict(pk)}
        want = {f for f in frozen_flow_ids() if gt[(mech, f)]["evaded"]}
        assert got == want, f"{mech}: replica evades {len(got)}, Suricata {len(want)}"
```

```bash
.venv/bin/python -m pytest tests/test_replica_matches_suricata.py -q
```
**Kỳ vọng (RED):** `test_replica_agrees_with_suricata_on_every_cell` FAIL với
`24/100 cells disagree`; `test_fragmentation_does_not_evade_under_the_replica` FAIL
(`split24 evades 20 flows`); `test_non_fragmentation_mechanisms_keep_their_suricata_verdicts` PASS.

```bash
git add tests/test_replica_matches_suricata.py
git commit -m "test(P16c.1): RED -- replica disagrees with Suricata on 24/100 cells"
```

---

### Task 2 — GREEN: thêm stream reassembly vào replica

Sửa `snort_validation/real_rules_replica.py`. Thêm cạnh class `RealRulesReplica`
(đặt ngay **trước** `def _arms`, khoảng dòng 346):

```python
    reassemble: bool = False
    """Match content against the RECONSTRUCTED STREAM, not per packet.

    ``Rule.fires`` walks ``for payload in payloads``, so content split across
    two packets never matches. That models a Snort without stream reassembly.
    Real Suricata 7 reassembles the TCP stream before content matching, which
    is why the fragmentation family (``split8``/``split24``) evades the replica
    but not the engine. Measured on the 20 frozen HTTP-D4 flows against
    committed Suricata 7.0.3 runs: 76/100 agreement without reassembly,
    100/100 with it, and zero previously-correct cells broken.

    Default False so every existing caller keeps its current behaviour; the
    environment opts in explicitly (see hidden_defender_env).
    """
```

Rồi sửa `alert_count`, `verdict`, `firing_rules` để truyền cờ. Sửa `_arms`:

```python
    def _arms(self, packets: Sequence, home_ip: Optional[str] = None):
        handshake = _has_handshake(packets)
        fwd = _payloads(packets, forward_only=True, home_ip=home_ip)
        both = _payloads(packets, forward_only=False, home_ip=home_ip)
        if self.reassemble:
            # Engine-side view: one contiguous buffer per direction. Only TCP
            # streams have one; for UDP each packet IS its own datagram, so
            # joining them would fabricate adjacency that does not exist. UDP
            # therefore keeps per-packet matching (measured: 0/20 neris flow
            # change verdict under this flag).
            if _is_tcp_stream(packets):
                fwd = [b"".join(fwd)] if fwd else []
                both = [b"".join(both)] if both else []
        return handshake, fwd, both
```

Thêm helper ở module level, ngay **trên** `class RealRulesReplica`:

```python
def _is_tcp_stream(packets: Sequence) -> bool:
    """True when the flow has a TCP handshake -- i.e. an ordered byte stream.

    UDP datagrams are independent: concatenating them would invent adjacency and
    let content match across packet boundaries that the engine never sees.
    """
    from scapy.all import IP, TCP
    return any(IP in p and TCP in p for p in packets)
```

Đồng thời sửa `for_sids` để cờ truyền được:

```python
    @classmethod
    def for_sids(cls, sids: set, path: Path = RULES,
                 reassemble: bool = False) -> "RealRulesReplica":
        return cls(parse_ruleset(path, sid_filter=set(sids)), reassemble=reassemble)
```

Và `__init__`:

```python
    def __init__(self, rules: Sequence[Rule], reassemble: bool = False):
        self.rules = list(rules)
        self.reassemble = reassemble
```

```bash
.venv/bin/python -m pytest tests/test_replica_matches_suricata.py -q
```
**Kỳ vọng (GREEN):** `3 passed`. Cụ thể `100/100` agreement, `split8`/`split24` không né
flow nào, `http_header_case` 16/20, `query_param_prepend` 4/20 — **không đổi so với Suricata**.

```bash
git add snort_validation/real_rules_replica.py
git commit -m "fix(P16c.2): replica reassembles TCP streams before content match

Real Suricata 7 reassembles the TCP stream; Rule.fires matched content within a
single packet, so the split family evaded the surrogate but not the engine.
Measured on the 20 frozen HTTP-D4 flows vs committed Suricata runs:
76/100 -> 100/100 agreement, 0 previously-correct cells broken.
Opt-in via reassemble=True; UDP is excluded by _is_tcp_stream."
```

---

### Task 3 — Bật cờ trong env, không đụng revert `17a30fa`

Env hiện gọi `flow["replica"].verdict(pkts)` ở `ai_agent/hidden_defender_env.py:559`
(**không** truyền `home_ip` — đó là revert có chủ đích từ `17a30fa`, đừng đụng vào).

**Quan trọng:** reassembly và direction là hai trục độc lập. Fix đã verify ở **cả hai mode**,
nên bật reassembly **không** cần đụng tới quyết định direction.

Thêm cờ vào `HiddenDefenderEnv.__init__`:

```python
    def __init__(self, split: str = "train", real_snort: bool = False,
                 capture: Optional[str] = None, seed: int = SEED,
                 max_steps: int = 64, ownership: str = "client",
                 corpus: Optional[str] = None, reassemble: bool = True):
```

và gán `self.reassemble = reassemble` cạnh `self.real_snort = real_snort` (dòng ~528).

Trong `load_corpus` (dòng ~468) chỗ dựng `flow["replica"]`, truyền cờ qua. Nếu chỗ đó không
biết `self`, dùng cách đơn giản nhất: sau khi load, gán lại trong `_reset_flows`:

```python
        flow["replica"].reassemble = self.reassemble
```

**TDD trước:** thêm vào `tests/test_replica_matches_suricata.py`:

```python
def test_env_default_reassembles(tmp_path, pool):
    """The training env must score with stream reassembly on by default."""
    sys.path.insert(0, str(ROOT / "ai_agent"))
    from hidden_defender_env import HiddenDefenderEnv
    fid = frozen_flow_ids()[0]
    env = HiddenDefenderEnv(split="test", seed=42, real_snort=False, corpus=None)
    assert env.reassemble is True, "env default must match Suricata semantics"
    assert pool[fid]["flow_id"] == fid
```

Chạy → RED (`AttributeError: 'HiddenDefenderEnv' object has no attribute 'reassemble'`).
Sửa code → GREEN.

```bash
.venv/bin/python -m pytest tests/test_replica_matches_suricata.py tests/test_reward_semantic_gate.py tests/test_post_p14_actions.py tests/test_replica_direction.py -q
```
**Kỳ vọng:** tất cả pass. **`tests/test_replica_direction.py` phải vẫn xanh** — đó là bằng
chứng fix không đụng trục direction.

```bash
git add ai_agent/hidden_defender_env.py tests/test_replica_matches_suricata.py
git commit -m "feat(P16c.3): env scores with reassembly on by default (direction unchanged)"
```

---

### Task 4 — Train PPO trên surrogate đã sửa

```bash
cd /root/.hermes/c2-evasion-rl
.venv/bin/python ai_agent/train_hidden_defender_ppo.py \
    --n-flows 64 --max-epochs 30 --seed 42 --split train \
    --corpus snort_validation/reports/corpus_p13_extended.pkl \
    --out snort_validation/reports/train_p16c_rs_s42.json \
    > /tmp/p16c_train_s42.log 2>&1
```
**Kỳ vọng:** chạy xong, JSON có `evaded`, `semantics_breaks`, `n_queries`.
Surrogate ~1,3 s/flow → 30 epoch × 64 flow ≈ **40 phút**.

> Nếu `train_hidden_defender_ppo.py` không nhận `--corpus`, bỏ cờ đó và chạy lại;
> ghi vào doc dòng lệnh thực tế đã dùng. **Không sửa script train để né lỗi.**

Baseline so sánh (đã commit, `41b9162`): real-Snort seed 42 = **48,4%** (31/64 flow).

```bash
git add snort_validation/reports/train_p16c_rs_s42.json
git commit -m "feat(P16c.4): PPO trained on the reassembled surrogate (seed 42)"
```

---

### Task 5 — Validate policy trên Suricata THẬT

Viết `controls/validate_policy_suricata.py` — chạy **một** Suricata process cho mỗi cell,
đếm alert từ `fast.log`, cross-check `eve.json`, **fail-closed**.

```python
"""Evaluate a trained PPO policy with the REAL Suricata 7.0.3 engine.

One engine run per cell (not two): alert count and SID list come from the same
fast.log, which is the P16b.1f `alert_profile` decision. Fail-closed -- an engine
crash raises, it never writes -1 (that silent -1 is why cross_engine_v2.json has
5/5 cells = -1).

Budget: 25.66 s/cell. 20 flows x 1 mech = 8.6 min; x 5 mech = 42.8 min.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

import numpy as np

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "ai_agent"), str(ROOT / "snort_validation")]
sys.path.insert(0, str(ROOT / "controls"))

from hidden_defender_env import ACTION_NAMES  # noqa: E402
from hidden_defender_env import apply_mech, load_corpus  # noqa: E402
from c2_semantics import client_ip_of, ensure_chain  # noqa: E402
from snort_validation.suricata_runner import alert_profile  # noqa: E402
from suricata_groundtruth import assert_complete, frozen_flow_ids  # noqa: E402

YAML = ROOT / "snort_validation/suricata.yaml"
RULES = ROOT / "snort_validation/et_open_c2/suricata.rules"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True, help="path to the trained .zip")
    ap.add_argument("--out", required=True)
    ap.add_argument("--mechs", default="policy",
                    help="'policy' = the action the policy picks; or a comma list")
    args = ap.parse_args()

    from stable_baselines3 import PPO
    from hidden_defender_env import HiddenDefenderEnv

    env = HiddenDefenderEnv(split="test", seed=42, real_snort=False)
    model = PPO.load(args.model, env=env)

    fids = frozen_flow_ids()
    gt = assert_complete(("noop",))
    pool = {}
    for name in ("hidden_defender_corpus.pkl", "corpus_p13_extended.pkl"):
        for split in ("test", "train"):
            for f in load_corpus(split=split,
                                corpus=str(ROOT / "snort_validation/reports" / name)):
                pool[f["flow_id"]] = f

    mechs = (args.mechs.split(",") if args.mechs != "policy" else None)
    rows = []
    for fid in fids:
        flow = pool[fid]
        cip = client_ip_of(fid)
        if mechs is None:
            obs, _ = env.reset(seed=0)
            # put THIS flow in the env, then ask the policy
            env._flows = [flow]
            obs, _ = env.reset(seed=0)
            mask = env.action_masks()
            chosen = int(np.argmax(model.predict(obs, deterministic=True)[0]))
            mech = ACTION_NAMES[chosen]
        else:
            mech = mechs[0]
        pkts = [ensure_chain(p) for p in apply_mech(
            list(flow["packets"]), mech, cip, ownership="client")]
        prof = alert_profile(pkts, yaml=YAML, rules=RULES, workdir=ROOT)
        # `evaded` = n_alerts == 0 (decision 58). Never invert this.
        evaded = prof["n_alerts"] == 0
        rows.append({"flow_id": fid, "mech": mech, "n_alerts": prof["n_alerts"],
                     "sids": prof["sids"], "evaded": evaded,
                     "seconds": prof["seconds"], "noop_alerts": gt[("noop", fid)]["alerts"]})
        print(f"{mech:22s} {fid[-40:]:40s} alerts={prof['n_alerts']} "
              f"sids={prof['sids']} evaded={evaded}", flush=True)

    n = len(rows)
    ev = sum(r["evaded"] for r in rows)
    payload = {"engine": "suricata 7.0.3", "model": args.model,
               "flows": n, "evaded": ev, "evasion_rate": ev / n,
               "noop_alerts_total": sum(r["noop_alerts"] for r in rows),
               "cells": rows}
    out = ROOT / args.out if not args.out.startswith("/") else pathlib.Path(args.out)
    out.write_text(json.dumps(payload, indent=2, sort_keys=True))
    print(f"\nREAL SURICATA evasion = {ev}/{n} = {ev/n*100:.1f}%  -> {out}")
    if all(r["noop_alerts"] == 0 for r in rows):
        print("FAIL-CLOSED: every noop flow scored 0 alerts -- the harness is broken, "
              "these numbers must not be reported.", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

Trước khi chạy, kiểm tra signature thật của `alert_profile` và `HiddenDefenderEnv.action_masks`
(đã xác nhận: `action_masks()` **không** nhận tham số; `reset()` trả tuple `(obs, info)`;
obs shape `(11,)`, action space `Discrete(17)`).

```bash
.venv/bin/python controls/validate_policy_suricata.py \
    --model runs/ppo_post_p14_rs_s42.zip \
    --out snort_validation/reports/p16c_policy_suricata.json 2>&1 | tail -30
```
**Kỳ vọng:** `noop_alerts_total` = 20 (mọi flow đều alert dưới noop — nếu 0 thì harness hỏng,
script tự trả exit 2 và số phải bị loại). Thời gian ≈ **8,6 phút**.

```bash
git add controls/validate_policy_suricata.py snort_validation/reports/p16c_policy_suricata.json
git commit -m "feat(P16c.5): validate the trained policy with real Suricata 7.0.3"
```

---

### Task 6 — Ghi kết quả, kể cả khi nó là null

`docs/p16c_surrogate_fix_results.md` — bắt buộc có:

| mục | nội dung |
|---|---|
| Root cause | `Rule.fires()` khớp content trong 1 packet; Suricata reassemble stream |
| Số trước/sau | 76/100 → 100/100, 0 cell vỡ |
| Held-out check | 5 Virut-like ngoài mẫu: split8 đổi 5/5; noop vẫn 45/45 detect |
| UDP | `_is_tcp_stream` loại neris; 0/20 đổi verdict |
| Train | surrogate time, `evaded`, `semantics_breaks` |
| **Validate Suricata thật** | số thật, cùng SID khi alert |
| **Giới hạn** | n=4 Virut-like ở test; nếu kết quả null thì ghi "null" + vì sao |

Nếu validate ra kết quả tệ hơn 16/20 (tức dưới `http_header_case` 16/20 của P16b):
**ghi thẳng vào doc là thất bại**, không diễn giải lại. Đây là điều kiện đoạn cut:
surrogate khớp engine 100% ≠ policy tốt, vì train/validate khác phân bố
(train = 96 flow HTTP mở rộng, validate = 20 flow đóng băng).

```bash
git add docs/p16c_surrogate_fix_results.md
git commit -m "docs(P16c.6): surrogate reassembly fix + real-Suricata validation results"
```

---

### Task 7 — Verify chéo (không tin báo cáo tự khai)

```bash
.venv/bin/python controls/verify_report_claims.py | tail -1
.venv/bin/python -m pytest tests/ -q -k "not archive" 2>&1 | tail -5
.venv/bin/python controls/suricata_groundtruth.py
git log --oneline -7
```
**Kỳ vọng:** `109/109 checks passed, 0 failed`; test suite xanh (trừ 3 archive test
pre-existing đã biết: `test_real_cross_capture_reports_are_all_selected`,
`test_committed_summary_agrees_with_the_per_capture_reports`, `test_action_mask_format`);
`100 cells`; 7 commit đúng thứ tự.

---

## Ngân sách thời gian

| Task | Việc | Ước lượng |
|---|---|---|
| 0 | ground-truth loader | 10 phút |
| 1 | RED test | 15 phút |
| 2 | fix reassembly | 20 phút |
| 3 | env wiring | 20 phút |
| 4 | train PPO | 40 phút |
| 5 | validate Suricata | 10 phút (chạy nền song song Task 4) |
| 6 | viết doc | 20 phút |
| 7 | verify | 10 phút |
| | **Tổng** | **~2 giờ 25 phút** |

Dự phòng ~35 phút cho lỗi. Chạy Task 5 **song song** Task 4 (validate seed cũ
`ppo_post_p14_rs_s42.zip` ngay khi có Task 3 xanh) để tiết kiệm 10 phút.

---

## Risks / tradeoffs / câu hỏi mở

**R1 — Fix chỉ verify trên 20 flow của chính mẫu đó.** Đã giảm thiểu bằng held-out check
(5 Virut-like ngoài mẫu, `noop` 45/45 vẫn detect). Nhưng agreement 100/100 là trên tập nhỏ.
Nếu được thêm thời gian, chạy Suricata thật trên ~40 flow train để đo agreement rộng hơn —
**không nằm trong 3 giờ**.

**R2 — Surrogate khớp engine ≠ policy tốt.** Đây là rủi ro lớn nhất và **không giảm được
bằng kỹ thuật trong 3 giờ**: train trên 96 flow HTTP mở rộng, validate trên 20 flow đóng băng.
Surrogate chỉ là *scorer*; nó không sửa được việc thiếu Virut-like trong tập train
(chỉ 4 flow `list.php?c=` trong corpus gốc train, 2 trong extended train).
Headroom 20 pp của P16b vẫn đứng trên **n=4 ở nhóm quyết định** — điều này **không thay đổi**
dù surrogate có khớp 100%.

**R3 — Cờ `reassemble` mặc định False trong class nhưng True trong env.** Cố ý: không
đổi hành vi của caller cũ, nhưng env (thứ duy nhất train policy) bật. Nếu sau này ai đó
dựng `RealRulesReplica` trực tiếp để chấm, họ phải truyền cờ. Ghi rõ trong docstring.

**R4 — `_is_tcp_stream` dựa vào có mặt header TCP, không phải handshake thật.**
Đủ cho corpus này (mọi flow HTTP đều có handshake). Nếu corpus sau này có TCP không
handshake, `established` trong rule đã chặn sẵn.

**R5 — Neris/UDP không được hưởng lợi.** Fix cố ý không áp cho UDP. Điều này *đúng* về mặt
kỹ thuật nhưng nghĩa là **họ fragmentation vẫn có headroom trên UDP dưới chính replica** —
nếu train trên flow UDP, policy có thể học sai. Kiểm tra: tập train phải toàn HTTP
(`corpus_p13_extended.pkl` là 96 http / 120 http, đã xác nhận).

**R6 — Câu hỏi mở về nguyên nhân `http_header_case` thắng.** FakeAV SID 2012627 có
`depth:4` ở content đầu; Suricata khớp được `http_header_case` 16/16 vì rule match
`nocase`-ish trên header. Cơ chế này chỉ được xác nhận bằng **đo dưới engine thật**,
không được suy ra từ rule text. Không cần giải thích trong plan này.

**R7 — Nếu Task 4 cho kết quả kém, đừng sửa lại bar hay đổi tập.** Ghi null, ghi lý do,
chuyển sang viết thesis (đã có đường sẵn: `docs/p16b_direction1_results.md` mục 9).