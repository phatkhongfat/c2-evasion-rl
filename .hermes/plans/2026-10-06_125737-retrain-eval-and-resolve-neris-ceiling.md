# Plan: retrain + eval + hướng giải quyết cho trần 40.0%

*Created 2026-10-06 12:57 (Asia/Ho_Chi_Minh). Repo: `/root/.hermes/c2-evasion-rl`, branch `packet-level-rl`.*

---

## Goal

Decide — by measurement, not by guesswork — whether the 40.0% honest result is
near the achievable ceiling or a fixable training defect, then retrain and
evaluate accordingly and write down the conclusion the numbers support.

## Current context / assumptions

### Verified facts (each checked against a file this session)

1. **Headline result.** `snort_validation/reports/ppo_masked_test_ALIGNED.json`:
   `valid_evasion_pct: 40.0` (16/40), `semantics_breaks: 0`,
   `baseline_alert_pct: 100.0`, `actions_chosen: {split24: 16, noop: 24}`,
   `per_framing: http {16, 16, 100.0} / neris {24, 0, 0.0}`.

2. **`framing ≡ capture`, 1:1, and the split is NOT capture-disjoint.**

   | capture | framing | train | test |
   |---|---|---|---|
   | `botnet-capture-20110811-neris` | `http` | 455 | 16 |
   | `botnet-capture-20110819-bot` | `neris` | 698 | 24 |

   Both captures appear in both splits. `snort_validation/corpus_config.py`
   `split_flows()` pools all flows, shuffles, takes the first 40 — the
   docstring says "stratified by capture" but the code does not stratify.
   `CAPTURES` lists 4 captures; only these 2 ended up with flows in the corpus
   (`n_train 1153`, `n_test 40`, `n_all 1193`).

   The word *neris* therefore means two different things: a **capture**
   (`20110811-neris`, whose framing is `http`) and a **framing** (which comes
   from `20110819-bot`). Rename in the report, or readers will conflate them.

3. **The only full 14-mechanism sweep is stale by a week.**
   `snort_validation/reports/surrogate_sweep_14mech.json` mtime
   **2026-09-28 18:48**, i.e. before commit `40fffdf` (2026-10-05 22:00) which
   introduced the strict bar. Its stored `semantics_ok` column reflects the OLD
   relaxed rule: it reports `http_header_pad` `semantics_ok=True` on 16/16
   flows, which cannot hold under `bytes_equal_semantics` (header padding
   inserts bytes into the client stream). **Its ceiling must not be quoted.**

4. **A re-run today would be correct.** `ai_agent/hidden_defender_env.py`
   `semantics_intact()` delegates to `c2_semantics.bytes_equal_semantics`
   (verified in source). There is no stored packet payload in the sweep JSON,
   so re-running is the only way to get a valid `semantics_ok` column.

5. **What the stale sweep still validly says** (alert verdicts do not depend on
   the semantics rule), on 16 train flows × 14 mechanisms = 224 cells:
   - replica vs real Snort agreed **161/224 (71.9%)**;
   - `surrogate_false_safe = 0` — the surrogate **never** said "safe" when real
     Snort alerted;
   - **all 63 disagreements were `framing=http`, direction replica=ALERT /
     real=SAFE** (surrogate is conservative);
   - on neris: agreed **70/70**;
   - `split8` disagreed 11/16 (all on http) while `split24` disagreed 1/16 —
     which plausibly explains why the policy picked `split24` over `split8`.

6. **neris may not be hopeless, but this is unproven on the test split.**
   On the 5 neris *train* flows the sweep shows `split8` viable under real
   Snort. Whether any mechanism works on the 24 neris *test* flows has **never
   been measured** — the eval only ever scores the action the policy chose
   (`noop`), which proves nothing about the alternatives.

7. **An earlier claim of mine is unsupported and must be re-measured.**
   I previously stated "the surrogate is blind on neris: 0/20 evaded vs real
   Snort 3/20". No file in `snort_validation/reports/` contains it, and both
   saved audits contradict it (70/70 and 8/8 agreement on neris). Treat as
   **UNVERIFIED** until Phase 1 produces a saved artifact.

8. **Cost model.** `surrogate_sweep_14mech.json` = 2359 s / 224 cells →
   **10.5 s per real-Snort call**.
   - full test sweep 40 × 14 = 560 cells ≈ **98 min**
   - `train_hidden_defender_ppo.py --real-snort --n-flows 256` ≈ 45 min/epoch
     (infeasible at `MAX_EPOCHS=200`)
   - eval of 40 flows (baseline + action = 2 calls each) ≈ **14 min**

9. **Green baseline at HEAD `c10636e`:** `pytest -q` → 90 passed;
   `controls/verify_report_claims.py` → 109/109.

10. **CLI gaps.** `ai_agent/train_hidden_defender_ppo.py` exposes
    `--real-snort --n-flows --max-epochs --seed --out` but hardcodes
    `split="train"` and `model.save(models_dir / "ppo_hidden_defender")` → a
    retrain **would clobber the current ALIGNED model**. `ai_agent/eval_fixed_pipeline.py`
    exposes `--model --split --out --progress --limit --no-baseline` but has no
    `--capture`.

11. **Flow records already carry `capture`**: keys are
    `['flow_id','capture','dataset','key','packets','obs','framing','replica']`.

### Assumptions (flag if any is wrong)
- A real-Snort verdict for a fixed (flow, mechanism, dynamic-IP attempt) is
  deterministic across runs — needed only if Q3 (verdict cache) is taken up.
- 10.5 s/call stays representative for the rest of this session.

## Architecture / proposed approach

Three gated phases instead of a straight retrain, because the first thing
missing is not a better model — it is the number that says whether a better
model is possible. Phase 1 re-runs the 14-mechanism sweep under the current
strict bar on the **held-out test split** to produce the per-flow valid-evasion
*ceiling*; that single number decides whether Phase 2 can pay off. Phase 2 is a
real-Snort-teacher retrain (reduced budget so it fits in hours) and its honest
eval, and only runs if Phase 1 shows headroom. Phase 3 adds a `capture` filter
so a leave-one-capture-out run can answer the generalisation question. Phase 4
writes the conclusion and only then repairs the stale docs.

Each phase has a written exit criterion and its own commit, so stopping after
any phase leaves the repo consistent.

---

## Step-by-step tasks

### Phase 0 — baseline sanity (5 min, no code)

**T0.1** Confirm the starting point.
```bash
cd /root/.hermes/c2-evasion-rl
.venv/bin/python -m pytest -q 2>&1 | tail -3
```
Expected: `90 passed` (a `1 skipped` line may also appear).

```bash
.venv/bin/python controls/verify_report_claims.py 2>&1 | tail -2
```
Expected: `109/109 checks passed, 0 failed`.

```bash
git rev-parse --short HEAD   # expected: c10636e
```
Nothing to commit. **If either command is red, stop and report — do not
proceed on a broken baseline.**

---

### Phase 1 — measure the ceiling (TDD; ~100 min wall)

**T1.1 (3 min) — make the sweep declare which semantics bar produced
`semantics_ok`, and refuse stale sweeps.**

RED. Create `tests/test_sweep_semantics_bar.py`:
```python
"""The sweep must declare which semantics bar produced semantics_ok.

A sweep written before commit 40fffdf records the OLD relaxed rule in that
column; if its ceiling is quoted as if it were the strict bar, every number
downstream is wrong.  Recording the bar and refusing unknown bars closes that
hole.
"""
import json
import pathlib
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "controls"))


def test_sweep_records_semantics_bar():
    src = (REPO / "controls" / "surrogate_sweep_14mech.py").read_text()
    assert '"semantics_bar"' in src


def test_ceiling_report_refuses_sweep_without_bar(tmp_path):
    import ceiling_report

    stale = {"rows": [{"flow_idx": 0, "framing": "http", "mech": "split8",
                       "semantics_ok": True, "real_alert": False,
                       "masked_out": False}]}
    p = tmp_path / "stale.json"
    p.write_text(json.dumps(stale))
    try:
        ceiling_report.load(p)
    except ValueError as exc:
        assert "semantics_bar" in str(exc)
    else:
        raise AssertionError("a sweep without a declared bar must be refused")
```
```bash
.venv/bin/python -m pytest tests/test_sweep_semantics_bar.py -q
```
Expected: `2 failed`.

GREEN. In `controls/surrogate_sweep_14mech.py` add near the top:
```python
# Which strict bar produced `semantics_ok` in this file's rows.  Recorded so a
# later reader cannot mistake pre-alignment output for current output.
SEMANTICS_BAR = "c2_semantics.bytes_equal_semantics"
```
and include it in **both** JSON writes (the incremental one inside the loop and
the final one after summarising):
```python
out_path.write_text(json.dumps(
    {"semantics_bar": SEMANTICS_BAR,
     "n_rows": len(rows), "elapsed_s": round(time.time() - t0),
     "rows": rows}, indent=2))
```
```python
final = {
    "semantics_bar": SEMANTICS_BAR,
    "elapsed_s": round(time.time() - t0),
    "overall": summarize(compared),
    "eligible_only": summarize(eligible),
    "per_mechanism": per_mech,
    "rows": rows,
}
```

Create `controls/ceiling_report.py`:
```python
"""Max valid evasion achievable per flow, over all 14 mechanisms.

Reads a sweep produced under the STRICT bar and reports, per framing, how many
flows have at least one mechanism that evades real Snort with semantics intact
and is not masked out.  That count is the ceiling: no policy can score above it
on the same flows, so a policy at 40% against a 40% ceiling is not undertrained.
"""
from __future__ import annotations

import argparse
import collections
import json
from pathlib import Path

BAR = "c2_semantics.bytes_equal_semantics"


def load(path: Path) -> dict:
    d = json.loads(path.read_text())
    if d.get("semantics_bar") != BAR:
        raise ValueError(
            f"{path.name} was not produced under the current semantics bar "
            f"(declared {d.get('semantics_bar')!r}, need {BAR!r}); re-run it.")
    return d


def ceiling(d: dict) -> dict:
    by_flow: dict = collections.defaultdict(list)
    for r in d["rows"]:
        if r.get("real_alert") is None:
            continue                      # mechanism could not be applied
        by_flow[r["flow_idx"]].append(r)

    agg: dict = {}
    for rows in by_flow.values():
        framing = rows[0]["framing"]
        ok = [r["mech"] for r in rows
              if r.get("semantics_ok") and not r.get("masked_out")
              and not r["real_alert"]]
        slot = agg.setdefault(framing, {"flows": 0, "reachable": 0,
                                        "mechs": collections.Counter()})
        slot["flows"] += 1
        slot["reachable"] += bool(ok)
        for m in ok:
            slot["mechs"][m] += 1

    return {
        fr: {"flows": v["flows"],
             "reachable": v["reachable"],
             "ceiling_pct": round(100.0 * v["reachable"] / v["flows"], 1),
             "viable_mech_counts": dict(v["mechs"].most_common())}
        for fr, v in agg.items()
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("sweep", type=Path)
    args = ap.parse_args()
    res = ceiling(load(args.sweep))
    print(json.dumps(res, indent=2))
    print()
    for fr, v in sorted(res.items()):
        print(f"{fr}: {v['reachable']}/{v['flows']} flows reachable "
              f"= {v['ceiling_pct']}%")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```
```bash
.venv/bin/python -m pytest tests/test_sweep_semantics_bar.py -q
```
Expected: `2 passed`.

```bash
.venv/bin/python controls/ceiling_report.py snort_validation/reports/surrogate_sweep_14mech.json
```
Expected: raises `ValueError: ... was not produced under the current semantics
bar ...` — this is the guard proving the Sept-28 file is now refused.

```bash
git add controls/surrogate_sweep_14mech.py controls/ceiling_report.py tests/test_sweep_semantics_bar.py
git commit -m "measure: declare semantics bar; refuse stale sweeps in ceiling report"
```

**T1.2 (≈98 min, background) — sweep ALL 14 mechanisms over the held-out test
split under the current code.**

```bash
cd /root/.hermes/c2-evasion-rl && nohup .venv/bin/python controls/surrogate_sweep_14mech.py \
  --split test --n-flows 40 --seed 42 \
  --out snort_validation/reports/sweep_test_14mech.json \
  > /tmp/sweep_test_14mech.log 2>&1 &
```
Expected stdout, one line per cell:
```
  OK   flow  0 http    split8           sem=True  replica_alert=True  real_alert=False masked=False
...
[*] OVERALL <n>/560 agree (<p>%)
[*] surrogate said SAFE but real Snort ALERTED: <k>
[+] /root/.hermes/c2-evasion-rl/snort_validation/reports/sweep_test_14mech.json
```
The script rewrites the JSON after **every** cell, so re-running the identical
command after a timeout resumes from `done = {(flow_idx, mech)}`. Progress
check:
```bash
.venv/bin/python -c "import json;d=json.load(open('snort_validation/reports/sweep_test_14mech.json'));print(d.get('n_rows'),'/560')"
```

**T1.3 (2 min) — the gate.**
```bash
.venv/bin/python controls/ceiling_report.py snort_validation/reports/sweep_test_14mech.json
```
Expected shape:
```
{"http": {"flows": 16, "reachable": <n>, "ceiling_pct": <p>, "viable_mech_counts": {...}},
 "neris": {"flows": 24, "reachable": <n>, "ceiling_pct": <p>, "viable_mech_counts": {...}}}
```
Apply this decision table and write the real numbers into Phase 4:

| `neris.reachable` | Meaning | Action |
|---|---|---|
| `0` | no mechanism in the 14-action space evades the neris half | **skip Phase 2 and Phase 3's retrain**; the policy is already at ceiling; go to Phase 4 |
| `1..23` | headroom exists; `24 - reachable` is the most neris points available | run Phase 2 |
| `24` | every neris flow is theoretically evadable; the gap is purely the learner | run Phase 2, and `surrogate_false_safe` here is direct evidence about the teacher |

Also record `http.reachable` — if it is `< 16`, the current 16/16 is not the
ceiling either and the honest headline changes.

```bash
git add snort_validation/reports/sweep_test_14mech.json
git commit -m "measure: 14-mechanism ceiling on the held-out test split (strict bar)"
```

---

### Phase 2 — retrain with an honest teacher (conditional; ≈4 h background)

**Precondition:** `neris.reachable > 0` from T1.3 (or an explicit decision to
measure the training effect rather than chase ceiling).

**T2.1 (5 min) — `capture` filtering in the env.**

RED. Create `tests/test_capture_filter.py`:
```python
"""Capture filtering, so a leave-one-capture-out run is expressible.

The pooled split puts both captures in train AND test, so no result from it
supports a cross-capture claim.  These tests pin the filter that makes an
honest capture-disjoint run possible, and pin the confound the report must
disclose.
"""
import pathlib
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))

from hidden_defender_env import load_corpus  # noqa: E402

CAPTURE_HTTP = "botnet-capture-20110811-neris"   # framing == "http"
CAPTURE_NERIS = "botnet-capture-20110819-bot"    # framing == "neris"


def test_capture_filter_returns_only_that_capture():
    flows = load_corpus("all", capture=CAPTURE_HTTP)
    assert flows, "expected flows for the http capture"
    assert {f["capture"] for f in flows} == {CAPTURE_HTTP}


def test_loco_directions_are_disjoint():
    a = {f["flow_id"] for f in load_corpus("all", capture=CAPTURE_HTTP)}
    b = {f["flow_id"] for f in load_corpus("all", capture=CAPTURE_NERIS)}
    assert a and b, "both captures must have flows"
    assert not (a & b), "a flow must never be in both LOCO directions"


def test_split_all_spans_both_splits():
    n_all = len(load_corpus("all"))
    n_train = len(load_corpus("train"))
    n_test = len(load_corpus("test"))
    assert n_all == n_train + n_test


def test_unknown_filter_is_an_error():
    import pytest
    with pytest.raises(ValueError):
        load_corpus("all", capture="does-not-exist")


def test_capture_is_confounded_with_framing():
    """Documentation of the confound: this is why LOCO cannot isolate capture."""
    a = {f["framing"] for f in load_corpus("all", capture=CAPTURE_HTTP)}
    b = {f["framing"] for f in load_corpus("all", capture=CAPTURE_NERIS)}
    assert a == {"http"} and b == {"neris"}
```
```bash
.venv/bin/python -m pytest tests/test_capture_filter.py -q
```
Expected: `4 failed, 1 passed` (or `5 failed` if `load_corpus` rejects the extra
argument).

GREEN. In `ai_agent/hidden_defender_env.py` replace `load_corpus`:
```python
def load_corpus(split: str = "train", capture: str | None = None):
    """Load flows, optionally restricted to one capture.

    ``split="all"`` pools train+test; combined with ``capture`` it yields the
    flow set for one leave-one-capture-out direction (train on A, test on B).
    """
    with open(CORPUS_PKL, "rb") as fh:
        data = pickle.load(fh)
    flows = (data["train"] + data["test"]) if split == "all" else data[split]
    if capture:
        flows = [f for f in flows if f.get("capture") == capture]
        if not flows:
            raise ValueError(f"no flows for split={split!r} capture={capture!r}")
    return flows
```
and in `HiddenDefenderEnv.__init__`:
```python
    def __init__(self, split: str = "train", real_snort: bool = False,
                 seed: int = 42, max_steps: int = 1,
                 capture: str | None = None):
        super().__init__()
        self.split = split
        self.capture = capture
        self._flows = load_corpus(split, capture)
```
```bash
.venv/bin/python -m pytest tests/test_capture_filter.py -q
```
Expected: `5 passed`.

```bash
git add ai_agent/hidden_defender_env.py tests/test_capture_filter.py
git commit -m "feat(env): capture filter + split=all for leave-one-capture-out"
```

**T2.1b (5 min) — expose it on the train CLI, and stop clobbering the model.**

RED. Create `tests/test_train_cli.py`:
```python
"""The train CLI must not hardcode the model path or the split.

Hardcoding means every retrain overwrites models/ppo_hidden_defender.zip, i.e.
the previous condition becomes unreproducible the moment the next run starts.
"""
import pathlib

REPO = pathlib.Path(__file__).resolve().parent.parent
_MAIN = (REPO / "ai_agent" / "train_hidden_defender_ppo.py").read_text().split(
    "def main")[1]


def test_model_out_is_configurable():
    assert '"--model-out"' in _MAIN
    assert 'model.save(models_dir / "ppo_hidden_defender")' not in _MAIN


def test_split_is_configurable():
    assert '"--split"' in _MAIN
    assert 'BatchEnv(split="train"' not in _MAIN


def test_capture_is_configurable():
    assert '"--capture"' in _MAIN
```
```bash
.venv/bin/python -m pytest tests/test_train_cli.py -q
```
Expected: `3 failed`.

GREEN. In `ai_agent/train_hidden_defender_ppo.py`:
1. `BatchEnv.__init__` gains `capture=None` and forwards it:
```python
    def __init__(self, split="train", seed=SEED, real_snort=False,
                 capture=None):
        self.inner = HiddenDefenderEnv(split=split, seed=seed,
                                      real_snort=real_snort, capture=capture)
```
2. In `main()`:
```python
    ap.add_argument("--split", default="train",
                    choices=("train", "test", "all"),
                    help="corpus split to train on")
    ap.add_argument("--capture", default=None,
                    help="restrict training flows to one capture id")
    ap.add_argument("--model-out",
                    default=str(REPO / "models/ppo_hidden_defender.zip"),
                    help="destination .zip for the trained model")
```
3. Replace the env construction and the save:
```python
    env = BatchEnv(split=args.split, seed=SEED,
                   real_snort=args.real_snort, capture=args.capture)
```
```python
    out_model = Path(args.model_out)
    out_model.parent.mkdir(parents=True, exist_ok=True)
    model.save(str(out_model).removesuffix(".zip"))
```
```bash
.venv/bin/python -m pytest tests/test_train_cli.py -q      # 3 passed
.venv/bin/python -m pytest -q 2>&1 | tail -3               # 98 passed
git add ai_agent/train_hidden_defender_ppo.py tests/test_train_cli.py
git commit -m "feat(train): configurable split/capture/model-out"
```

**T2.1c (3 min) — same for eval.**

RED. `tests/test_eval_cli.py`:
```python
import pathlib

REPO = pathlib.Path(__file__).resolve().parent.parent
_MAIN = (REPO / "ai_agent" / "eval_fixed_pipeline.py").read_text().split(
    "def main")[1]


def test_eval_accepts_capture():
    assert '"--capture"' in _MAIN
    assert "capture=args.capture" in _MAIN
```
```bash
.venv/bin/python -m pytest tests/test_eval_cli.py -q   # expected: 1 failed
```
GREEN — add:
```python
    ap.add_argument("--capture", default=None,
                    help="restrict evaluation to one capture id")
```
```python
    env = HiddenDefenderEnv(split=args.split, seed=42, real_snort=False,
                            capture=args.capture)
```
```bash
.venv/bin/python -m pytest -q 2>&1 | tail -3      # 99 passed
.venv/bin/python controls/verify_report_claims.py 2>&1 | tail -1   # 109/109
git add ai_agent/eval_fixed_pipeline.py tests/test_eval_cli.py
git commit -m "feat(eval): accept a capture filter"
```

**T2.2 (≈3.7 h background) — retrain with real Snort as the teacher.**

```bash
cd /root/.hermes/c2-evasion-rl && nohup .venv/bin/python ai_agent/train_hidden_defender_ppo.py \
  --real-snort --n-flows 64 --max-epochs 20 --seed 42 \
  --out snort_validation/reports/ppo_realsnort64_train.json \
  --model-out models/ppo_realsnort64.zip \
  > /tmp/train_realsnort64.log 2>&1 &
```
Expected log, one line per epoch:
```
[*] training with scorer=real_snort
[*] epoch   1: 64 queries, <k>/64 flows valid this epoch (<p>%)
```
Budget: 64 × 10.5 s ≈ **11 min/epoch**; 20 epochs ≈ **3.7 h**; stops early if
`p >= 90`. Monitor with:
```bash
tail -f /tmp/train_realsnort64.log
```
On completion expect `[+] .../snort_validation/reports/ppo_realsnort64_train.json`
with `"scorer": "real_snort"`.

**`--n-flows 64` is deliberate**: at the default 256 one real-Snort epoch costs
45 min. Note in the report that this run differs from the ALIGNED run in *both*
teacher and rollout size, so it is a separate condition, not a clean A/B.

**T2.3 (≈14 min) — honest eval of the new model.**
```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python ai_agent/eval_fixed_pipeline.py \
  --model models/ppo_realsnort64.zip --split test \
  --out snort_validation/reports/ppo_masked_test_REALSNORT.json \
  --progress snort_validation/reports/.eval_realsnort_progress.jsonl
```
Expected runtime ≈ 14 min; expected keys `n_flows: 40`,
`pipeline: "fixed_6_fixes"`, `scorer: "real_snort"`.

**Gate:** `baseline_alert_pct` must be `100.0`. If it is not, the run is
*invalid*, not "worse" — re-run it, do not report the number.

```bash
git add snort_validation/reports/ppo_realsnort64_train.json \
        snort_validation/reports/ppo_masked_test_REALSNORT.json
git commit -m "measure: real-Snort teacher retrain + honest eval"
git check-ignore -v models/ppo_realsnort64.zip    # expect a match (gitignored)
```

---

### Phase 3 — capture-disjoint check (≈1 h background)

**Precondition:** T2.1 merged.

Direction 1 — train on capture A (`http`), test on capture B (`neris`):
```bash
cd /root/.hermes/c2-evasion-rl && nohup .venv/bin/python ai_agent/train_hidden_defender_ppo.py \
  --split all --capture botnet-capture-20110811-neris \
  --n-flows 128 --max-epochs 40 --seed 42 \
  --out snort_validation/reports/loco_A_train.json \
  --model-out models/loco_A.zip > /tmp/loco_A.log 2>&1 &
```
```bash
.venv/bin/python ai_agent/eval_fixed_pipeline.py \
  --model models/loco_A.zip --split all --capture botnet-capture-20110819-bot \
  --limit 40 \
  --out snort_validation/reports/loco_A_on_B.json \
  --progress snort_validation/reports/.loco_A_progress.jsonl
```
Direction 2 — swap A and B (`--capture botnet-capture-20110819-bot` for
training, `--capture botnet-capture-20110811-neris` for eval), producing
`models/loco_B.zip`, `loco_B_train.json`, `loco_B_on_A.json`.

`--limit 40` scores the first 40 flows of the target capture (≈14 min); raise it
for a stronger claim (200 flows ≈ 70 min per direction).

**Gate for both directions:** `baseline_alert_pct == 100.0`.

**Mandatory caveat for the report:** because `framing ≡ capture` 1:1, this is
simultaneously a cross-framing test. A low score cannot be attributed to "did
not generalise to the other capture" rather than "never saw this framing in
training" — with n=2 captures those two explanations are not separable. State
this; do not pick the flattering reading.

```bash
git add snort_validation/reports/loco_*.json
git commit -m "measure: leave-one-capture-out, both directions"
```

---

### Phase 4 — decide and write up (no compute)

1. Put the four numbers in one table before writing prose:
   - `ppo_masked_test_ALIGNED.json` → **40.0%** (current headline, replica teacher)
   - `ceiling_report(sweep_test_14mech)` → **ceiling %**
   - `ppo_masked_test_REALSNORT.json` → real-teacher retrain %
   - `loco_A_on_B.json` + `loco_B_on_A.json` → cross-capture %

2. Read the conclusion off the table:
   - ceiling ≈ 40.0 → *"the policy is already at ceiling; the corpus and action
     space, not the learner, are the binding constraint."*
   - ceiling > 40.0 and real-teacher > 40.0 → report the gain. Only call it an
     improvement if you also state which bar each number used (the 57.5%
     reference was measured under the relaxed bar and is not comparable).
   - ceiling > 40.0 and real-teacher ≈ 40.0 → the defect is exploration/reward,
     not the teacher; document that as the next step rather than retraining
     again.
   - LOCO collapses → *"no cross-capture generalisation claim is supportable
     with 2 captures."*

3. Repair `docs/thesis_vi.tex`, `docs/README_SIC.md`, and
   `docs/SIC_AI_FRAMEWORK_VALIDATION.md` **line by line with `patch`** — never a
   bulk string replace (repo rule established 2026-10-04). Only after the four
   numbers are final. Known stale values there: 73.3%, 65,536 actions,
   "+100/−2/−50", "3.2 packets", 71/71 control, 81/81 verifier.

4. Re-run the verifier; if it pins a number you just changed, update
   `controls/verify_report_claims.py` in the same commit:
```bash
.venv/bin/python controls/verify_report_claims.py 2>&1 | tail -2   # 109/109
```

---

## Tests / validation

- **Per task:** RED → run → confirm failure → implement → run → confirm pass →
  commit. Exact commands with expected counts are given inline above.
- **Full gate before any commit touches docs:**
```bash
cd /root/.hermes/c2-evasion-rl
.venv/bin/python -m pytest -q 2>&1 | tail -3            # 99 passed (was 90)
.venv/bin/python controls/verify_report_claims.py 2>&1 | tail -2   # 109/109
```
- **Every measurement** must land as JSON in `snort_validation/reports/` with
  `baseline_alert_pct == 100.0` before its number is quoted anywhere. A missing
  or non-100 baseline invalidates the run; it never becomes "a lower score".
- **Never quote a ceiling from a file that `ceiling_report.load()` refuses.**

## Risks, tradeoffs, and open questions

### Risks
- **Measurement dominates wall-clock.** Phase 1 ≈ 98 min, Phase 2 ≈ 3.7 h +
  14 min, Phase 3 ≈ 2 × (25 min + 14 min) → ≈ **6 h** total background time.
  Cutting Phase 2 and 3 still leaves the most valuable answer (whether a better
  model is possible).
- **The stale-sweep trap is only half-closed.** T1.1 records the bar and
  `ceiling_report.load()` enforces it, but nothing stops a hand-written JSON.
  The guard exists for this workflow only.
- **Overwriting history.** The sweep appends to whatever `--out` names. The plan
  deliberately uses `sweep_test_14mech.json` instead of the existing
  `surrogate_sweep_14mech.json`; do not reuse the old filename.
- **`--n-flows 256 → 64` changes `n_steps` and `batch_size`**, so Phase 2 is not
  a pure teacher A/B against the ALIGNED run. Report both conditions and say
  what differs.
- **Model files are not in git** (`models/*.zip` is ignored), so a lost model
  means retraining. Confirm with `git check-ignore -v` before relying on a
  path.

### Tradeoffs
- Real-Snort-in-training is honest but ~15× slower than the replica. The
  alternative — teaching the replica the 4,394 rules it cannot implement
  (`pcre` / `byte_test` / `byte_extract` / `byte_jump`) — is open-ended work
  with no guaranteed payoff. Chosen: buy honesty with wall-clock.
- Capture-disjoint eval is the only honest generalisation test, but it doubles
  the compute and, at n=2, cannot separate capture from framing.
- `--limit 40` keeps LOCO affordable at the cost of a 40-flow sample per
  direction; raise it if the report needs more than a sample.

### Open questions
- **Q1 — compute budget (please decide).** Default: Phase 1 always, Phase 2+3
  only if Phase 1 shows headroom (≈6 h worst case). If you want the quick
  answer only, Phase 1 alone is ≈100 min and still decides whether retraining
  can ever help.
- **Q2 — is the earlier "surrogate blind on neris, 0/20 vs 3/20" real?** It is
  in no artifact and both saved audits contradict it. Phase 1 re-measures it on
  the test split; the evidence would be a non-zero
  `surrogate_false_safe` in `sweep_test_14mech.json`. If it reappears, Phase 2's
  premise flips back to "teacher fix" and Q1's budget matters more.
- **Q3 — verdict cache.** Memoising `SnortBatchService.verdicts_chunked` on
  `(flow_id, mech)` would make repeated epochs free. Not planned (YAGNI) unless
  Phases 1 and 2 both show headroom and wall-clock runs short; it depends on the
  determinism assumption above.
- **Q4 — corpus depth.** The corpus uses 2 of the 4 captures in `CAPTURES`
  (`capture-win13`, `botnet-capture-20110810-neris` have no flows). Adding them
  would let LOCO separate capture from framing — but that is a corpus change,
  out of scope here, and `capture-win13` has no payload-bearing traffic to
  evade with (see `aggregate_results.py`, which treats 0/24 for win13 as
  legitimate data).
