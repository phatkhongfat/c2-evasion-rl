# Stream-routing feasibility: can non-split actions become viable?

**Created:** 2026-10-12 22:16
**Repo:** `/root/.hermes/c2-evasion-rl` (HEAD `26daf2f`)
**Status:** planning only — no code changed by this plan.

---

## Goal

Determine whether routing evaluation packets through TCP stream reassembly
(`stream5_tcp: policy last` instead of the shipped `policy first`) makes the
ten non-split actions usable, and if the answer is no, specify the action-space
change that would create genuine per-flow headroom without rigging the
benchmark.

---

## Current context / assumptions

### The question's premise is refuted by existing measurements

`snort_validation/c2_semantics.py:388-404` defines the validity bar:

```python
def bytes_equal_semantics(original_packets, mutated_packets, client_ip) -> bool:
    if not wire_deliverable(original_packets, mutated_packets):
        return False
    if (reassembled_client_bytes(original_packets, client_ip)
            != reassembled_client_bytes(mutated_packets, client_ip)):
        return False
```

A valid evasion must satisfy **two independent conditions**:

1. the recovered client stream is byte-for-byte identical, **and**
2. Snort does not alert.

Condition 1 is enforced by our *own* code and is completely independent of the
Snort config. Measured per-mech over 40 test flows, ownership `client`
(`snort_validation/reports/ceiling_v3_client_test.json`):

| mechanism | valid evasions | semantics FAIL | why |
|---|---:|---:|---|
| `split8` | 15 | 0 | bytes preserved, stream lost |
| `split16` | 15 | 0 | bytes preserved, stream lost |
| `split_slow` | 15 | 0 | bytes preserved, stream lost (late) |
| `split24` | 11 | 0 | bytes preserved, stream lost |
| `prepend4/8/12` | 0 | **40 each** | rewrites the recovered bytes |
| `pad16` | 0 | **40** | rewrites the recovered bytes |
| `corrupt8` | 0 | **40** | rewrites the recovered bytes |
| `length_wrapper` | 0 | **40** | rewrites the recovered bytes |
| `http_header_pad` | 0 | 3 | rewrites the recovered bytes |
| `overlap8` | 0 | 33 | duplicate/ambiguous seq bytes |
| `reorder` | 0 | 8 | byte-safe, but reassembly restores order |
| `ttl` | 0 | 0 | byte-safe, changes nothing on-link |
| `noop` | 0 | 0 | byte-safe, changes nothing |

Under ownership `both` (`ceiling_v3_expert.json`, `ceiling_ownership_both_v2.json`)
the same pattern holds: every byte-rewriting action fails semantics on every
flow it was tested against (40/40 or 24/24), while `reorder`/`ttl`/`noop` pass
semantics and evade nothing.

**Therefore:** enabling stream reassembly cannot revive the byte-rewriting
actions. They are already at zero *before Snort ever sees the packet*, and no
Snort directive changes that. Reassembly only ever makes things worse for them:
it additionally undoes `reorder` by construction.

### What reassembly will actually do (two background sweeps, still running)

| action | `policy first` (shipped) | `policy last` (predicted) |
|---|---|---|
| `split8` / `split16` / `split24` | 40/40 evade | ~0 — reassembled inside the 30 s window |
| `split_slow` | 40/40 evade | 40/40 — tail held past the timeout |
| all ten others | 0 valid | 0 valid, unchanged (semantics bar) |

Prediction: after switching to `policy last` the action space has **exactly one
viable member**. `snort -T` on the new config confirms `Reassembly Policy: LAST`,
`Timeout: 30 seconds`; `split_slow` is documented as holding the tail past
frag3's 60 s, so it survives either way.

### The real structural constraint

A valid evasion needs *(bytes unchanged)* **AND** *(IDS loses the stream)*. The
action space has exactly one family satisfying both: the `split*` family. Four
of them tie at 40/40 under the shipped config, so `headroom = oracle −
best_single = 0`. This is why `headroom = 0` at every measurement to date.

### Hard constraint carried forward

Do **not** obtain headroom by masking the winner (deleting `split8`/`split16`
or shrinking the action space to hide `split_slow`). That is rigging the
benchmark, and any comparison must be against the best mechanism under the same
constraint. `docs/THREAT_MODEL.md` and the existing gate discipline stay in
force.

---

## Architecture / proposed approach

Treat this as a **gate**: first confirm with the two running sweeps that
`policy last` leaves the viable set at `{split_slow}` and the ten byte-rewriting
actions at zero. Only then, if and only if a reviewer accepts the scope
expansion in "Open questions", prototype **byte-preserving, stream-degrading**
primitives — actions that leave the recovered stream identical but defeat the
IDS's ability to assemble it within its timeout, by a route the shipped
preprocessors do not cover. Re-measure headroom on the widened action space.

---

## Step-by-step tasks

### Task 1 — Harvest the two running sweeps (read-only, no code)

```bash
cd /root/.hermes/c2-evasion-rl
ls -la snort_validation/reports/ceiling_v4_both_test.json \
       snort_validation/reports/ceiling_v4_both_reassemble.json
```

Expected: both files exist (jobs `proc_4548e8cd6d70`, pid 702882, and
`proc_6207dd06e2ee`, pid 710170). Do not re-run them; if a file is missing, the
job died — capture the log, do not silently restart.

### Task 2 — Write the per-mech table helper (RED first)

Create `controls/compare_sweeps.py`. It reads two sweep reports and prints a
per-mech and per-flow diff, so the reassembly claim is reproducible rather than
eyeballed.

Write the test **first**, `tests/test_compare_sweeps.py`:

```python
"""A reassembly sweep must kill the fast splits and keep split_slow alive."""
import json
from pathlib import Path

from compare_sweeps import diff_sweeps

REPORTS = Path(__file__).resolve().parents[1] / "snort_validation" / "reports"


def _load(name):
    return json.loads((REPORTS / name).read_text())


def test_fast_splits_die_under_reassembly():
    first = _load("ceiling_v4_both_test.json")            # shipped conf
    reasm = _load("ceiling_v4_both_reassemble.json")      # policy last
    d = diff_sweeps(first, reasm)

    # Reassembly restores the byte stream inside the 30 s window, so the fast
    # splits can no longer hide the pattern.
    assert d["by_mech"]["split8"]["reassemble"] < d["by_mech"]["split8"]["first"]
    assert d["by_mech"]["split24"]["reassemble"] < d["by_mech"]["split24"]["first"]

    # split_slow holds the tail past frag3's 60 s, so it survives either way.
    assert d["by_mech"]["split_slow"]["reassemble"] > 0
```

Run it:

```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python -m pytest tests/test_compare_sweeps.py -q
```

Expected **RED**: `ModuleNotFoundError: No module named 'compare_sweeps'`.

Implement `controls/compare_sweeps.py` minimally:

```python
"""Per-mech and per-flow diff between two ceiling sweep reports."""
from __future__ import annotations


def _valid(report):
    """{mech: {flow_id: bool}} of valid_evasion across a sweep's cells."""
    out: dict[str, dict[str, bool]] = {}
    for c in report["cells"]:
        out.setdefault(c["mech"], {})[c["flow_id"]] = bool(c.get("valid_evasion"))
    return out


def diff_sweeps(first, reasm):
    """Compare two sweeps; return per-mech counts and per-flow sets."""
    a, b = _valid(first), _valid(reasm)
    mechs = sorted(set(a) | set(b))
    by_mech = {
        m: {
            "first": sum(a.get(m, {}).values()),
            "reassemble": sum(b.get(m, {}).values()),
            "closed_by_reassembly": sorted(
                fid for fid, v in a.get(m, {}).items()
                if v and not b.get(m, {}).get(fid, False)
            ),
        }
        for m in mechs
    }
    return {"by_mech": by_mech, "by_flow": {m: by_mech[m]["closed_by_reassembly"]
                                            for m in mechs}}
```

Run again. Expected **GREEN**: `1 passed`.

### Task 3 — Record the gate result in the root-cause doc

Append to `docs/headroom_root_cause.md` a section headed
`## Stream reassembly does not open the action space (2026-10-12)`, containing:

- `snort -T` output proving the shipped conf is `Reassembly Policy: FIRST` and
  the new conf is `LAST, Timeout: 30 seconds`;
- the per-mech table from Task 2;
- the semantics table from "Current context", stating that byte-rewriting
  actions fail at `c2_semantics.bytes_equal_semantics` **before** Snort is
  consulted, so no Snort directive can revive them;
- the resulting statement: viable set under `policy last` is `{split_slow}`,
  therefore `headroom` remains `0` and for a stricter reason.

Do **not** write "reassembly makes fragmentation pointless" — `split_slow`
refutes that.

### Task 4 — Verifier and commit

```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python controls/verify_report_claims.py
```

Expected: `109/109 passed` (or higher). If the new doc text trips a claim
check, fix the doc to match the measured numbers — never the checker.

```bash
cd /root/.hermes/c2-evasion-rl && git add -A && \
  git commit -m "docs(P10): stream reassembly leaves one viable action; headroom stays 0"
```

### Task 5 — Prototype byte-preserving primitives (ONLY after the scope question is answered)

For each candidate primitive, the TDD cycle is the same and the two assertions
are non-negotiable — the first says the endpoint can still talk, the second says
the IDS cannot:

```python
def test_primitive_preserves_recovered_bytes():
    # bytes_equal_semantics must stay True: the endpoint reassembles the
    # original stream, so this is a detection gap, not a broken attack.
    assert bytes_equal_semantics(original, mutated, client_ip)


def test_primitive_evades_shipped_conf():
    assert score_flow_real(mutated, client_ip, mech=prim, ownership="both")["alert"] is False
```

Implement in `snort_validation/eval_pipeline.py` alongside the existing branches
at lines 139 (`split_slow`), 186 (`overlap8`), 203 (`http_header_pad`),
214 (`length_wrapper`), 222 (`pad`), 228 (`prepend`), 234 (`corrupt`),
243 (`reorder`), 253 (`ttl`), 263 (`noop`), following the same
`elif mech.startswith(...)` dispatch, and register the name in
`ai_agent/hidden_defender_env.py:71-78` `ACTION_NAMES` plus a cost in
`ACTION_COSTS` (lines 91-111).

~~Candidate directions, in preference order, all byte-preserving:~~ **Two of the
three original candidates are refuted by measurement (see below). Only the third
remains unverified.**

- ~~**IPv6 extension-header chain** instead of IPv4 fragmentation — the shipped
  config enables `frag3_engine` (IPv4 only); there is no `frag6` preprocessor.~~
  **REFUTED, and unsafe to add.** `reassembled_client_bytes`
  (`c2_semantics.py:237-283`) filters on scapy's `IP` layer, which is **IPv4
  only** (`c2_semantics.py:253`); `wire_deliverable`'s `_datagrams` skips any
  packet without `IP` (`c2_semantics.py:338`); `client_ip_of`
  (`c2_semantics.py:142-156`) truncates an IPv6 flow id at the first `:`.
  Measured on synthetic IPv6 captures with *different* payloads
  (`AAAA` vs `BBBB`): `bytes_equal_semantics` returns **`True`**, because both
  sides recover `b""`. The bar is therefore **blind to IPv6** and would certify
  any IPv6 mutation as byte-preserving — a false-evasion generator. The corpus
  (`snort_validation/reports/hidden_defender_corpus.pkl`) is 100% IPv4 (train
  19,107 pkts / test 452 pkts, zero IPv6), so the primitive would also be
  inapplicable to every flow. Adding it requires IPv6 support in the bar, the
  corpus, `apply_mech`, `translate_source` and the action mask — a multi-layer
  precondition fix, not an action addition.
- ~~**Overlap that keeps the reassembled bytes identical** — differs from
  `overlap8`, which currently duplicates bytes and fails semantics 33/40.~~
  **REFUTED by existing tests.** `tests/test_overlap_policy_gap.py:57-72`
  documents that `overlap8` is a no-op on TCP (`len(mut) == 1`, bytes
  unchanged) and is rejected by the bar on UDP, because the bar reassembles by
  fragment offset and ignores arrival order — so a decoy at offset 0 and the
  real head at offset 0 land in different runs. An "overlap that keeps bytes
  identical" cannot pass without changing the bar, which is out of bounds.
- **Session-boundary / early-flush tricks** that force a flush without losing
  bytes. **Unverified — the only surviving candidate.** It must defeat a
  mechanism that is actually configured (`frag3`'s timeout, or stream5's
  reassembly policy), and must pass both non-negotiable tests.

Reject any candidate that fails the first test. A primitive that breaks the
endpoint's stream is not a detection gap and must not be counted as one.

**Prerequisite for this task, regardless of candidate:** close the IPv6
blindness hole in the semantics bar. Add a regression test asserting the bar
*rejects* a payload-changing IPv6 capture. It should fail today (the bar returns
`True`); that failure is the confirmed bug, not a broken test. Fixing it is
defensive hardening of an existing benchmark — it cannot change any reported
reported number, because no corpus flow is IPv6.

### Task 6 — Re-measure headroom

```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python controls/ownership_ceiling_sweep.py \
  --ownership both --split test \
  --out snort_validation/reports/ceiling_v5_both_test.json
```

Then:

```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python controls/rl_headroom.py \
  snort_validation/reports/ceiling_v5_both_test.json
```

The gate passes only if `headroom > 0` **and** no single mechanism reaches the
oracle. `headroom = 0` here is a valid, publishable negative result — report it
rather than loosening the bar.

---

## Tests / validation

| check | command | expected |
|---|---|---|
| new test red | `.venv/bin/python -m pytest tests/test_compare_sweeps.py -q` | `ModuleNotFoundError` |
| new test green | same | `1 passed` |
| full suite | `.venv/bin/python -m pytest tests/ -q` | `207 passed, 1 skipped` |
| verifier | `.venv/bin/python controls/verify_report_claims.py` | `109/109 passed` |

Full-suite runtime is ~627 s, so run it backgrounded with `notify: true` and
poll with `kill -0 <pid>`; a foreground call will time out.

Pre-existing failures in `archive/` (3) are out of scope and must not be
"fixed" by editing the archive: `test_aggregate_inputs.py` (2) and
`test_direction_2_masking.py::test_action_mask_format`.

---

## Risks, tradeoffs, and open questions

**Risks**

- Widening the action space raises the baseline bar: if a new primitive evades
  more flows than `split_slow`, the comparison must be against that new best,
  not against today's `split_slow`. Re-run `rl_headroom.py` after every added
  primitive, never against a stale report.
- A prototype that passes `bytes_equal_semantics` but evades only because it
  *breaks* the flow would silently inflate the ceiling. The first test in Task 5
  exists specifically to catch that.
- Two Snort-heavy sweeps are already running; adding a third will slow all of
  them on this 4-core box.

**Tradeoffs**

- `policy last` is a *more realistic* IDS than the shipped `policy first`, so
  moving to it strengthens the benchmark's external validity — but it shrinks
  the viable action set to one, which makes the RL problem a one-armed bandit
  rather than a decision problem. The honest framing is a negative result about
  the action space, not a fix for it.
- Keeping the shipped config keeps four tied actions, which is what made the
  oracle-collapse diagnosis visible. Switching configs is an analysis, not a
  change to adopt.

**Open questions — need a decision before Task 5**

1. Task 5 adds primitives whose purpose is to find gaps in Snort's reassembly.
   That is standard NIDS-evaluation methodology, but it does expand the thesis
   beyond "does RL pick mechanisms". Should it be pursued, or is the negative
   result at Task 3 sufficient for the write-up?
2. Should `policy last` become the default evaluation config (more realistic,
   one viable action) or stay a side experiment (four tied actions, richer
   diagnosis)? These are opposite choices and the reports must not be mixed.
3. Is relaxing the byte-equality bar ever on the table? Recording it here so it
   is explicitly rejected: it would make `prepend`/`pad`/`corrupt` "valid" and
   manufacture headroom without changing anything real.