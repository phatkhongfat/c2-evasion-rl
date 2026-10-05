# Fixed-pipeline evaluation results (2026-10-05)

All numbers below are read from the artefacts in
`snort_validation/reports/`, not transcribed by hand. Reproduce with:

```bash
.venv/bin/python ai_agent/eval_fixed_pipeline.py      # -> ppo_masked_test_FIXED.json
.venv/bin/python ai_agent/eval_overfit_check.py       # -> overfit_check_FIXED.json
.venv/bin/python ai_agent/compare_eval_pipeline.py    # -> eval_comparison_FIXED.json
```

## Headline: the 100% was inflated; the honest number is 57.5%

| | pre-fix | post-fix (6 fixes) |
|---|---|---|
| scorer | real Snort | real Snort |
| test flows | 40 | 40 |
| baseline alerted | (not recorded) | **40/40 (100%)** |
| valid evasion | 40/40 = 100% | **23/40 = 57.5%** |
| semantics breaks | 0 | 0 |
| mechanism diversity | 2 | **2** |
| actions | split24 ×16, split8 ×24 | split24 ×16, split8 ×24 |

Baseline alerting on 40/40 confirms every test flow is a true positive, so the
post-fix evasion is measured against a genuine positive baseline.

### Where the 42.5 pp went

| framing | n | valid evasion | % |
|---|---|---|---|
| http | 16 | 16 | **100.0** |
| neris | 24 | 7 | **29.2** |

HTTP flows are unaffected: fragmenting the client's request at 24 bytes still
suppresses the HTTP C2 signature and the client's bytes reassemble exactly.
Neris flows collapse from 24/24 to 7/24 because **the BitTorrent-DHT signature
is present in BOTH directions** of the flow — measured: 24/24 neris flows carry
the pattern in the client payload *and* in the server payload. The old pipeline
fragmented the server's copy too (the defect in Fix 2); client-only mutation
removes only the client's copy, so whether the flow evades now depends on the
responder's copy. Suppressing a signature the attacker cannot touch is not
evasion, and 29.2% is the honest figure.

## Answer 1 — Does RL still evade under byte equality?

**Yes, but not at 100%.** 23 of 40 held-out flows are evaded with the strict
byte-equality bar and zero semantics breaks. Evasion is real and non-trivial
(57.5%), and the entire loss is concentrated in flows where the signature is
duplicated on the server side.

## Answer 2 — Did it learn more than 2 actions?

**No.** The policy still uses exactly two actions (`split8` on neris,
`split24` on http), one per framing. Mechanism diversity is unchanged by the
fixes — this is a policy/training limitation, not an evaluation artefact. The
14-action space collapses to a deterministic 1:1 framing→action map.

## Overfit check

A 20-flow random sample of the **train** split scored with the identical fixed
pipeline: **8/20 = 40.0%**, versus **57.5%** on test. The generalisation gap is
**−17.5 pp** (test higher than train). There is no overfitting signature here —
if anything the test split is easier — so the 57.5% is not a memorisation
artefact.

## The 38.89% figure

Unchanged and still correct *for its own question*: it is the mean of three
**per-capture** evasions (16.67%, 100%, 0%) across three different corpora, one
of which (`capture-win13`) carries almost no payload. It is a transfer figure,
not the test-split evasion, and the two must never be averaged together or
quoted interchangeably. See `docs/EVAL_AUDIT_2026-10-05.md`.

## What changed in the code

`snort_validation/eval_pipeline.py` (new), exercised by
`tests/test_evaluation_fixes.py` (11 tests) and driven by
`ai_agent/eval_fixed_pipeline.py`. Six commits, one per fix, in the order the
plan specifies.
