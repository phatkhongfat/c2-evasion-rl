# Fixed-pipeline evaluation: what the honest numbers are

Date: 2026-10-05
Artifact: `snort_validation/reports/ppo_masked_test_FIXED.json`
Driver: `ai_agent/eval_fixed_pipeline.py` (uses `snort_validation/eval_pipeline.py`)
Tests: `tests/test_evaluation_fixes.py` (11)
Verifier: `controls/verify_report_claims.py` (102 checks)

## Headline

| report | pipeline | valid evasion | baseline alerted | mechanisms |
|---|---|---|---|---|
| `ppo_masked_test.json` | old | **40/40 = 100%** | 40/40 | split8, split24 |
| `ppo_masked_test_FIXED.json` | 6 fixes | **23/40 = 57.5%** | 40/40 | split8, split24 |

The 42.5-point drop is not a regression in the policy. It is the amount by which
the old score was inflated by scoring mutations the attacker cannot actually
make, and by a semantics bar that certified byte changes as "intact".

## Per framing — where the 40/40 came from

| framing | n | old valid | fixed valid | fixed % |
|---|---|---|---|---|
| http | 16 | 16/16 | 16/16 | 100.0% |
| neris | 24 | 24/24 | 7/24 | 29.2% |

The old pipeline fragmented the **server's** response as well as the client's,
so a neris flow evaded even when the bot's own bytes still carried the pattern
the rule matches. Restricted to client-side packets, real Snort still sees the
responder's copy and keeps alerting on 17 of the 24 neris flows.

## Does RL still evade under byte-equality?

Yes, on a well-defined subset, and with a fully intact C2 channel:

- **23/40 (57.5%)** flows evade real Snort with **zero semantics breaks**
  (`semantics_breaks: 0`). Every evasion preserves every client byte
  (byte-equality bar), so the C2 command reconstructs exactly.
- The evasion is **framing-dependent**: 100% on HTTP (16/16), 29.2% on the
  binary record-chain protocol (7/24). Client-only fragmentation cannot hide a
  pattern the responder also echoes back.
- `baseline_alerted: 40/40` — every unmutated flow still alerts, so the number
  is not vacuous.

## Did the policy learn more than 2 actions?

**No.** `mechanism_diversity: 2`, `actions_chosen: {split8: 24, split24: 16}`.
The policy still plays exactly one action per framing (split8 for neris,
split24 for http) and never uses the other 12 actions. The fixed pipeline did
not change this — it confirms the earlier finding that under this
(non-adaptive) defender the search problem is near-constant per framing.

## Overfit check

Same fixed pipeline, scored on a random 20-flow **train-split** sample
(`overfit_check_FIXED.json`, seed 7) versus the held-out test split:

| framing | train sample | test split | overfit? |
|---|---|---|---|
| http | 7/7 = 100.0% | 16/16 = 100.0% | no |
| neris | 1/13 = 7.7% | 7/24 = 29.2% | no (test higher) |
| all | 8/20 = 40.0% | 23/40 = 57.5% | no (test higher) |

The policy does not do better on the flows it trained on than on the held-out
flows, so the test number is not memorisation. `baseline_alerted: 20/20` on the
train sample too, so both measurements rest on a real detector response. The
neris gap runs the "wrong" way (test > train) and is small-sample noise at
n=13; the honest reading is that neris evasion is framing-limited (~8–29%),
not that the policy generalises better than it trains.

## Why the old 40/40 and the 38.89% summary disagreed

They are different measurements, neither of which was the number the thesis
needs (see `docs/EVAL_AUDIT_2026-10-05.md`):

- `38.89%` is `mean(16.67%, 100%, 0%)` over **3 captures** in
  `cross_capture_summary.json`, including `capture-win13` (a Windows capture
  with almost no payload the policy can act on). It is a per-capture transfer
  average, not the test-split evasion.
- `40/40` is the held-out test **split** (40 flows) under the old pipeline.

Averaging three captures — one of which the policy provably cannot act on —
produces a number that is neither. Both must be reported, labelled, and never
averaged together.

## Reproduce

```
.venv/bin/python ai_agent/eval_fixed_pipeline.py \
    --out snort_validation/reports/ppo_masked_test_FIXED.json \
    --progress snort_validation/reports/.eval_fixed_progress.jsonl
.venv/bin/python -m pytest tests/test_evaluation_fixes.py -q
.venv/bin/python controls/verify_report_claims.py
```

Cost: ~4.5 min for 40 flows (one PCAP + one Snort call per flow, ~1.7 s/flow).
